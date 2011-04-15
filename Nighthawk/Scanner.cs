using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap.WinPcap;

/**
Nighthawk - ARP spoofing, simple SSL stripping and password sniffing for Windows
Copyright (C) 2011  Klemen Bratec

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
    public class Scanner
    {
        // current device
        private WinPcapDevice device;
        private DeviceInfo deviceInfo;
        private PhysicalAddress physicalAddress;

        // status
        public bool Started;
        public bool ResolveHostnames;

        // packet queues (packet store for BG thread to work on)
        public List<ARPPacket> PacketQueueARP = new List<ARPPacket>();
        private List<ARPPacket> threadQueueARP = new List<ARPPacket>();

        public List<ICMPv6Packet> PacketQueueNDP = new List<ICMPv6Packet>();
        private List<ICMPv6Packet> threadQueueNDP = new List<ICMPv6Packet>();

        // worker threads
        private Thread workerARP;
        private Thread workerNDP;

        // scan completed event
        public event ScannerEventHandler ScanComplete;

        private void ScanCompleted()
        {
            if (ScanComplete != null) ScanComplete();
        }

        // scanner response event
        public event ScannerResponseReceived ScannerResponse;

        private void Response(string ip, bool ipv6, PhysicalAddress mac, string hostname)
        {
            if (ScannerResponse != null) ScannerResponse(ip, ipv6, mac, hostname);
        }

        // hostname resolved event
        public event ScannerHostnameResolvedHandler HostnameResolved;

        private void Resolved(string ip, bool ipv6, string hostname)
        {
            if (HostnameResolved != null) HostnameResolved(ip, ipv6, hostname);
        }

        // constructor
        public Scanner(DeviceInfo deviceInfo)
        {
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // scans network (ARP requests & NDP solicitation)
        public void ScanNetwork(bool resolveHostnames)
        {
            ResolveHostnames = resolveHostnames;

            // set MAC address
            physicalAddress = deviceInfo.PMAC;

            // get start/end IP
            long[] range = Network.MaskToStartEnd(deviceInfo.IP, deviceInfo.Mask);

            long startIP = range[0];
            long endIP = range[1];
            long currentIP = startIP;

            Started = true;

            // start worker to listen for ARP packets
            workerARP = new Thread(new ThreadStart(WorkerARP));
            workerARP.Name = "Scanner thread (ARP)";
            workerARP.Start();

            // start worker to listen for NDP/ICMPv6 packets
            workerNDP = new Thread(new ThreadStart(WorkerICMPv6));
            workerNDP.Name = "Scanner thread (ICMPv6)";
            workerNDP.Start();

            // send IPv6 stuff
            if (deviceInfo.IPv6 != string.Empty || deviceInfo.LinkLocal != string.Empty)
            {
                device.SendPacket(GenerateIpv6Ping());
            }

            // loop through entire subnet, send ARP packets
            while (currentIP <= endIP)
            {
                // send packet
                device.SendPacket(GenerateARPRequest(Network.LongToIP(currentIP), deviceInfo));

                currentIP++;
            }

            // timeout - wait for responses
            var waitTimer = new Timer(new TimerCallback(Timer_WaitOver));
            waitTimer.Change(4000, Timeout.Infinite);
        }

        // scanner timer callback
        private void Timer_WaitOver(object o)
        {
            Started = false;

            // stop threads
            workerARP.Join();
            workerNDP.Join();

            // signal scan end, dispose timer
            ScanCompleted();
            ((Timer) o).Dispose();
        }

        // create ARP request packet
        private EthernetPacket GenerateARPRequest(string destinationIP, DeviceInfo deviceInfo)
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(physicalAddress, PhysicalAddress.Parse("FFFFFFFFFFFF"),
                                                    EthernetPacketType.Arp);

            // arp data - layer 2
            var arpPacket = new ARPPacket(ARPOperation.Request, PhysicalAddress.Parse("FFFFFFFFFFFF"), IPAddress.Parse(destinationIP), physicalAddress,
                                       IPAddress.Parse(deviceInfo.IP));

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // create multicast ping packet
        private EthernetPacket GenerateIpv6Ping()
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(physicalAddress, PhysicalAddress.Parse("FFFFFFFFFFFF"),
                                                    EthernetPacketType.Arp);

            // generate IP part - layer 2
            var ipv6Packet = new IPv6Packet(IPAddress.Parse((deviceInfo.IPv6 != string.Empty ? deviceInfo.IPv6 : deviceInfo.LinkLocal)), IPAddress.Parse("ff02::1"));
            ipv6Packet.NextHeader = IPProtocolType.ICMPV6;
            ethernetPacket.PayloadPacket = ipv6Packet;
            
            // generate ICMPv6 part - layer 3
            var icmpv6Packet = new ICMPv6Packet(new ByteArraySegment(new byte[40]))
                                   {
                                       Type = ICMPv6Types.EchoRequest,
                                       PayloadData = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwabcdefghi")
                                   };

            ipv6Packet.PayloadPacket = icmpv6Packet;

            var pseudo = Network.GetPseudoHeader(ipv6Packet.SourceAddress, ipv6Packet.DestinationAddress,
                                                 icmpv6Packet.Bytes.Length, 58);

            icmpv6Packet.Checksum = (ushort)(ChecksumUtils.OnesComplementSum(pseudo.Concat(icmpv6Packet.Bytes).ToArray()) + 4);

            return ethernetPacket;
        }

        // worker function that parses ARP packets
        public void WorkerARP()
        {
            List<IPAddress> processedIPs = new List<IPAddress>();

            // main loop
            while (Started)
            {
                // copy packets to threadQueue
                lock (PacketQueueARP)
                {
                    foreach (ARPPacket packet in PacketQueueARP)
                    {
                        threadQueueARP.Add(packet);
                    }

                    PacketQueueARP.Clear();
                }

                if (threadQueueARP.Count > 0)
                {
                    // loop through packets
                    foreach (ARPPacket packet in threadQueueARP)
                    {
                        // if ARP response and scanner still active
                        if (packet.Operation == ARPOperation.Response && Started)
                        {
                            // get IP, MAC
                            var ip = packet.SenderProtocolAddress;
                            var mac = packet.SenderHardwareAddress;
                            var hostname = ResolveHostnames ? "Resolving..." : String.Empty;

                            // check if IP already processed
                            if (!processedIPs.Contains(ip))
                            {
                                Response(ip.ToString(), false, mac, hostname);

                                // resolve hostname
                                if (ResolveHostnames)
                                {
                                    // start resolver thread
                                    var resolver = new Thread(new ParameterizedThreadStart(WorkerResolver));
                                    resolver.Start(ip);
                                }

                                // start ipv6 thread
                                var ipv6Resolve = new Thread(new ParameterizedThreadStart(WorkerIPv6));
                                ipv6Resolve.Start(mac);
                            }

                            processedIPs.Add(ip);
                        }
                    }

                    threadQueueARP.Clear();
                }
                else
                {
                    Thread.Sleep(50);
                }
            }

            return;
        }
        
        // worker function that parses ICMPv6 ping reply
        public void WorkerICMPv6()
        {
            // main loop
            while (Started)
            {
                // copy packets to threadQueue
                lock (PacketQueueNDP)
                {
                    foreach (ICMPv6Packet packet in PacketQueueNDP)
                    {
                        threadQueueNDP.Add(packet);
                    }

                    PacketQueueNDP.Clear();
                }

                if (threadQueueNDP.Count > 0)
                {
                    // loop through packets
                    foreach (ICMPv6Packet packet in threadQueueNDP)
                    {
                        // if ping reply
                        if (packet.Bytes.Count() > 0 && packet.Bytes[0] == 129)
                        {
                            // get IP, MAC
                            if (packet.ParentPacket == null || packet.ParentPacket.ParentPacket == null) continue;

                            var ip = ((IPv6Packet) packet.ParentPacket).SourceAddress;
                            var mac = ((EthernetPacket) packet.ParentPacket.ParentPacket).SourceHwAddress;

                            Response(ip.ToString(), true, mac, "");
                        }
                    }

                    threadQueueNDP.Clear();
                }
                else
                {
                    Thread.Sleep(50);
                }
            }

            return;
        }

        // worker for retrieving IPv6 addresses from cache
        public void WorkerIPv6(object data)
        {
            var mac = (PhysicalAddress)data;
            var ipv6 = GetIPv6Adress(mac);

            Response(ipv6, true, mac, "");

            return;
        }

        // worker function for resolving hostnames
        public void WorkerResolver(object data)
        {
            var ip = (IPAddress) data;
            var hostname = "";

            Thread.Sleep(100);

            try
            {
                hostname = Dns.GetHostEntry(ip).HostName;
            }
            catch { }

            // invoke event
            Resolved(ip.ToString(), ip.AddressFamily == AddressFamily.InterNetworkV6, hostname);

            return;
        }

        // read IPv6 from ND cache
        public string GetIPv6Adress(PhysicalAddress mac)
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
                p.StartInfo.Arguments = "/k netsh int ipv6 show neigh | findstr " + macString;
                p.Start();
                
                var output = p.StandardOutput.ReadToEnd();

                p.WaitForExit();

                // split output lines
                var lines = output.Contains("\r\n") ? Regex.Split(output, "\r\n") : new string[] {output};

                // return IP from the first line
                foreach (var line in lines)
                {
                    var split = line.Split(' ');
                    return split[0].Trim() != string.Empty ? split[0].Trim() : "/";
                }

                return "/";
            }

            // Windows XP - "ipv6 nc"
            if (system.Version.Major == 5 && system.Version.Minor == 1)
            {
                // set parameters
                p.StartInfo.Arguments = "/k ipv6 nc | findstr " + macString;
                p.Start();

                var output = p.StandardOutput.ReadToEnd();

                p.WaitForExit();

                // split output lines (also clean double spaces)
                var lines = output.Contains("\r\n") ? Regex.Split(Regex.Replace(output, "  ", " "), "\r\n") : new string[] { Regex.Replace(output, "  ", " ") };

                // split line on spaces, return IPv6
                foreach (var line in lines)
                {
                    var split = line.Split(' ');

                    if (split.Length > 1)
                    {
                        return split[1].Trim() != string.Empty ? split[1].Trim() : "/";
                    }
                }

                return "/";
            }

            p.Close();         

            return "/";
        }
    }

    // ScannerEventHandler event delegate
    public delegate void ScannerEventHandler();

    // ScannerResponseReceived event delegate
    public delegate void ScannerResponseReceived(string ip, bool ipv6, PhysicalAddress mac, string hostname);

    // ScannerHostnameResolvedHandler event delegate
    public delegate void ScannerHostnameResolvedHandler(string ip, bool ipv6, string hostname);
}
