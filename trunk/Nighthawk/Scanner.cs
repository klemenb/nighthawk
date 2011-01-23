using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;

/**
Nighthawk - ARP/NDP spoofing, simple SSL stripping and password sniffing for Windows
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
    public class Scanner
    {
        // current device
        private LivePcapDevice device;
        private DeviceInfo deviceInfo;

        // status
        public bool Started = false;

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
            this.ResolveHostnames = resolveHostnames;

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
            device.SendPacket(GenerateIpv6Ping());

            // loop through entire subnet, send ARP packets
            while (currentIP <= endIP)
            {
                // send packet
                device.SendPacket(GenerateARPRequest(Network.LongToIP(currentIP), deviceInfo));

                currentIP++;
            }

            // timeout - wait for responses
            var waitTimer = new Timer(new TimerCallback(Timer_WaitOver));
            waitTimer.Change(3000, Timeout.Infinite);
        }

        // scanner timer callback
        private void Timer_WaitOver(object o)
        {
            Started = false;

            // stop threads
            workerARP.Abort();

            // signal scan end, dispose timer
            ScanCompleted();
            (o as Timer).Dispose();
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

        // create multicast ping packet
        private EthernetPacket GenerateIpv6Ping()
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(device.Interface.MacAddress, PhysicalAddress.Parse("FFFFFFFFFFFF"),
                                                    EthernetPacketType.Arp);

            // generate IP part - layer 2
            var ipv6Packet = new IPv6Packet(IPAddress.Parse(deviceInfo.IPv6), IPAddress.Parse("ff02::1"));
            ipv6Packet.NextHeader = IPProtocolType.ICMPV6;
            ethernetPacket.PayloadPacket = ipv6Packet;
            
            // generate ICMPv6 part - layer 3
            var icmpv6Packet = new ICMPv6Packet(new byte[40], 0);
            
            icmpv6Packet.Type = ICMPv6Types.EchoRequest;
            icmpv6Packet.PayloadData = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwabcdefghi");
            icmpv6Packet.UpdateCalculatedValues();
            ipv6Packet.PayloadPacket = icmpv6Packet;

            var pseudo = Network.GetPseudoHeader(ipv6Packet.SourceAddress, ipv6Packet.DestinationAddress,
                                                 icmpv6Packet.Bytes.Length, 58);

            icmpv6Packet.Checksum = (ushort)(ChecksumUtils.OnesComplementSum(pseudo.Concat(icmpv6Packet.Bytes).ToArray()) + 4);

            return ethernetPacket;
        }

        // worker function that parses ARP packets
        public void WorkerARP()
        {
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
                            var ip = (packet.ParentPacket as IPv6Packet).SourceAddress;
                            var mac = (packet.ParentPacket.ParentPacket as EthernetPacket).SourceHwAddress;

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
            catch { }

            // invoke event
            Resolved(ip.ToString(), ip.AddressFamily == AddressFamily.InterNetworkV6, hostname);
        }

        // read IPv6 from ND cache
        public string GetIPv6Adress(PhysicalAddress mac)
        {
            // check if vista/windows 7 - netsh
            OperatingSystem system = Environment.OSVersion;

            if (system.Version.Major > 5)
            {
                // format MAC
                var macString = Network.FriendlyPhysicalAddress(mac).Replace(":", "-").ToLower();

                // run command
                Process p = new Process();
                
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                p.StartInfo.FileName = "cmd";
                p.StartInfo.Arguments = "/k netsh int ipv6 show neigh | findstr " + macString;
                p.Start();
                
                var output = p.StandardOutput.ReadToEnd();

                p.WaitForExit();

                // split output lines
                var lines = output.IndexOf("\r\n") != -1 ? Regex.Split(output, "\r\n") : new string[] {output};

                // return IP from the first line
                foreach (var line in lines)
                {
                    var split = line.Split(' ');
                    return split[0].Trim() != string.Empty ? split[0].Trim() : "/";
                }

                return "/";
            }

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
