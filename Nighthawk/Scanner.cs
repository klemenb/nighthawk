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
    public class Scanner
    {
        private WinPcapDevice device;
        private DeviceInfo deviceInfo;
        private PhysicalAddress physicalAddress;

        private readonly PhysicalAddress broadcastMAC = PhysicalAddress.Parse("FFFFFFFFFFFF");

        public bool Started;
        public bool ResolveHostnames;

        // packet queues (packet storage for BG threads)
        public List<ARPPacket> PacketQueueARP = new List<ARPPacket>();
        private List<ARPPacket> threadQueueARP = new List<ARPPacket>();

        public List<ICMPv6Packet> PacketQueueNDP = new List<ICMPv6Packet>();
        private List<ICMPv6Packet> threadQueueNDP = new List<ICMPv6Packet>();

        private Thread workerARP;
        private Thread workerSenderARP;
        private Thread workerNDP;

        // events
        public event ScannerEventHandler ScanComplete;

        private void ScanCompleted()
        {
            if (ScanComplete != null) ScanComplete();
        }

        public event ScannerResponseReceived ScannerResponse;

        private void Response(string ip, bool ipv6, PhysicalAddress mac, string hostname, List<string> ipv6List = null)
        {
            if (ScannerResponse != null) ScannerResponse(ip, ipv6, mac, hostname, ipv6List);
        }

        public event ScannerHostnameResolvedHandler HostnameResolved;

        private void Resolved(string ip, bool ipv6, string hostname)
        {
            if (HostnameResolved != null) HostnameResolved(ip, ipv6, hostname);
        }

        public Scanner(DeviceInfo deviceInfo)
        {
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start a network scan - ARP request for IPv4, multicast ping & cache search for IPv6 (resolve hostnames)
        public void ScanNetwork(bool resolveHostnames)
        {
            ResolveHostnames = resolveHostnames;

            physicalAddress = deviceInfo.PMAC;

            Started = true;

            // start worker to listen for ARP packets
            workerARP = new Thread(new ThreadStart(WorkerARP));
            workerARP.Name = "Scanner thread (ARP)";
            workerARP.Start();

            // start worker to listen for ICMPv6 packets
            workerNDP = new Thread(new ThreadStart(WorkerICMPv6));
            workerNDP.Name = "Scanner thread (ICMPv6)";
            workerNDP.Start();

            // send mutlicast IPv6 ping
            if (deviceInfo.IPv6 != string.Empty || deviceInfo.LinkLocal != string.Empty)
            {
                device.SendPacket(GenerateIpv6Ping());
            }

            workerSenderARP = new Thread(new ThreadStart(WorkerSender));
            workerSenderARP.Start();
        }

        // create ARP request packet (destination IP, deviceInfo)
        private EthernetPacket GenerateARPRequest(IPAddress destinationIP, IPAddress senderIP)
        {
            var ethernetPacket = new EthernetPacket(physicalAddress, broadcastMAC, EthernetPacketType.Arp);
            var arpPacket = new ARPPacket(ARPOperation.Request, broadcastMAC, destinationIP, physicalAddress, senderIP);

            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        // create multicast IPv6 ping packet
        private EthernetPacket GenerateIpv6Ping()
        {
            var ethernetPacket = new EthernetPacket(physicalAddress, broadcastMAC, EthernetPacketType.Arp);
            var ipv6Packet = new IPv6Packet(IPAddress.Parse((deviceInfo.IPv6 != string.Empty ? deviceInfo.IPv6 : deviceInfo.LinkLocal)), IPAddress.Parse("ff02::1"));
            
            ipv6Packet.NextHeader = IPProtocolType.ICMPV6;
            ethernetPacket.PayloadPacket = ipv6Packet;
            
            var icmpv6Packet = new ICMPv6Packet(new ByteArraySegment(new byte[40]))
            {
                Type = ICMPv6Types.EchoRequest,
                PayloadData = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwabcdefghi")
            };

            ipv6Packet.PayloadPacket = icmpv6Packet;

            // ICMPv6 checksum fix
            var pseudo = Network.GetPseudoHeader(ipv6Packet.SourceAddress, ipv6Packet.DestinationAddress, icmpv6Packet.Bytes.Length, 58);
            icmpv6Packet.Checksum = (ushort)(ChecksumUtils.OnesComplementSum(pseudo.Concat(icmpv6Packet.Bytes).ToArray()) + 4);

            return ethernetPacket;
        }

        // worker function for sending ARP requests
        private void WorkerSender()
        {
            // get start/end IP
            long[] range = Network.MaskToStartEnd(deviceInfo.IP, deviceInfo.Mask);

            long startIP = range[0];
            long endIP = range[1];
            long currentIP = startIP;

            var possibilities = (int)endIP - (int)startIP;

            var sendQueue = new SendQueue(possibilities * 80);
            var deviceIP = IPAddress.Parse(deviceInfo.IP);

            // create ARP requests for all the hosts in our subnet);
            while (currentIP <= endIP)
            {
                sendQueue.Add(GenerateARPRequest(Network.LongToIP(currentIP), deviceIP).Bytes);

                currentIP++;
            }

            // send our queue
            sendQueue.Transmit(device, SendQueueTransmitModes.Normal);

            Thread.Sleep(3000);

            // stop other threads and stop scanning
            Started = false;

            workerARP.Join();
            workerNDP.Join();

            ScanCompleted();

            return;
        }

        // worker function for processing incoming ARP replies
        public void WorkerARP()
        {
            List<IPAddress> processedIPs = new List<IPAddress>();

            while (Started)
            {
                // copy packets to thread's packet storage (threadQueue)
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
                    // loop through packets and parse responses
                    foreach (ARPPacket packet in threadQueueARP)
                    {
                        // if we have an ARP reply (response) and scanner is still active
                        if (packet.Operation == ARPOperation.Response && Started)
                        {
                            var ip = packet.SenderProtocolAddress;
                            var mac = packet.SenderHardwareAddress;
                            var hostname = ResolveHostnames ? "Resolving..." : String.Empty;

                            // process IP if not already processed
                            if (!processedIPs.Contains(ip))
                            {
                                Response(ip.ToString(), false, mac, hostname);

                                if (ResolveHostnames)
                                {
                                    // start a background resolver thread
                                    var resolver = new Thread(new ParameterizedThreadStart(WorkerResolver));
                                    resolver.Start(ip);
                                }

                                // start ipv6 resolver thread
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
        
        // worker function for parsing ICMPv6 responses
        public void WorkerICMPv6()
        {
            while (Started)
            {
                // copy packets to thread's packet storage (threadQueue)
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
                    // loop through packets and parse them
                    foreach (ICMPv6Packet packet in threadQueueNDP)
                    {
                        // if we have a ping reply
                        if (packet.Bytes.Count() > 0 && packet.Bytes[0] == 129)
                        {
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
            var ipv6List = GetIPv6Address(mac);

            Response((ipv6List.Count > 0 ? ipv6List[0] : "/"), true, mac, "", ipv6List);

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

            Resolved(ip.ToString(), ip.AddressFamily == AddressFamily.InterNetworkV6, hostname);

            return;
        }

        // read IPv6 address from ND cache
        public List<string> GetIPv6Address(PhysicalAddress mac)
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

            // Vista, Windows 7/8 - use "netsh"
            if (system.Version.Major > 5)
            {
                p.StartInfo.Arguments = "/C netsh int ipv6 show neigh | findstr " + macString + "";
                p.Start();

                var output = p.StandardOutput.ReadToEnd();

                p.WaitForExit();
                p.Dispose();
                
                var lines = output.Contains("\r\n") ? Regex.Split(output, "\r\n") : new string[] {output};

                var ipv6List = new List<string>();

                foreach (var line in lines)
                {
                    // skip last line
                    if (line == lines.Last()) continue;

                    var split = line.Split(' ');

                    if(split[0].Trim() != string.Empty) ipv6List.Add(split[0].Trim());
                }

                return ipv6List;
            }

            p.Dispose();

            return new List<string>();
        }
    }

    public delegate void ScannerEventHandler();

    public delegate void ScannerResponseReceived(string ip, bool ipv6, PhysicalAddress mac, string hostname, List<string> ipv6List = null);

    public delegate void ScannerHostnameResolvedHandler(string ip, bool ipv6, string hostname);
}
