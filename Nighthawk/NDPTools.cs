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
            workerSender.Start();
        }

        // stop spoofing
        public void StopSpoofing()
        {
            SpoofingStarted = false;

            // stop threads & re-ARP
            workerSender.Join();
        }

        // create RA packet
        private EthernetPacket GenerateRAPacket()
        {
            // future...
            return (EthernetPacket)new object();
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
