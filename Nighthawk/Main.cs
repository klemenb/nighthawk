using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using SharpPcap;
using PacketDotNet;

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
    public class Main
    {
        // our network interface
        public LivePcapDevice Device;

        // list of devices (DeviceInfo)
        public List<DeviceInfo> DeviceInfoList = new List<DeviceInfo>();
        private DeviceInfo deviceInfo;

        // GUI
        public MainWindow Window;

        // modules
        public Sniffer Sniffer;
        public ARPTools ARPTools;
        public SSLStrip SSLStrip;
        public Scanner Scanner;

        // vendors (MAC OUI)
        public Dictionary<string, string> Vendors = new Dictionary<string, string>();

        // device status
        public bool Started = false;

        // last paragraph
        private string lastSSLText = string.Empty;

        // constructor
        public Main(MainWindow window)
        {
            Window = window;
        }

        // returns a collection of network interfaces
        public List<string> GetInterfaces()
        {
            var devices = new List<string>();

            // clear DeviceInfo list
            DeviceInfoList.Clear();

            // try to check for WinPcap???
            var error = false;

            try
            {
                var instance = LivePcapDeviceList.Instance[0];
                if (instance == null) error = true;
            } catch {
                error = true;
            }

            if(error) {
                MessageBox.Show("WinPcap not installed or no devices detected!", "Nighthawk error",
                            MessageBoxButton.OK, MessageBoxImage.Error);

                return new List<string>();
            }
            //

            foreach (var device in LivePcapDeviceList.Instance)
            {
                // get IPv4 address, subnet mask and broadcast address
                var address = "";
                var subnet = "";
                var broadcast = "";

                var address6 = "";

                foreach (var addr in device.Addresses)
                {
                    if (addr.Addr.ipAddress != null)
                    {
                        // IPv4
                        if (addr.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                        {
                            address = addr.Addr.ipAddress.ToString();
                            subnet = addr.Netmask.ipAddress.ToString();
                            broadcast = addr.Broadaddr.ipAddress.ToString();
                        }

                        if (addr.Addr.ipAddress.AddressFamily == AddressFamily.InterNetworkV6 && !addr.Addr.ipAddress.IsIPv6LinkLocal)
                        {
                            address6 = addr.Addr.ipAddress.ToString();
                            //subnet6 = addr.Netmask.ipAddress.ToString();
                            //broadcast6 = addr.Broadaddr.ipAddress.ToString();
                        }
                    }
                }
                
                DeviceInfoList.Add(new DeviceInfo { Device = device, CIDR = (int)Network.MaskToCIDR(subnet), IP = address, Mask = subnet, Broadcast = broadcast });
                devices.Add(device.Description + " (IPv4: " + address + "/" + Network.MaskToCIDR(subnet) + (address6 != string.Empty ? ", IPv6: " + address6 : "") + ")");
            }

            return devices;
        }

        // start listening on a device
        public void StartDevice(int deviceIndex)
        {
            Started = true;

            deviceInfo = DeviceInfoList[deviceIndex];
            Device = LivePcapDeviceList.Instance[deviceIndex];            

            // initialize modules
            Sniffer = new Sniffer(deviceInfo);
            ARPTools = new ARPTools(deviceInfo);
            SSLStrip = new SSLStrip(deviceInfo);
            Scanner = new Scanner(deviceInfo);

            // module events
            Sniffer.SnifferResult += new SnifferResultHandler(sniffer_OnSnifferResult);
            Scanner.ScannerResponse += new ScannerResponseReceived(scanner_OnResponse);
            Scanner.ScanComplete += new ScannerEventHandler(scanner_OnScanComplete);
            Scanner.HostnameResolved += new ScannerHostnameResolvedHandler(scanner_HostnameResolved);
            SSLStrip.SSLStripped += new SSLStrip.SSLStripHandler(SSLStrip_OnSSLStripped);

            // open device, start capturing
            Device.Open(DeviceMode.Promiscuous, 1);
            Device.Filter = "(arp || ip)";
            Device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            Device.StartCapture();
        }

        // stop listening on a device
        public void StopDevice()
        {
            Started = false;

            Device.StopCaptureTimeout = TimeSpan.FromMilliseconds(200);
            Device.StopCapture();
            Device.Close();
        }

        // OUI database loader
        public void LoadOUI()
        {
            string[] dbLines = File.ReadAllLines("OUI.txt");

            // parse every line and fill "Vendors"
            foreach (var line in dbLines)
            {
                if (!line.StartsWith("#") && line.Length > 5)
                {
                    var macSegment = line.Substring(0, 8).Replace("-", "");
                    var vendor = line.Substring(18, line.Length - 18);

                    if(!Vendors.ContainsKey(macSegment)) Vendors.Add(macSegment, vendor);
                }
            }
        }

        // check for Vendor
        private string GetVendorFromMAC(string mac)
        {
            var macSegment = mac.Substring(0, 6);

            if (Vendors.ContainsKey(macSegment)) return Vendors[macSegment];
            
            return "";
        }

        // packet arrival event
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            // parse packet
            var packet = Packet.ParsePacket(e.Packet);

            // check only ethernet packets
            if (packet is EthernetPacket)
            {
                // decode packet as TCP, ARP, IP
                var tcp = TcpPacket.GetEncapsulated(packet);
                var arp = ARPPacket.GetEncapsulated(packet);
                var ip = IpPacket.GetEncapsulated(packet);

                // TCP packet
                if (tcp != null)
                {
                    // if we are likely to have a HTTP packet
                    if ((tcp.SourcePort == 80 || tcp.DestinationPort == 80))
                    {
                        if (Sniffer.Started)
                        {
                            lock (Sniffer.PacketQueue)
                            {
                                Sniffer.PacketQueue.Add(tcp);
                            }
                        }

                        if (SSLStrip.Started)
                        {
                            SSLStrip.ProcessPacket(packet, tcp);
                        }
                    }
                }

                // ARP packet
                if (arp != null)
                {
                    if (Scanner.Started)
                    {
                        lock (Scanner.PacketQueueARP)
                        {
                            Scanner.PacketQueueARP.Add(arp);
                        }
                    }
                }

                // IP packet (for routing)
                if (ip != null)
                {
                    // only route IPv4 when ARP spoofing active
                    if (ARPTools.SpoofingStarted && ip.SourceAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        lock (ARPTools.PacketQueueRouting)
                        {
                            ARPTools.PacketQueueRouting.Add(packet);
                        }
                    }

                    // only route IPv6 when NDP spoofing active
                    //if (NDPTools.SpoofingStarted && ip.SourceAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    //{
                    //    lock (NDPTools.PacketRoutingQueue)
                    //    {
                    //        NDPTools.PacketRoutingQueue.Add(packet);
                    //    }
                    //}
                }
            }
        }

        /* Module events */
        private delegate void UI();

        // sniffer result (username/password sniffed)
        private void sniffer_OnSnifferResult(string url, string username, string password, string aditional, SnifferResultType type)
        {
            // update GUI text
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                var brush = new SolidColorBrush();

                // brush color
                if (type == SnifferResultType.HTML)
                {
                    brush = new SolidColorBrush(Window.ColorSnifferHTML);
                }
                else if (type == SnifferResultType.HTTPAuth)
                {
                    brush = new SolidColorBrush(Window.ColorSnifferHTTPAuth);
                }

                // create new result item
                var result = new SnifferResult { URL = url, Username = username, Password = password, Aditional = aditional, Type = type, ShapeBrush = brush};

                // don't repeat entries
                if (Window.SnifferResultList.Count == 0 || Window.SnifferResultList.Last() != result)
                {
                    Window.SnifferResultList.Add(result);
                }
            }));
        }

        // scanner response (new target)
        private void scanner_OnResponse(string ip, bool ipv6, PhysicalAddress mac, string hostname)
        {
            // update GUI
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                var item = new Target { Hostname = hostname, IP = ip, MAC = Network.FriendlyPhysicalAddress(mac), PMAC = mac, Vendor = GetVendorFromMAC(mac.ToString())};

                // exclude local IP
                if (ip != deviceInfo.IP)
                {
                    if (!Window.TargetList.ContainsIP(item.IP)) Window.TargetList.Add(item);
                }
            }));
        }

        // network scan completed
        private void scanner_OnScanComplete()
        {
            // update GUI
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                Window.BScanNetwork.IsEnabled = true;
                Window.BScanNetwork.Content = "Scan network";

                // check for target count to enable ARP spoofing button
                if (Window.TargetList.Count > 0)
                {
                    Window.BStartARP.IsEnabled = true;
                }
            }));
        }


        // hostname resolved
        private void scanner_HostnameResolved(string ip, bool ipv6, string hostname)
        {
            if (Scanner.ResolveHostnames)
            {
                // update GUI
                Window.Dispatcher.BeginInvoke(new UI(delegate
                {
                    // check for local IP
                    if (ip != deviceInfo.IP)
                    {
                        var target = Window.TargetList.Where(t => t.IP == ip.ToString()).First();
                        target.Hostname = hostname;
                    }
                }));
            }
        }

        // SSL stripped
        private void SSLStrip_OnSSLStripped(string sourceIP, string destIP, List<string> changed)
        {
            // update GUI text
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                // determine what has changed
                var changedText = string.Empty;

                foreach(var change in changed)
                {
                    if(change != changed.Last())
                    {
                        changedText += change + ", ";
                    } else {
                        changedText += change;
                    }
                }

                // build output string
                var text = "SSL stripped ("+ sourceIP +" -> "+ destIP +"): "+ changedText;
                var resultText = new Run(text);
                resultText.Foreground = new SolidColorBrush(Window.ColorSSLStrip);

                // change paragraph style
                var thickness = new Thickness(0, 0, 0, 5);
                var paragraph = new Paragraph(resultText);

                paragraph.Margin = thickness;

                // don't repeat entries
                if (lastSSLText != text)
                {
                    lastSSLText = text;

                    if(Window.TSSLText.Document.Blocks.Count > 0) {
                        Window.TSSLText.Document.Blocks.InsertBefore(Window.TSSLText.Document.Blocks.First(), paragraph);
                    } else {
                        Window.TSSLText.Document.Blocks.Add(paragraph);
                    }
                }
            }));
        }
    }
}
