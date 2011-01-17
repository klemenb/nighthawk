using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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

namespace Nighthawk
{
    public class Main
    {
        // our network interface
        public LivePcapDevice Device;

        // list of devices (DeviceInfo)
        public List<DeviceInfo> DeviceInfoList = new List<DeviceInfo>();

        // GUI
        public MainWindow Window;

        // modules
        public Sniffer Sniffer;
        public ARPTools ARPTools;
        public SSLStrip SSLStrip;

        // device status
        public bool Started = false;

        // last paragraph
        private string lastResultText = string.Empty;

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

            foreach (var device in LivePcapDeviceList.Instance)
            {
                // get IPv4 address
                var address = "No IPv4";
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
                
                DeviceInfoList.Add(new DeviceInfo {CIDR = (int)Network.MaskToCIDR(subnet), IP = address, Mask = subnet, Broadcast = broadcast});
                devices.Add(" IP: " + address + "/" + Network.MaskToCIDR(subnet) + "  " + device.Description);   
            }

            return devices;
        }

        // start listening on a device
        public void StartDevice(int deviceIndex)
        {
            Started = true;

            Device = LivePcapDeviceList.Instance[deviceIndex];

            // initialize modules
            Sniffer = new Sniffer(Device);
            ARPTools = new ARPTools(Device);
            SSLStrip = new SSLStrip(Device);

            // module events
            Sniffer.OnSnifferResult += new SnifferResultHandler(sniffer_OnSnifferResult);
            ARPTools.OnArpResponse += new ArpResponseEventHandler(ARPTools_OnArpResponse);
            ARPTools.OnArpScanComplete += new ArpScanEventHandler(ARPTools_OnArpScanComplete);

            // open device
            Device.Open(DeviceMode.Promiscuous, 1);

            // Device.NonBlockingMode = true;

            // set filters
            Device.Filter = "(arp || ip)";

            // bind capture event
            Device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // start
            Device.StartCapture();
        }

        // packet arrival event
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            // parse packet
            var packet = Packet.ParsePacket(e.Packet);

            // check only ethernet packets
            if (packet is EthernetPacket)
            {
                packet = (EthernetPacket) packet;

                // decode packet as TCP, ARP, IP
                var tcp = TcpPacket.GetEncapsulated(packet);
                var arp = ARPPacket.GetEncapsulated(packet);
                var ip = IpPacket.GetEncapsulated(packet);

                // TCP packet
                if (tcp != null)
                {
                    // if HTTP packet (port 80 - 99% probability of being HTTP) and IPv4
                    if ((tcp.SourcePort == 80 || tcp.DestinationPort == 80) && ip.SourceAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        if (Sniffer.Started)
                        {
                            // add packet to queue
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
                    // if ARP tools activated
                    if (ARPTools.ScanStarted)
                    {
                        // add ARP to queue
                        lock (ARPTools.PacketQueue)
                        {
                            ARPTools.PacketQueue.Add(arp);
                        }
                    }
                }

                // IP packet (routing)
                if (ip != null)
                {
                    // if spoofing is active and is IPv4
                    if (ARPTools.SpoofingStarted && ip.SourceAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        // add packet to routing queue
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
                // create element
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

                // style
                var thickness = new Thickness(0, 0, 0, 5);
                var paragraph = new Paragraph(resultText);

                paragraph.Margin = thickness;

                // don't repeat same entries
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
                var item = new ARPTarget { Hostname = hostname, IP = ip.ToString(), MAC = Network.FriendlyPhysicalAddress(mac), PMAC = mac};

                if(!Window.ARPTargetList.ContainsIP(item.IP)) Window.ARPTargetList.Add(item);
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

    public class ARPTarget
    {
        private string _IP;
        private string _MAC;
        private PhysicalAddress _PMAC;
        private string _Hostname;

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

        public string Hostname
        {
            get { return _Hostname; }
            set { _Hostname = value; }
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
