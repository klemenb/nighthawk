using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
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
    public partial class MainWindow : Window
    {
        public Main Nighthawk;
        public ARPTargetList ARPTargetList = new ARPTargetList();

        // colors
        private Color DisabledColor = Color.FromRgb(255, 185, 185);
        private Color EnabledColor = Color.FromRgb(169, 239, 168);

        private Color TextDisabledColor = Color.FromRgb(255, 91, 91);
        private Color TextEnabledColor = Color.FromRgb(92, 180, 90);

        // sniffer colos
        public Color ColorSnifferHTML = Color.FromRgb(0, 0, 151);
        public Color ColorSnifferHTTPAuth = Color.FromRgb(167, 0, 0);

        // device info
        private DeviceInfo deviceInfo;
        
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Nighthawk = new Main(this);

            // fill interfaces
            CInterface.ItemsSource = Nighthawk.GetInterfaces();
            
            // select first interface
            if ((CInterface.ItemsSource as List<string>).Count > 0) CInterface.SelectedIndex = 0;

            // set list sources
            LArpTargets1List.ItemsSource = ARPTargetList;
            LArpTargets2List.ItemsSource = ARPTargetList;

            // set first combobox item
            CConnectionsSourceIP.ItemsSource = new List<ARPTarget> {new ARPTarget {IP = "Scan your network..."}};
            CConnectionsSourceIP.SelectedIndex = 0;
        }
        
        private void Window_Closed(object sender, EventArgs e)
        {
            // stop everything
            Nighthawk.Device.StopCaptureTimeout = TimeSpan.FromMilliseconds(200);
            Nighthawk.Device.StopCapture();
            Nighthawk.Device.Close();

            Nighthawk.Sniffer.Stop();
            Nighthawk.ARPTools.StopSpoofing();

            Application.Current.Shutdown();
        }

        // get ARP targets
        private List<ARPTarget> GetTargets(ListView list)
        {
            var targets = new List<ARPTarget>();

            foreach (var item in list.SelectedItems)
            {
                if(item is ARPTarget) targets.Add((item as ARPTarget));
            }

            return targets.Count > 0 ? targets : null;
        }

        // get ARP target
        private ARPTarget GetTarget(ListView list)
        {
            return list.SelectedItem != null ? (list.SelectedItem as ARPTarget) : null;
        }

        /* Button handlers */

        // "Scan network"
        private void BScanNetwork_Click(object sender, RoutedEventArgs e)
        {
            // start device
            if (!Nighthawk.Started)
            {
                Nighthawk.StartDevice(CInterface.SelectedIndex);
            }

            // clear collection
            ARPTargetList.Clear();

            // start scanner
            Nighthawk.ARPTools.ScanNetwork(Nighthawk.DeviceInfoList[CInterface.SelectedIndex], (bool)CHResolveHostnames.IsChecked);

            // set device info
            deviceInfo = Nighthawk.DeviceInfoList[CInterface.SelectedIndex];

            // update button text
            BScanNetwork.Content = "Scanning...";
            BScanNetwork.IsEnabled = false;
        }

        // "Start/Stop sniffer"
        private void BStartSniffer_Click(object sender, RoutedEventArgs e)
        {
            if (Nighthawk.Sniffer == null || !Nighthawk.Sniffer.Started)
            {
                // start device
                if (!Nighthawk.Started)
                {
                    Nighthawk.StartDevice(CInterface.SelectedIndex);
                }

                // start sniffer
                Nighthawk.Sniffer.Start((bool)CHExcludeLocalIP.IsChecked, deviceInfo != null ? deviceInfo : Nighthawk.DeviceInfoList[CInterface.SelectedIndex]);

                // update button text, color
                BStartSniffer.Content = "Stop sniffer";
                SHStartSniffer.Color = EnabledColor;
                TSnifferStatusText.Text = "enabled";
                TSnifferStatusText.Foreground = new SolidColorBrush(TextEnabledColor);
            }
            else
            {
                // stop sniffer
                Nighthawk.Sniffer.Stop();

                // update button text, color
                BStartSniffer.Content = "Start sniffer";
                SHStartSniffer.Color = DisabledColor;
                TSnifferStatusText.Text = "disabled";
                TSnifferStatusText.Foreground = new SolidColorBrush(TextDisabledColor);
            }
        }

        // "Start/Stop ARP spoofing"
        private void  BStartARP_Click(object sender, RoutedEventArgs e)
        {
            if (!Nighthawk.ARPTools.SpoofingStarted)
            {
                // check for properly selected targets
                if (GetTargets(LArpTargets1List) != null && GetTarget(LArpTargets2List) != null)
                {
                    // start spoofing
                    Nighthawk.ARPTools.StartSpoofing(GetTargets(LArpTargets1List), GetTarget(LArpTargets2List));

                    // update button text, color
                    BStartARP.Content = "Stop ARP spoofing";
                    SHStartARP.Color = EnabledColor;
                    TArpStatusText.Text = "enabled";
                    TArpStatusText.Foreground = new SolidColorBrush(TextEnabledColor);
                }
                else
                {
                    MessageBox.Show("Please select desired targets.", "Nighthawk warning",
                        MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
            }
            else
            {
                // stop spoofing
                Nighthawk.ARPTools.StopSpoofing();
                
                // stop ssl strip
                // Nighthawk.SSLStrip.Stop();

                // update button text, color
                BStartARP.Content = "Start ARP spoofing";
                SHStartARP.Color = DisabledColor;
                TArpStatusText.Text = "disabled";
                TArpStatusText.Foreground = new SolidColorBrush(TextDisabledColor);
            }
        }

        // "Start/Stop SSL stripping"
        private void BStartSSLstrip_Click(object sender, RoutedEventArgs e)
        {
            if (Nighthawk.SSLStrip == null || !Nighthawk.SSLStrip.Started)
            {
                // start device
                if (!Nighthawk.Started)
                {
                    Nighthawk.StartDevice(CInterface.SelectedIndex);
                }

                // check for ARP spoofing
                if (!Nighthawk.ARPTools.SpoofingStarted)
                {
                    MessageBox.Show("SSL stripping will only work for remote computers.", "Nighthawk notice",
                                    MessageBoxButton.OK, MessageBoxImage.Information);
                }

                // start SSL strip
                Nighthawk.SSLStrip.Start((bool)CHExcludeLocalIP.IsChecked, deviceInfo != null ? deviceInfo : Nighthawk.DeviceInfoList[CInterface.SelectedIndex], Nighthawk.ARPTools);

                // update button text, color
                BStartSSLstrip.Content = "Stop SSL stripping";
                SHStartSSLstrip.Color = EnabledColor;
                TSSLStatusText.Text = "enabled";
                TSSLStatusText.Foreground = new SolidColorBrush(TextEnabledColor);
            }
            else
            {
                // start SSL strip
                Nighthawk.SSLStrip.Stop();

                // update button text, color
                BStartSSLstrip.Content = "Start SSL stripping";
                SHStartSSLstrip.Color = DisabledColor;
                TSSLStatusText.Text = "disabled";
                TSSLStatusText.Foreground = new SolidColorBrush(TextDisabledColor);
            }
        }
    }
}
