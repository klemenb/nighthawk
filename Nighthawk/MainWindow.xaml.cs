using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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
using Microsoft.Win32;
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
    public partial class MainWindow : Window
    {
        public Main Nighthawk;

        public TargetList TargetList = new TargetList();
        public SnifferResultList SnifferResultList = new SnifferResultList();

        // colors
        private Color DisabledColor = Color.FromRgb(255, 185, 185);
        private Color EnabledColor = Color.FromRgb(169, 239, 168);

        // sniffer colos
        public Color ColorSnifferHTML = Color.FromRgb(0, 0, 151);
        public Color ColorSnifferHTTPAuth = Color.FromRgb(167, 0, 0);

        public Color ColorSSLStrip = Color.FromRgb(60, 60, 60);

        // device info
        private DeviceInfo deviceInfo;
        
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Nighthawk = new Main(this);

            Title = "Nighthawk " + GetWindowTitle(false);

            // load OUI database
            Nighthawk.LoadOUI();

            // fill interfaces
            CInterface.ItemsSource = Nighthawk.GetInterfaces();
            
            // select first interface
            if ((CInterface.ItemsSource as List<string>).Count > 0) CInterface.SelectedIndex = 0;

            // set list sources
            LArpTargets1List.ItemsSource = TargetList;
            LArpTargets2List.ItemsSource = TargetList;

            LSnifferResults.ItemsSource = SnifferResultList;
        }
        
        private void Window_Closed(object sender, EventArgs e)
        {
            // stop everything
            Nighthawk.StopDevice();

            Nighthawk.Sniffer.Stop();
            Nighthawk.ARPTools.StopSpoofing();

            Application.Current.Shutdown();
        }

        // get current title (from AssemblyVersion)
        public static string GetWindowTitle(bool revision)
        {
            var major = Assembly.GetExecutingAssembly().GetName().Version.Major.ToString();
            var minor = Assembly.GetExecutingAssembly().GetName().Version.Minor.ToString();
            var build = Assembly.GetExecutingAssembly().GetName().Version.Build.ToString();

            return !revision ? major + "." + minor : major + "." + minor + " (" + build + ")";
        }

        // get ARP targets
        private List<Target> GetTargets(ListView list)
        {
            var targets = new List<Target>();

            foreach (var item in list.SelectedItems)
            {
                if(item is Target) targets.Add((item as Target));
            }

            return targets.Count > 0 ? targets : null;
        }

        // get ARP target
        private Target GetTarget(ListView list)
        {
            return list.SelectedItem != null ? (list.SelectedItem as Target) : null;
        }

        /* Button handlers */

        // "Scan network"
        private void BScanNetwork_Click(object sender, RoutedEventArgs e)
        {
            // check for bad interface
            if (Nighthawk.DeviceInfoList[CInterface.SelectedIndex].IP == "0.0.0.0") 
            {
                MessageBox.Show("Invalid interface! Please select another one from the list.", "Nighthawk - network scan",
                        MessageBoxButton.OK, MessageBoxImage.Exclamation);

                return;
            }

            // start device
            if (!Nighthawk.Started)
            {
                Nighthawk.StartDevice(CInterface.SelectedIndex);
            }
            // restart device
            else
            {
                Nighthawk.StopDevice();
                Nighthawk.StartDevice(CInterface.SelectedIndex);
            }

            // clear collection
            TargetList.Clear();

            // start scanner
            Nighthawk.Scanner.ScanNetwork((bool)CHResolveHostnames.IsChecked);

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
                Nighthawk.Sniffer.Start((bool)CHExcludeSnifferLocalIP.IsChecked);

                // update button text, color
                BStartSniffer.Content = "Stop sniffer";
                SHStartSniffer.Color = EnabledColor;
                SBSniffer.Enabled = true;
            }
            else
            {
                // stop sniffer
                Nighthawk.Sniffer.Stop();

                // update button text, color
                BStartSniffer.Content = "Start sniffer";
                SHStartSniffer.Color = DisabledColor;
                SBSniffer.Enabled = false;
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
                    SBArp.Enabled = true;
                }
                else
                {
                    MessageBox.Show("Please select desired targets.", "Nighthawk - ARP spoofing",
                        MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
            }
            else
            {
                // stop spoofing
                Nighthawk.ARPTools.StopSpoofing();
               
                // update button text, color
                BStartARP.Content = "Start ARP spoofing";
                SHStartARP.Color = DisabledColor;
                SBArp.Enabled = false;
            }
        }

        // "Start/Stop NDP spoofing"
        private void BStartNDP_Click(object sender, RoutedEventArgs e)
        {
            if (!Nighthawk.NDPTools.SpoofingStarted)
            {
                // start spoofing
                Nighthawk.NDPTools.StartSpoofing();

                // update button text, color
                BStartNDP.Content = "Stop NDP spoofing";
                SHStartNDP.Color = EnabledColor;
                SBNdp.Enabled = true;
            }
            else
            {
                // stop spoofing
                Nighthawk.NDPTools.StopSpoofing();

                // update button text, color
                BStartNDP.Content = "Start NDP spoofing";
                SHStartNDP.Color = DisabledColor;
                SBNdp.Enabled = false;
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
                    MessageBox.Show("SSL stripping requires active ARP spoofing to function properly.", "Nighthawk - SSL stripping",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);

                    return;
                }

                // start SSL strip
                Nighthawk.SSLStrip.Start((bool)CHExcludeSSLLocalIP.IsChecked, Nighthawk.ARPTools);

                // update button text, color
                BStartSSLstrip.Content = "Stop SSL stripping";
                SHStartSSLstrip.Color = EnabledColor;
                SBSsl.Enabled = true;
            }
            else
            {
                // start SSL strip
                Nighthawk.SSLStrip.Stop();

                // update button text, color
                BStartSSLstrip.Content = "Start SSL stripping";
                SHStartSSLstrip.Color = DisabledColor;
                SBSsl.Enabled = false;
            }
        }

        // refresh interfaces
        private void BInterfaceRefresh_Click(object sender, RoutedEventArgs e)
        {
            // check for active tools
            if (!Nighthawk.Started || (Nighthawk.Started && !Nighthawk.Scanner.Started && !Nighthawk.ARPTools.SpoofingStarted && !Nighthawk.NDPTools.SpoofingStarted && !Nighthawk.Sniffer.Started && !Nighthawk.SSLStrip.Started))
            {
                CInterface.ItemsSource = Nighthawk.GetInterfaces();
            }
            else
            {
                MessageBox.Show("Please stop any active tools or wait for an active scan to complete.", "Nighthawk - interfaces",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);
            }
        }

        /* Menu events */

        // Help -> About
        private void MenuItemAbout_Click(object sender, RoutedEventArgs e)
        {
            About window = new About();
            window.Show();
        }
        
        // File -> Save network list
        private void MenuItemSaveNetwork_Click(object sender, RoutedEventArgs e)
        {
            if (TargetList.Count > 0)
            {
                var fileData = new StringBuilder();

                // create first line
                fileData.AppendLine("IPv4 address;IPv6 address;MAC;Vendor;Hostname");

                foreach (var item in TargetList)
                {
                    fileData.AppendLine(item.IP + ";" + item.IPv6 + ";" + item.MAC + ";" + item.Vendor + ";" + item.Hostname);
                }

                // show dialog
                SaveFileDialog dialog = new SaveFileDialog();
                dialog.Title = "Save network list";
                dialog.FileName = "Network"; // Default file name
                dialog.DefaultExt = ".csv"; // Default file extension
                dialog.Filter = "CSV file |*.csv"; // Filter files by extension

                Nullable<bool> result = dialog.ShowDialog();

                if (result == true)
                {
                    // try to save file
                    try
                    {
                        FileStream file = File.Open(dialog.FileName, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                                              FileShare.None);

                        var data = Encoding.Unicode.GetBytes(fileData.ToString());
                        
                        file.Write(data, 0, data.Length);
                        
                    }
                    catch
                    {
                        MessageBox.Show("Unable to save file. Please try again with a different location or filename", "Nighthawk - file error",
                                    MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        // File -> Save network list
        private void MenuItemSaveSniffer_Click(object sender, RoutedEventArgs e)
        {
            if (SnifferResultList.Count > 0)
            {
                var fileData = new StringBuilder();

                // create first line
                fileData.AppendLine("Type;URL;Username;Password;Aditional");

                foreach (var item in SnifferResultList)
                {
                    // get type
                    var type = "";

                    if (item.Type == SnifferResultType.HTML) type = "HTML";
                    if (item.Type == SnifferResultType.HTTPAuth) type = "HTTP authentication";

                    fileData.AppendLine(type  + ";" + item.URL + ";" + item.Username + ";" + item.Password + ";" +
                                        item.Aditional);
                }

                // show dialog
                SaveFileDialog dialog = new SaveFileDialog();
                dialog.Title = "Save sniffer results";
                dialog.FileName = "Sniffer";
                dialog.DefaultExt = ".csv";
                dialog.Filter = "CSV file |*.csv";

                Nullable<bool> result = dialog.ShowDialog();

                if (result == true)
                {
                    // try to save file
                    try
                    {
                        FileStream file = File.Open(dialog.FileName, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                                                    FileShare.None);

                        var data = Encoding.Unicode.GetBytes(fileData.ToString());

                        file.Write(data, 0, data.Length);

                    }
                    catch
                    {
                        MessageBox.Show("Unable to save file. Please try again with a different location or filename",
                                        "Nighthawk - file error",
                                        MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        // File -> Exit
        private void MenuItemExit_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to exit the application?", "Nighthawk", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
            {
                Close();
                Application.Current.Shutdown();
            }
        }
    }
}
