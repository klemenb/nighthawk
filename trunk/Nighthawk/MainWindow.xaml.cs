using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shell;
using Microsoft.Win32;

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
    public partial class MainWindow : Window
    {
        public Main Nighthawk;

        public TargetList TargetList = new TargetList();
        public SnifferResultList SnifferResultList = new SnifferResultList();

        public Color DisabledColor = Color.FromRgb(255, 89, 89);
        public Color EnabledColor = Color.FromRgb(110, 220, 110);

        public Color ColorSnifferHTML = Color.FromRgb(0, 0, 151);
        public Color ColorSnifferHTTPAuth = Color.FromRgb(167, 0, 0);
        public Color ColorSnifferFTP = Color.FromRgb(0, 150, 0);
        public Color ColorSnifferIMAP = Color.FromRgb(255, 140, 0);
        public Color ColorSnifferPOP3 = Color.FromRgb(120, 0, 120);
        public Color ColorSnifferSMTP = Color.FromRgb(91, 221, 255);

        public Color ColorSSLStrip = Color.FromRgb(60, 60, 60);

        public bool QuickAttack = false;
        public bool WindowLoaded = false;
        
        public MainWindow()
        {
            InitializeComponent();

            TaskbarItemInfo = new TaskbarItemInfo();
            TaskbarItemInfo.ProgressState = new TaskbarItemProgressState();

            RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Nighthawk = new Main(this);

            Title = "Nighthawk " + GetWindowTitle(false);

            // "Loading..." interfaces
            CInterface.ItemsSource = new List<string> { "Loading..." };
            CInterface.SelectedIndex = 0;

            // do startup things in the background
            var startupThread = new Thread(new ThreadStart(Startup));
            startupThread.Start();

            // windows 8 sniffer notification
            if (Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor > 1)
                RCTSnifferUpdated.Margin = new Thickness(122, RCTSnifferUpdated.Margin.Top, RCTSnifferUpdated.Margin.Right, RCTSnifferUpdated.Margin.Bottom);
        }

        private void Startup()
        {
            // load OUI database
            Nighthawk.LoadOUI();

            var interfaces = Nighthawk.GetInterfaces();

            Dispatcher.BeginInvoke(new UI(delegate
            {
                // fill interfaces
                CInterface.ItemsSource = interfaces;

                if (((List<string>)CInterface.ItemsSource).Count > 0) CInterface.SelectedIndex = 0;

                LArpTargets1List.ItemsSource = TargetList;
                LArpTargets2List.ItemsSource = TargetList;

                LSnifferResults.ItemsSource = SnifferResultList;

                // select first working interface from the list
                SelectWorkingInterface();

                // enable network scanning
                BScanNetwork.IsEnabled = true;
            }));

            WindowLoaded = true;
        }
        
        private void Window_Closed(object sender, EventArgs e)
        {
            if (WindowLoaded && Nighthawk.Started)
            {
                Nighthawk.ARPTools.StopSpoofing();
                Nighthawk.NDTools.StopSpoofing();
                Nighthawk.Sniffer.Stop();
                Nighthawk.SSLStrip.Stop();

                while (Nighthawk.Scanner.Started)
                {
                    Thread.Sleep(50);
                }

                Nighthawk.StopDevice();

                Application.Current.Shutdown();
            }
        }

        // get current title (from AssemblyVersion)
        public static string GetWindowTitle(bool revision)
        {
            var major = Assembly.GetExecutingAssembly().GetName().Version.Major.ToString();
            var minor = Assembly.GetExecutingAssembly().GetName().Version.Minor.ToString();
            var subminor = Assembly.GetExecutingAssembly().GetName().Version.Build.ToString();

            return major + "." + minor + "." + subminor;
        }

        // select working interface
        public void SelectWorkingInterface() 
        {
            // check all available interfaces
            for(int i = 0; i < Nighthawk.DeviceInfoList.Count; i++)
            {
                var device = Nighthawk.DeviceInfoList[i];

                // check for all the neccessary params
                if(device.IP != "0.0.0.0" && device.GatewayIP != null)
                {
                    CInterface.SelectedIndex = i;
                    break;
                }
            }
        }

        // get selected ARP targets
        private List<Target> GetTargets(ListView list)
        {
            var targets = new List<Target>();

            foreach (var item in list.SelectedItems)
            {
                if(item is Target) targets.Add((Target) item);
            }

            return targets.Count > 0 ? targets : null;
        }

        // get selected ARP target
        private Target GetTarget(ListView list)
        {
            return list.SelectedItem != null ? (Target) list.SelectedItem : null;
        }

        /* Button handlers */

        // "Scan network"
        private void BScanNetwork_Click(object sender, RoutedEventArgs e)
        {
            // check for bad interface
            if (Nighthawk.DeviceInfoList.Count == 0 || Nighthawk.DeviceInfoList[CInterface.SelectedIndex].IP == "0.0.0.0")
            {
                MessageBox.Show("Invalid interface! Please select another one from the list.",
                                "Nighthawk - network scan",
                                MessageBoxButton.OK, MessageBoxImage.Exclamation);

                QuickAttack = false;

                return;
            }

            // check for active ARP spoofing or SSL stripping
            if (Nighthawk != null) {
                if (Nighthawk.ARPTools != null && Nighthawk.ARPTools.SpoofingStarted)
                {
                    MessageBox.Show("Please stop ARP spoofing before running another scan.", "Nighthawk - network scan",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);

                    return;
                }

                if (Nighthawk.NDTools != null && Nighthawk.NDTools.SpoofingStarted)
                {
                    MessageBox.Show("Please stop ND spoofing before running another scan.", "Nighthawk - network scan",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);

                    return;
                }

                if (Nighthawk.SSLStrip != null && Nighthawk.SSLStrip.Started)
                {
                    MessageBox.Show("Please stop SSL stripping before running another scan.", "Nighthawk - network scan",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);

                    return;
                }
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

            TargetList.Clear();

            // reset lists and clear filters
            LArpTargets1List.ItemsSource = TargetList;
            LArpTargets2List.ItemsSource = TargetList;

            LArpTargets1List.Items.Filter = null;
            LArpTargets2List.Items.Filter = null;

            Nighthawk.Scanner.ScanNetwork(CHResolveHostnames.IsChecked != null ? (bool)CHResolveHostnames.IsChecked : false);

            // update GUI
            BScanNetwork.Content = "Scanning...";
            BScanNetwork.IsEnabled = false;
            CHResolveHostnames.IsEnabled = false;
        }

        // "Start/Stop sniffer"
        private void BStartSniffer_Click(object sender, RoutedEventArgs e)
        {
            if (Nighthawk.Sniffer == null || !Nighthawk.Sniffer.Started)
            {
                if (!Nighthawk.Started)
                {
                    Nighthawk.StartDevice(CInterface.SelectedIndex);
                }

                Nighthawk.Sniffer.Start((bool)CHExcludeSnifferLocalIP.IsChecked);

                // update GUI
                BStartSniffer.Content = "Stop sniffer";
                SHStartSniffer.Fill = new SolidColorBrush(EnabledColor);
                SBSniffer.Enabled = true;
                CHExcludeSnifferLocalIP.IsEnabled = false;
            }
            else
            {
                Nighthawk.Sniffer.Stop();

                // update GUI
                BStartSniffer.Content = "Start sniffer";
                SHStartSniffer.Fill = new SolidColorBrush(DisabledColor);
                SBSniffer.Enabled = false;
                CHExcludeSnifferLocalIP.IsEnabled = true;
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
                    Nighthawk.ARPTools.StartSpoofing(GetTargets(LArpTargets1List), GetTarget(LArpTargets2List), CHBlockPPTP.IsChecked != null ? (bool)CHBlockPPTP.IsChecked : false);

                    // update GUI
                    BStartARP.Content = "Stop ARP spoofing";
                    CHBlockPPTP.IsEnabled = false;
                    SHStartARP.Fill = new SolidColorBrush(EnabledColor);
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
                Nighthawk.ARPTools.StopSpoofing();

                // update GUI
                BStartARP.Content = "Start ARP spoofing";
                CHBlockPPTP.IsEnabled = true;
                SHStartARP.Fill = new SolidColorBrush(DisabledColor);
                SBArp.Enabled = false;
            }
        }

        // "Start/Stop ND spoofing"
        private void BStartND_Click(object sender, RoutedEventArgs e)
        {
            if (!Nighthawk.NDTools.SpoofingStarted)
            {
                var targetList = TargetList.ToList();

                if (Network.PrefixValid(TBPrefix.Text) && Nighthawk.DeviceInfo.GatewayIPv6 != string.Empty && targetList.Find(t => t.IPv6List.Contains(Nighthawk.DeviceInfo.GatewayIPv6)) != null)
                {
                    Nighthawk.NDTools.StartSpoofing(TBPrefix.Text, targetList);

                    // update GUI
                    BStartND.Content = "Stop ND spoofing";
                    SHStartND.Fill = new SolidColorBrush(EnabledColor);
                    SBNd.Enabled = true;
                }
                else
                {
                    if (!QuickAttack)
                    {
                        MessageBox.Show("There was a problem detecting IPv6/MAC address of the gateway.", "Nighthawk - ND spoofing", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    }
                }
            }
            else
            {
                Nighthawk.NDTools.StopSpoofing();

                // update GUI
                BStartND.Content = "Start ND spoofing";
                SHStartND.Fill = new SolidColorBrush(DisabledColor);
                SBNd.Enabled = false;
            }
        }
        
        // "Start/Stop SSL stripping"
        private void BStartSSLstrip_Click(object sender, RoutedEventArgs e)
        {
            if (Nighthawk.SSLStrip == null || !Nighthawk.SSLStrip.Started)
            {
                if (!Nighthawk.Started)
                {
                    Nighthawk.StartDevice(CInterface.SelectedIndex);
                }

                if (!Nighthawk.ARPTools.SpoofingStarted && !Nighthawk.NDTools.SpoofingStarted)
                {
                    MessageBox.Show("SSL stripping requires active ARP or ND spoofing to function properly.", "Nighthawk - SSL stripping",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);

                    return;
                }

                Nighthawk.SSLStrip.Start(CHStripCookies.IsChecked != null ? (bool)CHStripCookies.IsChecked : false);

                // update GUI
                BStartSSLstrip.Content = "Stop SSL stripping";
                SHStartSSLstrip.Fill = new SolidColorBrush(EnabledColor);
                SBSsl.Enabled = true;
                CHStripCookies.IsEnabled = false;
            }
            else
            {
                Nighthawk.SSLStrip.Stop();

                // update GUI
                BStartSSLstrip.Content = "Start SSL stripping";
                SHStartSSLstrip.Fill = new SolidColorBrush(DisabledColor);
                SBSsl.Enabled = false;
                CHStripCookies.IsEnabled = true;
            }
        }

        // refresh interfaces
        private void BInterfaceRefresh_Click(object sender, RoutedEventArgs e)
        {
            if (!Nighthawk.Started || (Nighthawk.Started && !Nighthawk.Scanner.Started && !Nighthawk.ARPTools.SpoofingStarted && !Nighthawk.Sniffer.Started && !Nighthawk.SSLStrip.Started))
            {
                CInterface.ItemsSource = Nighthawk.GetInterfaces();
            }
            else
            {
                MessageBox.Show("Please stop any active tools or wait for an active scan to complete.", "Nighthawk - interfaces",
                                    MessageBoxButton.OK, MessageBoxImage.Exclamation);
            }
        }

        // clear sniffer results
        private void BClearSniffer_Click(object sender, RoutedEventArgs e)
        {
            SnifferResultList.Clear();
        }

        // selected advanced mode
        private void BSelectAdvancedMode_Click(object sender, RoutedEventArgs e)
        {
            GRModeSelect.Visibility = Visibility.Collapsed;
        }

        // selected quick attack mode
        private void BSelectQuickAttack_Click(object sender, RoutedEventArgs e)
        {
            QuickAttack = true;
            BScanNetwork_Click(null, null);

            // this can be false if scan throws an error
            if (QuickAttack)
            {
                GRModeSelect.Visibility = Visibility.Collapsed;
                GRQuickAttack.Visibility = Visibility.Visible;
            }
        }

        // stop quick attack
        private void BStopQuickAttack_Click(object sender, RoutedEventArgs e)
        {
            GRModeSelect.Visibility = Visibility.Visible;
            GRQuickAttack.Visibility = Visibility.Collapsed;

            QuickAttack = false;
            if(Nighthawk.Sniffer.Started) BStartSniffer_Click(null, null);
            if(Nighthawk.SSLStrip.Started) BStartSSLstrip_Click(null, null);
            if(Nighthawk.ARPTools.SpoofingStarted) BStartARP_Click(null, null);

            if(Nighthawk.NDTools.SpoofingStarted) BStartND_Click(null, null);
        }

        // current tab changed
        private void TCTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            RCTSnifferUpdated.Visibility = Visibility.Collapsed;

            ((Storyboard)Resources["STSnifferUpdated"]).Stop();

            TaskbarItemInfo.ProgressState = TaskbarItemProgressState.None;
        }

        // start quick attack (after scan completes)
        public void StartQuickAttack()
        {
            // clone source items
            LArpTargets1List.ItemsSource = TargetList.ToList();
            LArpTargets2List.ItemsSource = TargetList.ToList();
           
            // filter out hosts
            LArpTargets1List.Items.Filter = TargetFilterHosts;
            LArpTargets1List.UpdateLayout();
            LArpTargets1List.SelectAll();

            // filter out gateway
            LArpTargets2List.Items.Filter = TargetFilterGateway;
            LArpTargets2List.UpdateLayout();
            LArpTargets2List.SelectedIndex = 0;

            BStartARP_Click(null, null);

            if (Nighthawk.DeviceInfo.IPv6 != string.Empty && Nighthawk.DeviceInfo.GatewayIPv6 != string.Empty && !Nighthawk.DeviceInfo.IPv6.Contains("fe80::"))
                BStartND_Click(null, null);

            BStartSSLstrip_Click(null, null);
            BStartSniffer_Click(null, null);

            TCTabs.SelectedIndex = 1;
        }

        // gateway filter
        private bool TargetFilterGateway(object t)
        {
            return ((Target)t).IP == Nighthawk.DeviceInfo.GatewayIP;
        }

        // host filter
        private bool TargetFilterHosts(object t)
        {
            return ((Target)t).IP != Nighthawk.DeviceInfo.GatewayIP && ((Target)t).IP != "/";
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
                        file.Close();
                    }
                    catch
                    {
                        MessageBox.Show("Unable to save file. Please try again with a different location or filename.", "Nighthawk - file error",
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
                fileData.AppendLine("Type;Date;URL;Username;Password;Aditional info");

                foreach (var item in SnifferResultList)
                {
                    // get type
                    var type = "";

                    if (item.Type == SnifferResultType.HTML) type = "HTML form";
                    if (item.Type == SnifferResultType.HTTPAuth) type = "HTTP authentication";

                    fileData.AppendLine(type  + ";" + item.Time.ToString("dd-MM-yyyy HH:mm:ss") + ";" + item.URL + ";" + item.Username + ";" + item.Password + ";" +
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
                        file.Close();
                    }
                    catch
                    {
                        MessageBox.Show("Unable to save file. Please try again with a different location or filename.",
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
