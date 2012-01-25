using System;
using System.Collections.ObjectModel;
using System.IO.IsolatedStorage;
using System.Net;
using System.ServiceModel;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using HawkWP.RemoteHawk;
using Microsoft.Phone.Controls;

namespace HawkWP
{
    public partial class MainPage : PhoneApplicationPage
    {
        private RemoteHawkClient client;
        private Timer timer;

        private int previousResultsCount;

        private bool started;
        private bool freshStart;

        private IsolatedStorageSettings settings;

        // constructor
        public MainPage()
        {
            InitializeComponent();

            hideInfoTB();

            // load settings
            settings = IsolatedStorageSettings.ApplicationSettings;

            if (settings.Contains("ipaddress")) TB_Host.Text = settings["ipaddress"].ToString();

            // set the data context of the listbox control to the sample data
            DataContext = App.ViewModel;
        }

        // hide textboxes
        private void hideInfoTB()
        {
            LTB_IPv4Clients.Visibility = Visibility.Collapsed;
            LTB_IPv6Spoofing.Visibility = Visibility.Collapsed;
            LTB_IPv4Network.Visibility = Visibility.Collapsed;
            LTB_ARPSpoofing.Visibility = Visibility.Collapsed;

            TB_IPv4Clients.Visibility = Visibility.Collapsed;
            TB_IPv6Spoofing.Visibility = Visibility.Collapsed;
            TB_IPv4Network.Visibility = Visibility.Collapsed;
            TB_ARPSpoofing.Visibility = Visibility.Collapsed;
        }

        // receive callback
        private void client_CredentialsReceived(object sender, GetCredentialsCompletedEventArgs e)
        {
            if (e.Error == null)
            {
                Dispatcher.BeginInvoke(delegate
                {
                    if(e.Result != null)
                    {
                        // loada data
                        LoadData(e.Result);

                        // notification
                        if(PV_Main.SelectedIndex == 0 && previousResultsCount < e.Result.Count)
                        {
                            TB_Notification.Visibility = Visibility.Visible;
                            SH_Arrow.Visibility = Visibility.Visible;

                            ArrowBlink.Begin();
                        }

                        previousResultsCount = e.Result.Count;
                        
                        // first receive
                        if (freshStart)
                        {
                            freshStart = false;
                            started = true;

                            // dispose pooling timer
                            timer.Dispose();

                            // get other things
                            client.GetClientsAsync();
                            client.GetIPv6SpoofingAsync();
                            client.GetNetworkAsync();

                            // change GUI
                            BTN_Start.IsEnabled = true;
                            BTN_Start.Content = "Disconnect";

                            // change status
                            TB_Status.Text = "connected";
                        }

                        // update others
                        client.GetNetworkAsync();
                        client.GetIPv6SpoofingAsync();
                        client.GetClientsAsync();

                        // timer for the next one
                        timer.Dispose();
                        timer = new Timer(TimerCallback, null, 1000, -1);
                    } else
                    {
                        // on first connection error
                        if (!started && freshStart)
                        {
                            // close pooling timer
                            if (timer != null)
                            {
                                timer.Dispose();
                            }

                            started = false;

                            // change GUI
                            BTN_Start.IsEnabled = true;

                            // change status
                            TB_Status.Text = "disconnected";

                            MessageBox.Show("Nighthawk instance was not found at this address. Please change the IP address to a running Nighthawk instance.",
                                "Connection failed", MessageBoxButton.OK);
                        } 
                        // on connection error when already connected
                        else
                        {
                            // close timer
                            if(timer != null) timer.Dispose();

                            started = false;

                            MessageBox.Show("There was an error communicating with Nighthawk. Please try to reconnect.",
                                "Connection error", MessageBoxButton.OK);

                            // change GUI
                            BTN_Start.Content = "Connect";
                            BTN_Start.IsEnabled = true;

                            // change status
                            TB_Status.Text = "disconnected";
                        }
                    }
                });
            }
        }

        // load sniffer data
        public void LoadData(ObservableCollection<ObservableCollection<string>> data)
        {
            var items = new ObservableCollection<ItemViewModel>();

            foreach (var item in data)
            {
                // remove "www."
                if (item[0].StartsWith("www.")) item[0] = item[0].Remove(0, 4);

                // append labels
                item[1] = "user: " + item[1];
                item[2] = "pass: " + item[2];

                // create itemviewmodel
                items.Add(new ItemViewModel { LineOne = item[0], LineTwo = item[1], LineThree = item[2] });
            }

            // load data
            App.ViewModel.LoadData(items);
        }

        // button start
        private void BTN_Start_Click(object sender, RoutedEventArgs e)
        {
            if(started)
            {
                started = false;

                // close timer and start closing connection
                timer.Dispose();
                client.CloseAsync();

                // change button state
                BTN_Start.IsEnabled = true;
                BTN_Start.Content = "Connect";

                // change status
                TB_Status.Text = "disconnected";
            } else
            {
                if(TB_Host.Text != String.Empty)
                {
                    try
                    {
                        var ip = IPAddress.Parse(TB_Host.Text);
                    } catch
                    {
                        MessageBox.Show("Please enter a valid IP address.", "Invalid IP address", MessageBoxButton.OK);

                        return;
                    }

                    if(settings.Contains("ipaddress"))
                    {
                        settings["ipaddress"] = TB_Host.Text;
                    } else
                    {
                        settings.Add("ipaddress", TB_Host.Text);
                    }

                    settings.Save();

                    freshStart = true;

                    // connect to WCF service
                    client = new RemoteHawkClient(new BasicHttpBinding(), new EndpointAddress("http://" + TB_Host.Text + ":51337/remotehawk"));

                    client.GetCredentialsCompleted += client_CredentialsReceived;
                    client.GetClientsCompleted += client_GetClientsCompleted;
                    client.GetIPv6SpoofingCompleted += client_GetIPv6SpoofingCompleted;
                    client.GetNetworkCompleted += client_GetNetworkCompleted;
                        
                    client.Endpoint.Binding.OpenTimeout = TimeSpan.FromSeconds(3);
                    client.Endpoint.Binding.SendTimeout = TimeSpan.FromSeconds(3);
                    client.Endpoint.Binding.ReceiveTimeout = TimeSpan.FromSeconds(3);

                    // timer for the next one
                    timer = new Timer(TimerCallback, null, 500, -1);

                    BTN_Start.IsEnabled = false;

                    // change status
                    TB_Status.Text = "connecting";
                }
            }
        }

        // ipv6 spoofing state received
        private void client_GetIPv6SpoofingCompleted(object sender, GetIPv6SpoofingCompletedEventArgs e)
        {
            LTB_IPv6Spoofing.Visibility = Visibility.Visible;
            TB_IPv6Spoofing.Visibility = Visibility.Visible;
            TB_IPv6Spoofing.Text = e.Result ? "On" : "Off";
        }

        // network received
        private void client_GetNetworkCompleted(object sender, GetNetworkCompletedEventArgs e)
        {
            LTB_IPv4Network.Visibility = Visibility.Visible;
            TB_IPv4Network.Visibility = Visibility.Visible;
            TB_IPv4Network.Text = e.Result != "/" ? e.Result : "ARP spoofing stopped";
        }

        // number of clients received
        private void client_GetClientsCompleted(object sender, GetClientsCompletedEventArgs e)
        {
            LTB_IPv4Clients.Visibility = Visibility.Visible;
            TB_IPv4Clients.Visibility = Visibility.Visible;
            TB_IPv4Clients.Text = e.Result != 0 ? e.Result.ToString() : "ARP spoofing stopped";
        }

        // timer callback
        private void TimerCallback(object s)
        {
            client.GetCredentialsAsync();

            return;
        }

        // pivot item changed
        private void PV_Main_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if(PV_Main.SelectedIndex == 1)
            {
                if(ArrowBlink.GetCurrentState() != ClockState.Stopped) ArrowBlink.Stop();

                TB_Notification.Visibility = Visibility.Collapsed;
                SH_Arrow.Visibility = Visibility.Collapsed;
            }
        }
    }
}