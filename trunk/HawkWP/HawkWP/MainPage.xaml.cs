using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.ServiceModel;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using HawkWP.RemoteHawk;
using Microsoft.Phone.Controls;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Phone.Net.NetworkInformation;

namespace HawkWP
{
    public partial class MainPage : PhoneApplicationPage
    {
        private RemoteHawkClient client;
        private Timer timer;

        private int previousResultsCount;

        private bool started;      

        // constructor
        public MainPage()
        {
            InitializeComponent();
            
            // hide TB's
            LTB_IPv4Clients.Visibility = Visibility.Collapsed;
            LTB_IPv6Spoofing.Visibility = Visibility.Collapsed;
            LTB_IPv4Network.Visibility = Visibility.Collapsed;

            // change context
            DataContext = App.ViewModel;
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
                        if (!started)
                        {
                            started = true;

                            // dispose pooling timer
                            if (timer != null) timer.Dispose();

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

                        // timer for the next one
                        timer = new Timer(TimerCallback, null, 1000, 0);
                    } else
                    {
                        // on first connection error
                        if (!started)
                        {
                            // close pooling timer
                            if (timer != null) timer.Dispose();

                            // change GUI
                            BTN_Start.IsEnabled = true;

                            // change status
                            TB_Status.Text = "disconnected";

                            MessageBox.Show("Nighthawk instance was not found at this address. Please change the IP/hostname to a running Nighthawk instance.",
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
                if (item[0].StartsWith("www.")) item[0].Remove(0, 4);

                // append labels
                item[1] = "user: " + item[1];
                item[2] = "pass: " + item[2];

                // create itemviewmodel
                items.Add(new ItemViewModel {LineOne = item[0], LineTwo = item[1], LineThree = item[2]});
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
                    // connect to WCF service
                    client = new RemoteHawkClient(new BasicHttpBinding(), new EndpointAddress("http://" + TB_Host.Text + ":51337/remotehawk"));

                    client.GetCredentialsCompleted += client_CredentialsReceived;
                    client.GetClientsCompleted += client_GetClientsCompleted;
                    client.GetIPv6SpoofingCompleted += client_GetIPv6SpoofingCompleted;
                    client.GetNetworkCompleted += client_GetNetworkCompleted;
                        
                    client.Endpoint.Binding.OpenTimeout = TimeSpan.FromSeconds(3);

                    client.GetCredentialsAsync();

                    // timer for the next one
                    // timer = new Timer(TimerCallback, null, 100, 500);

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
            TB_IPv6Spoofing.Text = e.Result ? "on" : "off";
        }

        // network received
        private void client_GetNetworkCompleted(object sender, GetNetworkCompletedEventArgs e)
        {
            LTB_IPv4Network.Visibility = Visibility.Visible;
            TB_IPv4Network.Text = e.Result;
        }

        // number of clients received
        private void client_GetClientsCompleted(object sender, GetClientsCompletedEventArgs e)
        {
            LTB_IPv4Clients.Visibility = Visibility.Visible;
            TB_IPv4Clients.Text = e.Result.ToString();
        }

        // timer callback
        private void TimerCallback(object s)
        {
            client.GetCredentialsAsync();
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