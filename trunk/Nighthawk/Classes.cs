using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Windows.Media;
using System.Windows.Shapes;
using SharpPcap;

namespace Nighthawk
{
    // GUI - observable collection for targets
    public class TargetList : ObservableCollection<Target>
    {
        public bool ContainsIP(string ip)
        {
            foreach (Target target in this)
            {
                if (target.IP == ip) return true;
            }

            return false;
        }
    }

    // target class
    public class Target : INotifyPropertyChanged
    {
        private string _Hostname;

        public string IP { get; set; }
        public string IPv6 { get; set; }
        public string MAC { get; set; }
        public PhysicalAddress PMAC { get; set; }
        public string Vendor { get; set; }

        public Target()
        {
            IPv6 = "/";
        }

        public event PropertyChangedEventHandler PropertyChanged;

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

    // GUI - observable collection for sniffer results
    public class SnifferResultList : ObservableCollection<SnifferResult>
    {
        
    }

    // sniffer result class
    public class SnifferResult
    {
        public SnifferResultType Type { get; set; }
        public SolidColorBrush ShapeBrush { get; set; }
        public string URL { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Aditional { get; set; }
    }

    // device (interface) info class
    public class DeviceInfo
    {
        public LivePcapDevice Device;
        public string IP;
        public string IPv6;
        public string Mask;
        public string Broadcast;
        public int CIDR;
        public int CIDRv6;
    }
}
