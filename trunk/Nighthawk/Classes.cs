using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Windows.Media;
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
    // observable collection for targets
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

        public List<Target> ToList()
        {
            return new List<Target>(this);
        }
    }

    // target class
    public class Target : INotifyPropertyChanged, IComparable
    {
        private string _Hostname;
        private string _IPv6;
        private string _IP;

        public List<string> IPv6List { get; set; }
        
        public string MAC { get; set; }
        public PhysicalAddress PMAC { get; set; }
        public string Vendor { get; set; }

        public Target()
        {
            _IP = "/";
            _IPv6 = "/";

            IPv6List = new List<string>();
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

        public string IP
        {
            get { return _IP; }
            set
            {
                _IP = value;
                OnPropertyChanged("IP");
            }
        }

        public string IPv6
        {
            get { return _IPv6; }
            set
            {
                _IPv6 = value;
                OnPropertyChanged("IPv6");
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

        public int CompareTo(object o)
        {
            if (((Target) o).IP == "/") return -1;
            if (IP == "/") return 1;

            long num2 = Network.IPToLong(((Target) o).IP);
            long num1 = Network.IPToLong(IP);
             
            if (num1 > num2)
                return 1;

            if (num1 < num2)
                return -1;
            
            return 0;
        }       
    }

    // observable collection for sniffer results
    public class SnifferResultList : ObservableCollection<SnifferResult>
    {
        
    }

    // sniffer result class
    public class SnifferResult
    {
        public SnifferResultType Type { get; set; }
        public SolidColorBrush ShapeBrush { get; set; }
        public DateTime Time { get; set; }
        public string URL { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Aditional { get; set; }

        public SnifferResult()
        {
            Time = DateTime.Now;
        }

        public string CompareString()
        {
            return ShapeBrush.Color.ToString() + URL + Username + Password + Aditional;
        }
    }

    // device (interface) info class
    public class DeviceInfo
    {
        public WinPcapDevice Device;
        public string IP;
        public string IPv6;
        public List<string> IPv6List = new List<string>();
        public string GatewayIP;
        public string GatewayIPv6;
        public string LinkLocal;
        public string Mask;
        public string WinName;
        public string Broadcast;
        public PhysicalAddress PMAC;
        public PhysicalAddress GatewayPMAC;
        public int CIDR;
        public int CIDRv6;
    }

    // extension methods
    public static class Extensions
    {
        // ObservableList sorting
        public static void Sort<T>(this ObservableCollection<T> collection) where T : IComparable
        {
            List<T> sorted = collection.OrderBy(x => x).ToList();

            for (int i = 0; i < sorted.Count(); i++)
                collection.Move(collection.IndexOf(sorted[i]), i);
        }
    }
}
