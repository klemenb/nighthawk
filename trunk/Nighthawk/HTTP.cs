using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SharpPcap;
using PacketDotNet;

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
    /**
     * HTTP parsing class (simple implementation)
     * 
     * Important:
     * "HTTP packet" is here considered only the part with "HTTP header" included and we don't keep track of whole TCP streams (we don't need it)
     */
    public class HttpPacket
    {
        // public
        public HttpHeader Header;
        public List<string[]> PostParams = new List<string[]>();

        // packet information
        private TcpPacket Packet;

        // regex
        private static Regex regexIsHTTP = new Regex(@"HTTP\/1\.", RegexOptions.Compiled | RegexOptions.Singleline);
        
        // encoding converter (for bytes -> string conversion)
        private static UTF8Encoding encoding = new UTF8Encoding();

        // constructor
        public HttpPacket(TcpPacket packet)
        {
            // set packet
            Packet = packet;

            // get ASCII data
            var data = encoding.GetString(packet.PayloadData);

            // split header & content
            string[] parts = Regex.Split(data, "\r\n\r\n");

            // fill header
            Header = new HttpHeader(parts[0]);

            var postParts = HasPOST(packet);

            // get POST parameters (key=value)
            if (postParts || parts[0].Substring(0, 4) == "POST")
            {
                // split params
                if (postParts || parts.Length > 1)
                {
                    var postLine = data;
                    
                    // modify data for basic parsing
                    if (!postParts) postLine = parts[0];

                    var postParams = postLine.Split('&');

                    // fill List<>
                    foreach (var param in postParams)
                    {
                        if (param.IndexOf('=') > 0)
                        {
                            var splitParam = param.Split('=');

                            if (splitParam.Length == 2)
                            {
                                PostParams.Add(new string[]
                                {
                                    splitParam[0] != null ? splitParam[0] : string.Empty,
                                    splitParam[1] != null ? splitParam[1] : string.Empty
                                });
                            }
                        }
                    }
                }
            }
        }

        // check if packet is HTTP packet
        public static bool IsHTTP(TcpPacket packet)
        {
            // check for null payload
            if (packet.PayloadData != null)
            {
                // check for HTTP
                if (SimpleRegex.GetMatches(regexIsHTTP, encoding.GetString(packet.PayloadData)).Count > 0) return true;
            }

            return false;
        }

        // check if packet might contain traces of POST data (if client sent separate packets)
        public static bool HasPOST(TcpPacket packet)
        {
            // check for null payload
            if (packet.PayloadData != null)
            {
                // check for "key=value" pairs
                var split = encoding.GetString(packet.PayloadData).Split('&');

                if (split.Length > 0)
                {
                    var keys = split[0].Split('=');

                    if (keys.Length > 0) return true;
                }
            }

            return false;
        }
    }

    public class HttpHeader
    {
        public enum PacketType
        {
            Request,
            Response
        }
        
        // properties
        public PacketType Type;
        public string Code = string.Empty;
        public string Path = string.Empty; // request path (GET ... HTTP)
        public string Host = string.Empty;
        public string Authorization = string.Empty;
        public string ContentType = string.Empty;
        public List<string[]> GetParams = new List<string[]>();

        // regex
        private static Regex regexCode = new Regex(@"HTTP\/1\.(0|1) (.*?) ", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexPath = new Regex(@"(GET|POST) (.*?) HTTP\/1\.(0|1)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexHost = new Regex(@"Host: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexAuth = new Regex(@"Authorization: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexType = new Regex(@"Content-Type: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);

        public HttpHeader(string header)
        {
            // parse header...
            if (header == string.Empty) return;

            // determine type
            if (header.Length > 4 && (header.Substring(0, 3) == "GET" || header.Substring(0, 4) == "POST"))
            {
                Type = PacketType.Request;
            }
            else
            {
                Type = PacketType.Response;
            }

            // get "HTTP Code"
            if (Type == PacketType.Response)
            {
                // regex match code
                var codeMatches = SimpleRegex.GetMatches(regexCode, header);
                if (codeMatches != null && codeMatches.Count > 1) Code = codeMatches[2];
            }

            // get request path
            if (Type == PacketType.Request)
            {
                // regex match path
                var pathMatches = SimpleRegex.GetMatches(regexPath, header);
                if (pathMatches != null && pathMatches.Count > 1) Path = pathMatches[2];
            }

            // get host address
            if (Type == PacketType.Request)
            {
                // regex match path
                var hostMatches = SimpleRegex.GetMatches(regexHost, header);
                if(hostMatches != null && hostMatches.Count > 1) Host = hostMatches[1];
            }

            // get authorization
            if (Type == PacketType.Request)
            {
                // regex match authorization
                var authMatches = SimpleRegex.GetMatches(regexAuth, header);
                if (authMatches != null && authMatches.Count > 1) Authorization = authMatches[1]; 
            }

            // get content type
            if (Type == PacketType.Response)
            {
                // regex match authorization
                var typeMatches = SimpleRegex.GetMatches(regexType, header);
                if (typeMatches != null && typeMatches.Count > 1) ContentType = typeMatches[1];
            }

            // get GET parameters (key=value)
            if (Type == PacketType.Request)
            {
                // split PATH
                var getLine = Path.Split('?');

                // are there any params?
                if (getLine.Length == 2)
                {
                    var getParams = getLine[1].Split('&');

                    // fill List<>
                    foreach (var param in getParams)
                    {
                        var splitParam = param.Split('=');
                        if (splitParam.Count() == 2) GetParams.Add(new string[] { splitParam[0] != null ? splitParam[0] : string.Empty, splitParam[1] != null ? splitParam[1] : string.Empty });
                    }
                }
            }
        }
    }
}
