using System.Collections.Generic;
using System.Linq;
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
    /* Basic HTTP parser */
    public class HttpPacket
    {
        public HttpHeader Header;
        public List<string[]> PostParams = new List<string[]>();

        private static Regex regexIsHTTP = new Regex(@"HTTP\/1\.", RegexOptions.Compiled | RegexOptions.Singleline);
        
        private static UTF8Encoding encoding = new UTF8Encoding();

        public HttpPacket(TcpPacket packet)
        {
            var data = encoding.GetString(packet.PayloadData);

            // split header & content
            string[] parts = Regex.Split(data, "\r\n\r\n");

            Header = new HttpHeader(parts[0]);

            var postParts = HasPOST(packet);

            // get POST parameters (key=value)
            if (postParts || parts[0].Substring(0, 4) == "POST")
            {
                // split params
                if (postParts || parts.Length > 1)
                {
                    var postLine = data;

                    // if we have headers in the packet
                    if (parts.Length > 1)
                    {
                        postLine = parts[1];
                    }

                    var postParams = postLine.Split('&');

                    if (postParams.Length > 1)
                    {
                        foreach (var param in postParams)
                        {
                            if (param.Contains('='))
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
        }

        // check if the packet is HTTP packet
        public static bool IsHTTP(TcpPacket packet)
        {
            if (packet.PayloadData != null)
            {
                if (SimpleRegex.GetMatches(regexIsHTTP, encoding.GetString(packet.PayloadData)).Count > 0) return true;
            }

            return false;
        }

        // check if packet might contain traces of POST data (packet to process)
        public static bool HasPOST(TcpPacket packet)
        {
            if (packet.PayloadData != null)
            {
                var data = encoding.GetString(packet.PayloadData);

                // check for possible full GET/POST requests
                if (data.Length > 3 && (data.Substring(0, 4) == "POST" || data.Substring(0, 3) == "GET")) return false;

                // get rid of possible left-over headers
                if (data.Contains("\r\n\r\n"))
                {
                    var parts = Regex.Split(data, "\r\n\r\n");
                    if(parts.Length > 1) data = parts[1];
                }

                // check for "key=value" pairs
                var split = data.Split('&');

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

        public enum RequestType
        {
            POST,
            GET,
            None
        }
        
        public PacketType Type;
        public RequestType ReqType = RequestType.None;
        public string Code = string.Empty;
        public string Path = string.Empty; // request path (GET ... HTTP)
        public string Host = string.Empty;
        public string Authorization = string.Empty;
        public string ContentType = string.Empty;
        public List<string[]> GetParams = new List<string[]>();

        private static Regex regexCode = new Regex(@"HTTP\/1\.(0|1) (.*?) ", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexPath = new Regex(@"(GET|POST) (.*?) HTTP\/1\.(0|1)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexHost = new Regex(@"Host: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexAuth = new Regex(@"Authorization: (.*?)(\r\n|$)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static Regex regexType = new Regex(@"Content-Type: (.*?)\r\n", RegexOptions.Compiled | RegexOptions.Singleline);

        public HttpHeader(string header)
        {
            if (header == string.Empty) return;

            // determine type (GET/POST)
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
                var codeMatches = SimpleRegex.GetMatches(regexCode, header);
                if (codeMatches != null && codeMatches.Count > 1) Code = codeMatches[2];
            }

            // get request path, request type
            if (Type == PacketType.Request)
            {
                var pathMatches = SimpleRegex.GetMatches(regexPath, header);
                if (pathMatches != null && pathMatches.Count > 1)
                {
                    if (pathMatches[1] == "GET")
                    {
                        ReqType = RequestType.GET;
                    }
                    else if (pathMatches[1] == "POST")
                    {
                        ReqType = RequestType.POST;
                    }

                    Path = pathMatches[2];
                }
            }

            // get host address
            if (Type == PacketType.Request)
            {
                var hostMatches = SimpleRegex.GetMatches(regexHost, header);
                if(hostMatches != null && hostMatches.Count > 1) Host = hostMatches[1];
            }

            // get authorization
            if (Type == PacketType.Request)
            {
                var authMatches = SimpleRegex.GetMatches(regexAuth, header);
                if (authMatches != null && authMatches.Count > 1) Authorization = authMatches[1]; 
            }

            // get content type
            if (Type == PacketType.Response)
            {
                var typeMatches = SimpleRegex.GetMatches(regexType, header);
                if (typeMatches != null && typeMatches.Count > 1) ContentType = typeMatches[1];
            }

            // get GET parameters (key=value)
            if (Type == PacketType.Request)
            {
                var getLine = Path.Split('?');

                // are there any params?
                if (getLine.Length == 2)
                {
                    var getParams = getLine[1].Split('&');

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
