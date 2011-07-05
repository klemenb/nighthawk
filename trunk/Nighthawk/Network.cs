using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace Nighthawk
{
    /* Some helper functions - mainly from "http://stackoverflow.com/" */
    class Network
    {
        // convert subnet mask to CIDR notation
        public static int MaskToCIDR(string subnetMask)
        {
            IPAddress subnetAddress = IPAddress.Parse(subnetMask);

            byte[] ipParts = subnetAddress.GetAddressBytes();

            uint subnet = 16777216 * Convert.ToUInt32(ipParts[0]) + 65536 * Convert.ToUInt32(ipParts[1]) + 256 * Convert.ToUInt32(ipParts[2]) + Convert.ToUInt32(ipParts[3]);
            uint mask = 0x80000000;
            uint subnetConsecutiveOnes = 0;

            for (int i = 0; i < 32; i++)
            {
                if (!(mask & subnet).Equals(mask)) break;

                subnetConsecutiveOnes++;
                mask = mask >> 1;
            }

            return (int)subnetConsecutiveOnes;
        }

        // get starting IP from subnet mask
        public static long[] MaskToStartEnd(string ip, string subnetMask)
        {
            return MaskToStartEnd(ip, MaskToCIDR(subnetMask));
        }

        // get ending IP from subnet mask
        public static long[] MaskToStartEnd(string ip, int bits)
        {
            IPAddress ipAddr = IPAddress.Parse(ip);

            uint mask = ~(uint.MaxValue >> bits);

            byte[] ipBytes = ipAddr.GetAddressBytes();
            byte[] maskBytes = BitConverter.GetBytes(mask).Reverse().ToArray();

            byte[] startIPBytes = new byte[ipBytes.Length];
            byte[] endIPBytes = new byte[ipBytes.Length];

            for (int i = 0; i < ipBytes.Length; i++)
            {
                startIPBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
                endIPBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
            }

            IPAddress startIP = new IPAddress(startIPBytes);
            IPAddress endIP = new IPAddress(endIPBytes);

            return new long[] { (IPToLong(startIP.ToString()) + 1), (IPToLong(endIP.ToString()) - 1) }; // +1 and -1 to filter out network and broadcast
        }

        // IP to long
        public static long IPToLong(string addr)
        {
            string[] ipBytes;
            double num = 0;

            if (!string.IsNullOrEmpty(addr))
                {
                    ipBytes = addr.Split('.');
                for (int i = ipBytes.Length - 1; i >= 0; i--)
                {
                    num += ((int.Parse(ipBytes[i]) % 256) * Math.Pow(256, (3 - i)));
                }
            }

            return (long)num;
        }

        // long to IP
        public static IPAddress LongToIP(long address)
        {
            return IPAddress.Parse(address.ToString());
        }

        // convert MAC to friendly MAC (with :)
        public static string FriendlyPhysicalAddress(PhysicalAddress mac)
        {
            var macString = mac.ToString();
            var output = string.Empty;

            for (int i = 0; i < macString.Length; i++)
            {
                if (i % 2 == 0 && i > 0)
                {
                    output += ":" + macString[i];
                }
                else
                {
                    output += macString[i];
                }
            }

            return output;
        }

        // convert hexadecimal to bytes
        public static byte[] HexToByte(string hex)
        {
            hex = hex.Replace(" ", "");

            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];

            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        // convert ipv6 to it's full hexadecimal form
        public static string IPv6ToFullHex(string ipv6)
        {
            return BitConverter.ToString(IPAddress.Parse(ipv6).GetAddressBytes()).Replace("-", "").ToLower();
        }

        // check for valid IPv6 /64 prefix
        public static bool PrefixValid(string prefix)
        {
            var regex = new Regex("^([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4}::)$");

            return regex.IsMatch(prefix);
        }

        // get /64 prefix from IPv6 address
        public static string GetPrefixFromIP(string ip)
        {
            var parts = ip.Split(':');

            return parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + parts[3] + "::";
        }

        // get IPv6 pseudo-header (adapted from: http://www.winsocketdotnetworkprogramming.com/clientserversocketnetworkcommunication8f_3.html)
        public static byte[] GetPseudoHeader(IPAddress sourceIP, IPAddress destinationIP, int icmpv6Length, int nextHeader)
        {
            byte[] pseudoHeader, byteValue;
            int offset = 0, payLoadLength;
            
            // now build the pseudo header
            pseudoHeader = new byte[40];

            byteValue = sourceIP.GetAddressBytes();
            Array.Copy(byteValue, 0, pseudoHeader, offset, byteValue.Length);
            offset += byteValue.Length;

            byteValue = destinationIP.GetAddressBytes();
            Array.Copy(byteValue, 0, pseudoHeader, offset, byteValue.Length);
            offset += byteValue.Length;

            // Packet total length
            payLoadLength = IPAddress.HostToNetworkOrder(4 + icmpv6Length);

            byteValue = BitConverter.GetBytes(payLoadLength);
            Array.Copy(byteValue, 0, pseudoHeader, offset, byteValue.Length);
            offset += byteValue.Length;

            // 3 bytes of zero padding
            pseudoHeader[offset++] = (byte)0;
            pseudoHeader[offset++] = (byte)0;
            pseudoHeader[offset++] = (byte)0;
            pseudoHeader[offset++] = (byte)nextHeader;

            return pseudoHeader;
        }
    }
}
