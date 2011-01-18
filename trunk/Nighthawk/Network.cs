using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;

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

        // get START/END ip
        public static long[] MaskToStartEnd(string ip, string subnetMask)
        {
            IPAddress ipAddr = IPAddress.Parse(ip);
            int bits = MaskToCIDR(subnetMask);

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
        public static string LongToIP(long address)
        {
            return System.Net.IPAddress.Parse(address.ToString()).ToString();
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
    }
}
