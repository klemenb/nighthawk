using System.Collections.Generic;
using System.Text.RegularExpressions;

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
    class SimpleRegex
    {
        public static List<string> GetMatches(Regex regex, string data)
        {
            Match matches = regex.Match(data);

            var m = new List<string>();

            if (matches.Captures.Count != 0)
            {
                if (matches.Groups.Count != 0)
                {
                    foreach (Group group in matches.Groups)
                    {
                        foreach (Capture capture in group.Captures)
                        {
                            m.Add(capture.Value);
                        }
                    }
                }
                else
                {
                    foreach (Match capture in matches.Captures)
                    {
                        m.Add(capture.Value);
                    }
                }
            }

            return m;
        }
    }
}
