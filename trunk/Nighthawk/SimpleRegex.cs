using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Nighthawk
{
    /**
     * Simplification of C# regex matching
     */
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
