using Oc6.Library.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Oc6.Spf
{
    public record ExpandedSpfRecord(List<IpRange> Ranges, SpfAllMechanism SpfAll);
}
