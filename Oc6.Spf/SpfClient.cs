using DnsClient;
using Oc6.Library.Net;
using System.Net;

namespace Oc6.Spf
{
    public class SpfClient
    {
        private readonly LookupClient lookupClient;

        private SpfClient(params NameServer[] nameServers)
        {
            lookupClient = new LookupClient(nameServers);
        }

        public SpfClient()
            : this(NameServer.Cloudflare,
                 NameServer.Cloudflare2,
                 NameServer.CloudflareIPv6,
                 NameServer.Cloudflare2IPv6,
                 NameServer.GooglePublicDns,
                 NameServer.GooglePublicDns2,
                 NameServer.GooglePublicDnsIPv6,
                 NameServer.GooglePublicDns2IPv6)
        {

        }

        public async Task<ExpandedSpfRecord> GetIpRangesAsync(string domain, CancellationToken cancellationToken = default)
        {
            IDnsQueryResponse? response = await lookupClient.QueryAsync(domain, QueryType.TXT, QueryClass.IN, cancellationToken);

            if (response == null)
            {
                throw new Exception("No response received");
            }

            List<string> spfRecords = response.Answers
                .TxtRecords()
                .SelectMany(x => x.Text)
                .Where(x => x.StartsWith("v=spf1", StringComparison.Ordinal))
                .ToList();

            List<IpRange> ranges = new();

            foreach (var spfRecord in spfRecords)
            {
                ranges.AddRange(await ParseSpfRecordAsync(spfRecord));
            }

            return new ExpandedSpfRecord(ranges, SpfAllMechanism.Neutral);
        }

        private SpfAllMechanism GetSpfAllMechanism(string record)
            => record[^4..] switch
            {
                "+all" => SpfAllMechanism.Pass,
                "-all" => SpfAllMechanism.Fail,
                "~all" => SpfAllMechanism.SoftFail,
                "?all" => SpfAllMechanism.Neutral,
                _ => throw new ArgumentException("Invalid record", nameof(record)),
            };

        public async Task<List<IpRange>> ParseSpfRecordAsync(string record)
        {
            /*
             * v=spf1
             * ipv4:127.0.0.1
             * ipv4:127.0.0.1/32
             * ipv6:::1
             * ipv6:::1/128
             * a
             * a/16
             * a:example.com
             * a:example.com/16
             * mx
             * mx/16
             * mx:example.com
             * mx:example.com/16
             * include:example.com
             * -all"
             */

            List<IpRange> ranges = new();

            string[] parts = record.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            //skip first and last
            for (int i = 1; i < parts.Length - 1; ++i)
            {
                var part = parts[i];

                if (part.StartsWith("ipv4"))
                {
                    ranges.Add(ParseIPv4RecordAsync(part));
                }
                else if (part.StartsWith("ipv6"))
                {
                    ranges.Add(ParseIPv6RecordAsync(part));
                }
                else if (part.StartsWith("a"))
                {
                    ranges.AddRange(await ParseARecordAsync(part));
                }
                else if (part.StartsWith("mx"))
                {
                    ranges.AddRange(await ParseMXRecordAsync(part));
                }
                else if (part.StartsWith("include"))
                {
                    ranges.AddRange(await ParseIncludeRecordAsync(part));
                }
                else
                {
                    throw new ArgumentException($"Invalid record [{record}]", nameof(record));
                }
            }

            return ranges;
        }

        private IpRange ParseIPv4RecordAsync(string record)
        {
            return ParseIPRecord(record);
        }

        private IpRange ParseIPv6RecordAsync(string record)
        {
            return ParseIPRecord(record);
        }

        private static IpRange ParseIPRecord(string record)
        {
            //ipv4
            if (IpRange.TryParseCidr(record[5..], out IpRange? ipRange))
            {
                if (ipRange == null)
                {
                    throw new ArgumentException($"Invalid record [{record}]", nameof(record));
                }

                return ipRange;
            }

            throw new ArgumentException($"Invalid record [{record}]", nameof(record));
        }

        private async Task<List<IpRange>> ParseARecordAsync(string record)
        {
            throw new NotImplementedException();
        }

        private async Task<List<IpRange>> ParseMXRecordAsync(string record)
        {
            throw new NotImplementedException();
        }

        private async Task<List<IpRange>> ParseIncludeRecordAsync(string record)
        {
            throw new NotImplementedException();
        }
    }
}