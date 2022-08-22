using DnsClient;
using Oc6.Library.Net;
using System.Net;
using System.Net.Sockets;

namespace Oc6.Spf
{
    public class SpfClient : ISpfClient
    {
        private readonly LookupClient lookupClient;

        private SpfClient(params NameServer[] nameServers)
        {
            lookupClient = new LookupClient(nameServers);
        }

        public static ISpfClient Create()
            => new SpfClient(NameServer.Cloudflare,
                 NameServer.Cloudflare2,
                 NameServer.CloudflareIPv6,
                 NameServer.Cloudflare2IPv6,
                 NameServer.GooglePublicDns,
                 NameServer.GooglePublicDns2,
                 NameServer.GooglePublicDnsIPv6,
                 NameServer.GooglePublicDns2IPv6);

        public static ISpfClient Create(params NameServer[] nameServers)
            => new SpfClient(nameServers);

        public async Task<SpfResult> ValidateResultAsync(string sender, string domain, CancellationToken cancellationToken = default)
        {
            if (!IpRange.TryParseCidr(sender, out IpRange? sendingRange) || sendingRange == default)
            {
                return SpfResult.PermError;
            }

            return await ValidateResultAsync(sendingRange, domain, cancellationToken);
        }

        public async Task<SpfResult> ValidateResultAsync(IPAddress sender, string domain, CancellationToken cancellationToken = default)
        {
            if (!(sender.AddressFamily == AddressFamily.InterNetwork || sender.AddressFamily == AddressFamily.InterNetworkV6))
            {
                return SpfResult.PermError;
            }

            IpRange sendingRange = new(sender.GetAddressBytes());

            return await ValidateResultAsync(sendingRange, domain, cancellationToken);
        }

        public async Task<ExpandedSpfRecord> GetExpandedSpfRecordAsync(string domain, CancellationToken cancellationToken = default)
        {
            IDnsQueryResponse response = await lookupClient.QueryAsync(domain, QueryType.TXT, QueryClass.IN, cancellationToken);

            List<string> spfRecords = response.Answers
                .TxtRecords()
                .SelectMany(x => x.Text)
                .Where(x => x.StartsWith("v=spf1", StringComparison.Ordinal))
                .ToList();

            if (spfRecords.Count == 0)
            {
                return new(new(), SpfAllMechanism.None);
            }

            List<IpRange> ranges = new();

            SpfAllMechanism spfAllMechanism = SpfAllMechanism.Neutral;

            foreach (var spfRecord in spfRecords)
            {
                SpfAllMechanism mechanism = GetSpfAllMechanism(spfRecord);

                if (mechanism > spfAllMechanism)
                {
                    spfAllMechanism = mechanism;
                }

                ranges.AddRange(await ExpandSpfRecordAsync(spfRecord, domain, cancellationToken));
            }

            return new(ranges, spfAllMechanism);
        }

        public async Task<List<IpRange>> ExpandSpfRecordAsync(string record, string domain, CancellationToken cancellationToken)
        {
            List<IpRange> ranges = new();

            string[] parts = record.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            //skip first and last
            for (int i = 1; i < parts.Length - 1; ++i)
            {
                var part = parts[i];

                if (part.StartsWith("ip4"))
                {
                    ranges.Add(ParseIP4Record(part));
                }
                else if (part.StartsWith("ip6"))
                {
                    ranges.Add(ParseIP6Record(part));
                }
                else if (part.StartsWith("a"))
                {
                    ranges.AddRange(await ParseARecordAsync(part, domain, cancellationToken));
                }
                else if (part.StartsWith("mx"))
                {
                    ranges.AddRange(await ParseMXRecordAsync(part, domain, cancellationToken));
                }
                else if (part.StartsWith("include"))
                {
                    ranges.AddRange(await ParseIncludeRecordAsync(part, cancellationToken));
                }
                else
                {
                    throw new ArgumentException($"Invalid record [{record}]", nameof(record));
                }
            }

            return ranges;
        }

        private async Task<SpfResult> ValidateResultAsync(IpRange sendingRange, string domain, CancellationToken cancellationToken)
        {
            try
            {
                ExpandedSpfRecord expandedSpfRecord = await GetExpandedSpfRecordAsync(domain, cancellationToken);

                if (expandedSpfRecord.SpfAll == SpfAllMechanism.None)
                {
                    return SpfResult.None;
                }

                foreach (var range in expandedSpfRecord.Ranges)
                {
                    if (range.Overlap(sendingRange))
                    {
                        return SpfResult.Pass;
                    }
                }

                return expandedSpfRecord.SpfAll switch
                {
                    SpfAllMechanism.Fail => SpfResult.Fail,
                    SpfAllMechanism.Pass => SpfResult.Pass,
                    SpfAllMechanism.Neutral => SpfResult.Neutral,
                    SpfAllMechanism.SoftFail => SpfResult.SoftFail,
                    _ => SpfResult.PermError,
                };
            }
            catch (ArgumentNullException)
            {
                return SpfResult.PermError;
            }
            catch (ArgumentException)
            {
                return SpfResult.PermError;
            }
            catch (IOException)
            {
                return SpfResult.TempError;
            }
        }

        private static SpfAllMechanism GetSpfAllMechanism(string record)
            => record[^4..] switch
            {
                "+all" => SpfAllMechanism.Pass,
                "-all" => SpfAllMechanism.Fail,
                "~all" => SpfAllMechanism.SoftFail,
                "?all" => SpfAllMechanism.Neutral,
                _ => throw new ArgumentException("Invalid record", nameof(record)),
            };

        private static IpRange ParseIP4Record(string record)
            => ParseIPRecord(record);

        private static IpRange ParseIP6Record(string record)
            => ParseIPRecord(record);

        private static IpRange ParseIPRecord(string record)
        {
            if (IpRange.TryParseCidr(record[4..], out IpRange? ipRange))
            {
                if (ipRange == null)
                {
                    throw new ArgumentException($"Invalid record [{record}]", nameof(record));
                }

                return ipRange;
            }

            throw new ArgumentException($"Invalid record [{record}]", nameof(record));
        }

        private async Task<List<IpRange>> ParseARecordAsync(string record, string domain, CancellationToken cancellationToken)
        {
            int index = record.IndexOf(':');
            int slash = record.IndexOf('/');

            if (index < 0)
            {
                var records = await GetARecords(domain, cancellationToken);

                if (slash < 0)
                {
                    return records;
                }
                else
                {
                    var mask = int.Parse(record[(slash + 1)..]);

                    return records
                        .Select(x => new IpRange(x.Address, mask))
                        .ToList();
                }
            }
            else
            {
                if (slash < 0)
                {
                    return await GetARecords(record[2..], cancellationToken);
                }
                else
                {
                    var mask = int.Parse(record[(slash + 1)..]);

                    return (await GetARecords(record[2..slash], cancellationToken))
                        .Select(x => new IpRange(x.Address, mask))
                        .ToList();
                }
            }
        }

        private async Task<List<IpRange>> ParseMXRecordAsync(string record, string domain, CancellationToken cancellationToken)
        {
            int index = record.IndexOf(':');
            int slash = record.IndexOf('/');

            if (index < 0)
            {
                var records = await GetMXRecords(domain, cancellationToken);

                if (slash < 0)
                {
                    return records;
                }
                else
                {
                    var mask = int.Parse(record[(slash + 1)..]);

                    return records
                        .Select(x => new IpRange(x.Address, mask))
                        .ToList();
                }
            }
            else
            {
                if (slash < 0)
                {
                    return await GetMXRecords(record[3..], cancellationToken);
                }
                else
                {
                    var mask = int.Parse(record[(slash + 1)..]);

                    return (await GetMXRecords(record[3..slash], cancellationToken))
                        .Select(x => new IpRange(x.Address, mask))
                        .ToList();
                }
            }
        }

        private async Task<List<IpRange>> GetARecords(string domain, CancellationToken cancellationToken)
        {
            List<IpRange> records = new();

            IDnsQueryResponse response = await lookupClient.QueryAsync(domain, QueryType.A, QueryClass.IN, cancellationToken);

            foreach (var record in response.Answers.ARecords())
            {
                records.Add(new IpRange(record.Address.GetAddressBytes()));
            }

            response = await lookupClient.QueryAsync(domain, QueryType.AAAA, QueryClass.IN, cancellationToken);

            foreach (var record in response.Answers.AaaaRecords())
            {
                records.Add(new IpRange(record.Address.GetAddressBytes()));
            }

            return records;
        }

        private async Task<List<IpRange>> GetMXRecords(string domain, CancellationToken cancellationToken)
        {
            List<IpRange> records = new();

            IDnsQueryResponse response = await lookupClient.QueryAsync(domain, QueryType.MX, QueryClass.IN, cancellationToken);

            foreach (var record in response.Answers.ARecords())
            {
                records.Add(new IpRange(record.Address.GetAddressBytes()));
            }

            return records;
        }

        private async Task<List<IpRange>> ParseIncludeRecordAsync(string record, CancellationToken cancellationToken)
        {
            int index = record.IndexOf(':');

            string domain = record[(index + 1)..];

            return (await GetExpandedSpfRecordAsync(domain, cancellationToken)).Ranges;
        }
    }
}