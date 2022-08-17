using DnsClient;
using System.Net;

namespace Oc6.Spf
{
    public class SpfClient
    {
        private readonly LookupClient dnsClient;

        private SpfClient(params NameServer[] nameServers)
        {
            dnsClient = new LookupClient(nameServers);
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

        public SpfClient(params byte[][] addresses)
            : this(addresses.Select(x => FromBytes(x)).ToArray())
        {

        }

        public SpfClient(params string[] ips)
            : this(ips.Select(x => FromIp(x)).ToArray())
        {

        }

        public async Task<SpfRecord> GetSpfRecordAsync(string domain)
        {

        }

        private static NameServer FromBytes(byte[] ip)
            => new(new IPAddress(ip));

        private static NameServer FromIp(string ip)
            => new(IPAddress.Parse(ip));
    }
}