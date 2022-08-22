using Oc6.Library.Net;
using System.Net;

namespace Oc6.Spf
{
    public interface ISpfClient
    {
        Task<ExpandedSpfRecord> GetExpandedSpfRecordAsync(string domain, CancellationToken cancellationToken = default);
        Task<List<IpRange>> ExpandSpfRecordAsync(string record, string domain, CancellationToken cancellationToken);
        Task<SpfResult> ValidateResultAsync(IPAddress sender, string domain, CancellationToken cancellationToken = default);
        Task<SpfResult> ValidateResultAsync(string sender, string domain, CancellationToken cancellationToken = default);
    }
}