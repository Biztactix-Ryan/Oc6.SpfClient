using System.Net;

namespace Oc6.Spf.Tests
{
    [TestClass]
    public class SpfClientTests
    {
        [TestMethod]
        public async Task ValidateResultAsync_Pass()
        {
            SpfClient client = new();
            Assert.AreEqual(SpfResult.Pass, await client.ValidateResultAsync(new IPAddress(new byte[] { 52, 58, 128, 109 }), "21-5.dk"));
        }
    }
}