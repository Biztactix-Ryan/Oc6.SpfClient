using System.Net;

namespace Oc6.Spf.Tests
{
    [TestClass]
    public class SpfClientTests
    {
        [TestMethod]
        public async Task ValidateResultAsync_FromIPAddress_Pass()
        {
            ISpfClient client = SpfClient.Create();
            Assert.AreEqual(SpfResult.Pass, await client.ValidateResultAsync(new IPAddress(new byte[] { 52, 58, 128, 109 }), "21-5.dk"));
        }

        [TestMethod]
        public async Task ValidateResultAsync_FromString_Pass()
        {
            ISpfClient client = SpfClient.Create();
            Assert.AreEqual(SpfResult.Pass, await client.ValidateResultAsync("52.58.128.109", "21-5.dk"));
        }

        [TestMethod]
        public async Task ValidateResultAsync_FromString_Fail()
        {
            ISpfClient client = SpfClient.Create();
            Assert.AreEqual(SpfResult.Fail, await client.ValidateResultAsync("1.1.1.1", "21-5.dk"));
        }

        [TestMethod]
        public async Task ValidateResultAsync_FromString_Empty_Should_Fails()
        {
            ISpfClient client = SpfClient.Create();
            Assert.AreEqual(SpfResult.Fail, await client.ValidateResultAsync("1.1.1.1", "oc6.dk"));
        }
    }
}