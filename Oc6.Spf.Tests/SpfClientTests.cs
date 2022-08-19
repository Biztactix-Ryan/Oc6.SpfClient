namespace Oc6.Spf.Tests
{
    [TestClass]
    public class SpfClientTests
    {
        [TestMethod]
        public async Task Debug()
        {
            SpfClient client = new SpfClient();
            await client.GetIpRangesAsync("21-5.dk");
        }
    }
}