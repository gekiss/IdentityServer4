using FluentAssertions;
using IdentityServer.UnitTests.Common;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores.Default;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace IdentityServer.UnitTests.Stores.Default
{
    public class DistributedCacheAuthorizationParametersMessageStoreTest
    {
        private MockDistributedCache _mockDistibutedCache = new MockDistributedCache();
        private DistributedCacheAuthorizationParametersMessageStore _store;

        public DistributedCacheAuthorizationParametersMessageStoreTest()
        {
            var handleGenerationService = new DefaultHandleGenerationService();
            _store = new DistributedCacheAuthorizationParametersMessageStore(_mockDistibutedCache, handleGenerationService);
        }

        [Fact]
        public async Task Store_should_remove_item_after_delete()
        {
            _mockDistibutedCache.Items.Clear();

            var message = new Message<IDictionary<string, string[]>>()
            {
                Data = new Dictionary<string, string[]>()
                {
                    { "key", [ "value" ] }
                },
            };

            var id = await _store.WriteAsync(message);
            _mockDistibutedCache.Items.Count.Should().Be(1);

            await _store.DeleteAsync(id);
            _mockDistibutedCache.Items.Count.Should().Be(0);
        }
    }
}
