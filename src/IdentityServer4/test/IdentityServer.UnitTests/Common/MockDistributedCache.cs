using Microsoft.Extensions.Caching.Distributed;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityServer.UnitTests.Common
{
    public class MockDistributedCache : IDistributedCache
    {
        public IDictionary<string, byte[]> _items = new Dictionary<string, byte[]>();

        public IDictionary<string, byte[]> Items => _items;

        public byte[] Get(string key)
        {
            if (_items.TryGetValue(key, out var value))
            {
                return value;
            }

            return null;
        }

        public Task<byte[]> GetAsync(string key, CancellationToken token = default)
        {
            if (_items.TryGetValue(key, out var value))
            {
                return Task.FromResult(value);
            }

            return Task.FromResult<byte[]>(null);
        }

        public void Refresh(string key)
        {
            
        }

        public Task RefreshAsync(string key, CancellationToken token = default)
        {
            return Task.CompletedTask;
        }

        public void Remove(string key)
        {
            _items.Remove(key);
        }

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            _items.Remove(key);
            return Task.CompletedTask;
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            _items[key] = value;
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            _items[key] = value;
            return Task.CompletedTask;
        }
    }
}
