import { DnsClient } from '../src/index';

describe('Nameserver Cache Integration Tests', () => {
  jest.setTimeout(60000);

  test('should cache nameserver hostname resolutions', async () => {
    const client = new DnsClient();

    // use a hostname-based nameserver (e.g., one.google.com) to trigger nameserverCache usage
    // first query will resolve the hostname to IP and cache it
    const initialNameserverCacheSize = client.nsCache.size();
    const answers1 = await client.query({
      query: 'example.com',
      types: ['A'],
      server: 'one.one.one.one', // cloudflare DNS hostname
    });

    expect(answers1).toBeDefined();
    expect(answers1.length).toBeGreaterThan(0);

    // second query with same hostname should use cached IP
    const answers2 = await client.query({
      query: 'google.com',
      types: ['A'],
      server: 'one.one.one.one', // same hostname
    });

    expect(answers2).toBeDefined();
    expect(answers2.length).toBeGreaterThan(0);
    // nameserverCache should have cached the hostname resolution
    expect(client.nsCache.size()).toBeGreaterThan(initialNameserverCacheSize);
  });

  test('should cache multiple nameserver hostnames', async () => {
    const client = new DnsClient();

    // query with different hostname-based nameservers
    await client.query({
      query: 'example.com',
      types: ['A'],
      server: 'one.one.one.one', // cloudflare DNS hostname
    });
    await client.query({
      query: 'google.com',
      types: ['A'],
      server: 'dns.google', // google DNS hostname
    });

    // nameserverCache should have entries for both hostnames
    expect(client.nsCache.size()).toBeGreaterThanOrEqual(2);
  });

  test('should use cached hostname resolution for subsequent queries', async () => {
    const client = new DnsClient();

    const hostname = 'one.one.one.one';

    // first query resolves hostname
    await client.query({ query: 'example.com', types: ['A'], server: hostname });
    const firstSize = client.nsCache.size();

    // second query should use cached resolution
    await client.query({ query: 'google.com', types: ['A'], server: hostname });

    // cache size should not increase for same hostname
    expect(client.nsCache.size()).toBe(firstSize);
  });

  test('should handle nameserverCache expiration', async () => {
    const client = new DnsClient();

    // query with hostname to populate cache
    await client.query({
      query: 'example.com',
      types: ['A'],
      server: 'one.one.one.one',
    });

    expect(client.nsCache.size()).toBeGreaterThan(0);

    // clear cache manually to simulate expiration
    client.nsCache.clear();
    expect(client.nsCache.size()).toBe(0);

    // next query should repopulate cache
    await client.query({
      query: 'google.com',
      types: ['A'],
      server: 'one.one.one.one',
    });
    expect(client.nsCache.size()).toBeGreaterThan(0);
  });

  test('should not cache IP addresses (already resolved)', async () => {
    const client = new DnsClient();

    const initialSize = client.nsCache.size();

    // query with IP address (not hostname) - should not use nameserverCache
    await client.query({
      query: 'example.com',
      types: ['A'],
      server: '1.1.1.1', // IP address, not hostname
    });

    // nameserverCache size should not change when using IP addresses
    expect(client.nsCache.size()).toBe(initialSize);
  });

  test('should handle invalid hostnames gracefully', async () => {
    const client = new DnsClient();

    // query with invalid hostname - should not cache failures
    const invalidHostname = 'invalid-dns-server-12345.example.invalid';
    const initialSize = client.nsCache.size();

    try {
      await client.query({
        query: 'example.com',
        types: ['A'],
        server: invalidHostname,
      });
    } catch {
      // expected to fail
    }

    // nameserverCache should not cache failed resolutions
    expect(client.nsCache.size()).toBe(initialSize);
  });
});
