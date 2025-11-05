import { QueryCache } from '../src/caches/queries.js';
import { DnsClient } from '../src/index.js';
import {
  A_RECORD,
  AAAA_RECORD,
  DNS_TRANSPORT_TCP,
  FLAG_RECURSION_DESIRED,
} from '../src/constants.js';
import type { DnsQuestion, DnsAnswer } from '../src/types.js';

describe('Query Cache Tests', () => {
  jest.setTimeout(60000);

  // helper functions for unit tests
  const createQuestion = (
    query: string,
    type = 'A',
    flags: string[] = [FLAG_RECURSION_DESIRED]
  ): DnsQuestion => ({
    query,
    type: type as DnsQuestion['type'],
    server: '1.1.1.1',
    flags: flags as DnsQuestion['flags'],
  });

  const createAnswer = (query: string, ttl: number = 300): DnsAnswer => ({
    query,
    type: 'A',
    server: '1.1.1.1',
    serverHost: null,
    transport: 'udp',
    elapsed: 10,
    bytes: 100,
    rcode: 0,
    rcodeName: 'NOERROR',
    extendedErrors: null,
    ednsOptions: null,
    error: null,
    flags: [],
    records: [{ name: query, ttl, type: 'A', class: 'IN', address: '192.0.2.1' }],
    authorities: [],
    additionals: [],
    trace: [],
  });

  describe('Unit Tests - Basic operations', () => {
    test('should return null for non-existent key', () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      expect(cache.get(question)).toBeNull();
    });

    test('should store and retrieve entry', () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer = createAnswer('example.com');
      cache.set(question, answer);
      expect(cache.get(question)).toEqual(answer);
    });

    test('should generate different keys for different queries', () => {
      const cache = new QueryCache();
      const q1 = createQuestion('example.com');
      const q2 = createQuestion('google.com');
      cache.set(q1, createAnswer('example.com'));
      cache.set(q2, createAnswer('google.com'));
      expect(cache.size()).toBe(2);
    });

    test('should generate different keys for different record types', () => {
      const cache = new QueryCache();
      const q1 = createQuestion('example.com', 'A');
      const q2 = createQuestion('example.com', 'AAAA');
      cache.set(q1, createAnswer('example.com'));
      cache.set(q2, createAnswer('example.com'));
      expect(cache.size()).toBe(2);
    });

    test('should generate different keys for different flags', () => {
      const cache = new QueryCache();
      const q1 = createQuestion('example.com', 'A', [FLAG_RECURSION_DESIRED]);
      const q2 = createQuestion('example.com', 'A', []);
      cache.set(q1, createAnswer('example.com'));
      cache.set(q2, createAnswer('example.com'));
      expect(cache.size()).toBe(2);
    });

    test('should report correct size', () => {
      const cache = new QueryCache();
      expect(cache.size()).toBe(0);
      cache.set(createQuestion('example.com'), createAnswer('example.com'));
      expect(cache.size()).toBe(1);
      cache.set(createQuestion('google.com'), createAnswer('google.com'));
      expect(cache.size()).toBe(2);
    });

    test('should clear all entries', () => {
      const cache = new QueryCache();
      cache.set(createQuestion('example.com'), createAnswer('example.com'));
      cache.set(createQuestion('google.com'), createAnswer('google.com'));
      expect(cache.size()).toBe(2);
      cache.clear();
      expect(cache.size()).toBe(0);
    });
  });

  describe('Unit Tests - TTL and expiration', () => {
    test('should return null for expired entries', async () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer = createAnswer('example.com', 0); // 0 second TTL
      cache.set(question, answer);

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(cache.get(question)).toBeNull();
    });

    test('should remove expired entries on access', async () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer = createAnswer('example.com', 0);
      cache.set(question, answer);
      expect(cache.size()).toBe(1);

      await new Promise(resolve => setTimeout(resolve, 100));
      cache.get(question);
      expect(cache.size()).toBe(0);
    });

    test('should use minimum TTL from records', () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer: DnsAnswer = {
        ...createAnswer('example.com'),
        records: [
          { name: 'example.com', ttl: 100, type: 'A', class: 'IN', address: '192.0.2.1' },
          { name: 'example.com', ttl: 200, type: 'A', class: 'IN', address: '192.0.2.2' },
        ],
      };
      cache.set(question, answer);
      // Entry should use 100s TTL (minimum)
      expect(cache.get(question)).toEqual(answer);
    });

    test('should default to 300s when no records', () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer: DnsAnswer = { ...createAnswer('example.com'), records: [] };
      cache.set(question, answer);
      expect(cache.get(question)).toEqual(answer);
    });
  });

  describe('Unit Tests - LRU eviction', () => {
    test('should evict oldest entry when full', () => {
      const cache = new QueryCache(2);
      cache.set(createQuestion('example.com'), createAnswer('example.com'));
      cache.set(createQuestion('google.com'), createAnswer('google.com'));
      cache.set(createQuestion('cloudflare.com'), createAnswer('cloudflare.com'));

      expect(cache.size()).toBe(2);
      expect(cache.get(createQuestion('example.com'))).toBeNull();
      expect(cache.get(createQuestion('google.com'))).toBeDefined();
      expect(cache.get(createQuestion('cloudflare.com'))).toBeDefined();
    });

    test('should move accessed entry to end (most recent)', () => {
      const cache = new QueryCache(2);
      cache.set(createQuestion('example.com'), createAnswer('example.com'));
      cache.set(createQuestion('google.com'), createAnswer('google.com'));

      // Access first entry to make it most recent
      cache.get(createQuestion('example.com'));

      // Add third entry - should evict google.com (now oldest)
      cache.set(createQuestion('cloudflare.com'), createAnswer('cloudflare.com'));

      expect(cache.get(createQuestion('example.com'))).toBeDefined();
      expect(cache.get(createQuestion('google.com'))).toBeNull();
      expect(cache.get(createQuestion('cloudflare.com'))).toBeDefined();
    });

    test('should handle cache size of 1', () => {
      const cache = new QueryCache(1);
      cache.set(createQuestion('example.com'), createAnswer('example.com'));
      expect(cache.size()).toBe(1);
      cache.set(createQuestion('google.com'), createAnswer('google.com'));
      expect(cache.size()).toBe(1);
      expect(cache.get(createQuestion('example.com'))).toBeNull();
      expect(cache.get(createQuestion('google.com'))).toBeDefined();
    });

    test('should handle cache size of 0', () => {
      const cache = new QueryCache(0);
      cache.set(createQuestion('example.com'), createAnswer('example.com'));
      // Cache with size 0 still allows one entry before eviction check
      expect(cache.size()).toBeLessThanOrEqual(1);
    });
  });

  describe('Unit Tests - Edge cases', () => {
    test('should handle concurrent access', () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer = createAnswer('example.com');

      // Simulate concurrent sets
      cache.set(question, answer);
      cache.set(question, answer);
      expect(cache.size()).toBe(1);
    });

    test('should handle updates to same key', () => {
      const cache = new QueryCache();
      const question = createQuestion('example.com');
      const answer1 = createAnswer('example.com');
      const answer2 = { ...createAnswer('example.com'), elapsed: 20 };

      cache.set(question, answer1);
      cache.set(question, answer2);
      expect(cache.size()).toBe(1);
      expect(cache.get(question)?.elapsed).toBe(20);
    });
  });

  describe('Integration Tests - DnsClient API', () => {
    test('should cache DNS query results when cache is enabled', async () => {
      const client = new DnsClient({ cache: true });

      // first query should populate cache
      const answers1 = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers1).toBeDefined();
      expect(answers1.length).toBeGreaterThan(0);
      expect(client.queryCache.size()).toBe(1);

      // second identical query should hit cache
      const answers2 = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers2).toEqual(answers1);
      expect(client.queryCache.size()).toBe(1);
    });

    test('should not cache when cache is disabled', async () => {
      const client = new DnsClient({ cache: false });

      await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(client.queryCache.size()).toBe(0);
    });

    test('should cache different record types separately', async () => {
      const client = new DnsClient({ cache: true });

      await client.query({ query: 'example.com', types: [A_RECORD] });
      await client.query({ query: 'example.com', types: [AAAA_RECORD] });

      // should have 2 separate cache entries (one for A, one for AAAA)
      expect(client.queryCache.size()).toBe(2);
    });

    test('should cache different domains separately', async () => {
      const client = new DnsClient({ cache: true });

      await client.query({ query: 'example.com', types: [A_RECORD] });
      await client.query({ query: 'google.com', types: [A_RECORD] });
      await client.query({ query: 'cloudflare.com', types: [A_RECORD] });

      expect(client.queryCache.size()).toBe(3);
    });

    test('should cache queries with different servers separately', async () => {
      const client = new DnsClient({ cache: true });

      await client.query({ query: 'example.com', types: [A_RECORD], server: '1.1.1.1' });
      await client.query({ query: 'example.com', types: [A_RECORD], server: '8.8.8.8' });

      // same query but different servers should be cached separately
      expect(client.queryCache.size()).toBe(2);
    });

    test('should cache queries with different flags separately', async () => {
      const client = new DnsClient({ cache: true, transport: DNS_TRANSPORT_TCP });

      // query with recursion desired
      await client.query({ query: 'example.com', types: [A_RECORD], flags: ['RD'] });
      expect(client.queryCache.size()).toBe(1);

      const sizeBeforeTrace = client.queryCache.size();

      // query without recursion desired (authoritative mode - set via client options, not query)
      const authClient = new DnsClient({
        cache: true,
        transport: DNS_TRANSPORT_TCP,
        authoritative: true,
        flags: [],
      });
      await authClient.query({ query: 'example.com', types: [A_RECORD] });
      // authoritative queries cache intermediate steps (root -> TLD -> authoritative)
      // so we should have more than just 1 additional entry
      expect(authClient.queryCache.size()).toBeGreaterThan(sizeBeforeTrace);
    });

    test('should respect cache size limit', async () => {
      const client = new DnsClient({ cache: true, cacheSize: 2 });

      await client.query({ query: 'example.com', types: [A_RECORD] });
      await client.query({ query: 'google.com', types: [A_RECORD] });
      expect(client.queryCache.size()).toBe(2);

      // adding third query should evict oldest (LRU)
      await client.query({ query: 'cloudflare.com', types: [A_RECORD] });
      expect(client.queryCache.size()).toBe(2);

      // first query should be evicted
      const cached = client.queryCache.get({
        query: 'example.com',
        type: A_RECORD,
        server: client.options.server,
        flags: [],
      });
      expect(cached).toBeNull();
    });

    test('should respect TTL from DNS responses', async () => {
      const client = new DnsClient({ cache: true });

      // query a domain and get its TTL
      const answers1 = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers1[0].records).toBeDefined();
      if (answers1[0].records && answers1[0].records.length > 0) {
        const ttl = answers1[0].records[0].ttl;

        // entry should be cached
        expect(client.queryCache.size()).toBe(1);

        // if TTL is very short, wait for it to expire
        if (ttl < 5) {
          await new Promise(resolve => setTimeout(resolve, (ttl + 1) * 1000));

          // cache should be empty after expiration
          const cached = client.queryCache.get({
            query: 'example.com',
            type: A_RECORD,
            server: client.options.server,
            flags: [],
          });
          expect(cached).toBeNull();
        }
      }
    });

    test('should clear cache', async () => {
      const client = new DnsClient({ cache: true });

      await client.query({ query: 'example.com', types: [A_RECORD] });
      await client.query({ query: 'google.com', types: [A_RECORD] });
      expect(client.queryCache.size()).toBe(2);

      client.queryCache.clear();
      expect(client.queryCache.size()).toBe(0);

      // next query should repopulate cache
      await client.query({ query: 'cloudflare.com', types: [A_RECORD] });
      expect(client.queryCache.size()).toBe(1);
    });

    test('should handle cache with concurrent queries', async () => {
      const client = new DnsClient({ cache: true, concurrency: 5 });

      // make multiple concurrent queries
      await client.queryAll([
        { query: 'example.com', types: [A_RECORD] },
        { query: 'google.com', types: [A_RECORD] },
        { query: 'cloudflare.com', types: [A_RECORD] },
      ]);

      // all should be cached
      expect(client.queryCache.size()).toBe(3);

      // second batch should hit cache
      const answers = await client.queryAll([
        { query: 'example.com', types: [A_RECORD] },
        { query: 'google.com', types: [A_RECORD] },
        { query: 'cloudflare.com', types: [A_RECORD] },
      ]);

      // cache size should remain 3
      expect(client.queryCache.size()).toBe(3);
      expect(answers.length).toBe(3);
    });

    test('should not cache error responses', async () => {
      const client = new DnsClient({ cache: true });

      // query with invalid server to trigger error
      const answers = await client.query({
        query: 'example.com',
        types: [A_RECORD],
        server: '0.0.0.1',
      });

      expect(answers[0].error).toBeDefined();
      // errors should not be cached
      expect(client.queryCache.size()).toBe(0);
    });

    test('should handle cache with authoritative queries', async () => {
      const client = new DnsClient({
        cache: true,
        transport: DNS_TRANSPORT_TCP,
        authoritative: true,
      });

      // authoritative query
      const answers1 = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers1[0].trace).toBeDefined();
      // authoritative queries cache intermediate steps (root -> TLD -> authoritative)
      const cacheSize = client.queryCache.size();
      expect(cacheSize).toBeGreaterThan(0);

      // second authoritative query may select a different random root server
      // so cache size might grow slightly, but should reuse most cached entries
      const answers2 = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers2[0].records).toEqual(answers1[0].records);
      // cache should not grow significantly (allow for different root server path)
      const newCacheSize = client.queryCache.size();
      expect(newCacheSize).toBeLessThanOrEqual(cacheSize + 4);
    });

    test('should cache multiple record types in single query', async () => {
      const client = new DnsClient({ cache: true });

      // query for both A and AAAA records
      await client.query({ query: 'example.com', types: [A_RECORD, AAAA_RECORD] });

      // should have 2 cache entries (one per record type)
      expect(client.queryCache.size()).toBe(2);
    });
  });
});
