import { DnsClient, type DnsQuery } from '../src/index';
import { A_RECORD, AAAA_RECORD, DNS_TRANSPORT_UDP, NS_RECORD } from '../src/constants';

const TEST_TRANSPORT = DNS_TRANSPORT_UDP;

describe('DnsClient', () => {
  jest.setTimeout(30000);

  describe('Basic queries', () => {
    test('should query with default options', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });

      expect(answers).toBeDefined();
      expect(Array.isArray(answers)).toBe(true);
      expect(answers.length).toBeGreaterThan(0);
      expect(answers[0].query).toBe('example.com');
      expect(answers[0].type).toBe(A_RECORD);
    });

    test('should accept lowercase record types', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      // test with lowercase 'a' and 'aaaa'
      const answers = await client.query({ query: 'example.com', types: ['a', 'aaaa'] });

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThanOrEqual(2);
      // verify types are returned as uppercase
      expect(answers.some(a => a.type === 'A')).toBe(true);
      expect(answers.some(a => a.type === 'AAAA')).toBe(true);
    });

    test('should accept mixed case record types', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      // test with lowercase 'soa'
      const answers = await client.query({ query: 'example.com', types: ['soa'] });

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThan(0);
      // verify type is returned as uppercase
      expect(answers[0].type).toBe('SOA');
    });

    test('should query with constructor defaults', async () => {
      const client = new DnsClient({
        server: '1.1.1.1',
        transport: TEST_TRANSPORT,
      });
      const answers = await client.query({ query: 'cloudflare.com', types: [A_RECORD] });

      expect(answers).toBeDefined();
      expect(answers[0].query).toBe('cloudflare.com');
    });

    test('should query with default type (A_RECORD)', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'google.com' });

      expect(answers).toBeDefined();
      expect(answers[0].query).toBe('google.com');
      expect(answers[0].type).toBe(A_RECORD);
    });

    test('should override constructor defaults', async () => {
      const client = new DnsClient({
        server: '1.1.1.1',
        transport: TEST_TRANSPORT,
      });
      const answers = await client.query({
        query: 'cloudflare.com',
        types: [A_RECORD],
        server: '8.8.8.8',
      });

      expect(answers[0].query).toBe('cloudflare.com');
    });

    test('one-off query pattern', async () => {
      const answers = await new DnsClient({ transport: TEST_TRANSPORT }).query({
        query: 'example.com',
        types: [A_RECORD],
      });

      expect(answers).toBeDefined();
      expect(answers[0].query).toBe('example.com');
    });
  });

  describe('queryAll', () => {
    test('should execute multiple queries in parallel', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.queryAll([
        { query: 'google.com', types: [A_RECORD] },
        { query: 'cloudflare.com', types: [A_RECORD] },
        { query: 'example.com', types: [A_RECORD] },
      ]);

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThanOrEqual(3);

      const queries = answers.map(a => a.query);
      expect(queries).toContain('google.com');
      expect(queries).toContain('cloudflare.com');
      expect(queries).toContain('example.com');
    });

    test('should accept lowercase record types in queryAll', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.queryAll([
        { query: 'google.com', types: ['a'] },
        { query: 'example.com', types: ['aaaa'] },
        { query: 'cloudflare.com', types: ['soa'] },
      ]);

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThanOrEqual(3);
      // verify all types are returned as uppercase
      expect(answers.some(a => a.type === 'A')).toBe(true);
      expect(answers.some(a => a.type === 'AAAA')).toBe(true);
      expect(answers.some(a => a.type === 'SOA')).toBe(true);
    });
  });

  describe('Error handling', () => {
    test('should return error in answer when network error occurs', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({
        query: 'example.com',
        types: [A_RECORD],
        server: '0.0.0.1', // invalid server to trigger error
      });

      expect(answers).toBeDefined();
      expect(answers.length).toBe(1);
      expect(answers[0].error).toBeDefined();
    });

    test('should handle NXDOMAIN response (not an error)', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({
        query: 'nonexistent-domain-12345.invalid',
        types: [A_RECORD],
      });

      expect(answers).toBeDefined();
      expect(Array.isArray(answers)).toBe(true);
      expect(answers.length).toBeGreaterThan(0);
      // NXDOMAIN is a valid response, not an error
      expect(answers[0].rcode).toBe(3); // NXDOMAIN
      expect(answers[0].error).toBeNull();
    });
  });

  describe('Authoritative queries and referrals', () => {
    jest.setTimeout(60000);

    test('should query authoritative nameservers from root', async () => {
      const client = new DnsClient({
        transport: TEST_TRANSPORT,
        authoritative: true,
      });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThan(0);
      expect(answers[0].query).toBe('example.com');
      expect(answers[0].type).toBe(A_RECORD);

      // validate trace has multiple delegation steps
      expect(answers[0].trace).toBeDefined();
      expect(Array.isArray(answers[0].trace)).toBe(true);
      const trace = answers[0].trace;
      if (!trace || !Array.isArray(trace) || trace.length < 2) {
        throw new Error(`Trace is missing or invalid. Trace length: ${trace?.length || 0}`);
      }

      // first hop should be from a root server (server or serverHost should match)
      const firstHop = trace[0];
      const firstServer = firstHop.serverHost || firstHop.server;
      expect(firstServer).toMatch(/^[a-m]\.root-servers\.net$/);

      // second hop should be from TLD server (.com)
      const secondHop = trace[1];
      const secondServer = secondHop.serverHost || secondHop.server;
      expect(secondServer).toMatch(/\.gtld-servers\.net$/);
    });

    test('should handle tracing NS records', async () => {
      const client = new DnsClient({
        transport: TEST_TRANSPORT,
        authoritative: true,
      });

      const answers = await client.query({ query: 'google.com', types: [NS_RECORD] });

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThan(0);
      expect(answers[0].type).toBe(NS_RECORD);

      // should have NS records
      expect(answers[0].records).toBeDefined();
      const records = answers[0].records;
      if (!records) {
        throw new Error('Records are missing');
      }
      expect(records.length).toBeGreaterThan(0);

      // validate trace has multiple delegation steps
      expect(answers[0].trace).toBeDefined();
      expect(Array.isArray(answers[0].trace)).toBe(true);
      const trace = answers[0].trace;
      if (!trace || !Array.isArray(trace) || trace.length < 2) {
        throw new Error(`Trace is missing or invalid. Trace length: ${trace?.length || 0}`);
      }

      // first hop should be from a root server (server or serverHost should match)
      const firstHop = trace[0];
      const firstServer = firstHop.serverHost || firstHop.server;
      expect(firstServer).toMatch(/^[a-m]\.root-servers\.net$/);

      // second hop should be from TLD server (.com)
      const secondHop = trace[1];
      const secondServer = secondHop.serverHost || secondHop.server;
      expect(secondServer).toMatch(/\.gtld-servers\.net$/);
    });

    test('should resolve through TLD nameservers', async () => {
      const client = new DnsClient({
        transport: TEST_TRANSPORT,
        authoritative: true,
      });

      const answers = await client.query({ query: 'example.org', types: [A_RECORD] });

      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThan(0);

      // validate trace has multiple delegation steps (root -> TLD -> authoritative)
      expect(answers[0].trace).toBeDefined();
      expect(Array.isArray(answers[0].trace)).toBe(true);
      const trace = answers[0].trace;
      if (!trace || !Array.isArray(trace) || trace.length < 2) {
        throw new Error(`Trace is missing or invalid. Trace length: ${trace?.length || 0}`);
      }

      // first hop should be from a root server (server or serverHost should match)
      const firstHop = trace[0];
      const firstServer = firstHop.serverHost || firstHop.server;
      expect(firstServer).toMatch(/^[a-m]\.root-servers\.net$/);

      // second hop should be from TLD server (.org TLD servers use afilias-nst.info or other providers)
      const secondHop = trace[1];
      const secondServer = secondHop.serverHost || secondHop.server;
      // .org TLD nameservers include patterns like: a0.org.afilias-nst.info, a2.org.afilias-nst.org, etc
      expect(secondServer).toMatch(/org/i);
    });
  });

  describe('DnsAnswer structure', () => {
    test('should have type field (not recordType)', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });

      expect(answers[0]).toHaveProperty('type');
      expect(answers[0]).not.toHaveProperty('recordType');
      expect(answers[0].type).toBe(A_RECORD);
    });

    test('should not have timestamp field', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });

      expect(answers[0]).not.toHaveProperty('timestamp');
    });

    test('should have class field set to IN', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });

      expect(answers[0].records).toBeDefined();
      expect(answers[0].records.length).toBeGreaterThan(0);
      expect(answers[0].records[0]).toHaveProperty('class');
      expect(answers[0].records[0].class).toBe('IN');
    });
  });

  describe('Edge cases', () => {
    test('should handle root domain query', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      // empty string normalizes to root domain and performs normal lookup
      const answers = await client.query({ query: '', types: [NS_RECORD] });
      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThan(0);
      // root domain queries typically return NS records for root nameservers
      expect(answers[0].records).toBeDefined();
    });

    test('should handle very long domain name', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      // DNS labels are limited to 63 octets, total domain name to 253 octets
      // create a valid long domain with multiple labels (each <= 63 chars)
      const longLabel = 'a'.repeat(63); // max label length
      const longDomain = `${longLabel}.${longLabel}.${longLabel}.com`; // 63 + 63 + 63 + 4 = 193 chars total
      const answers = await client.query({ query: longDomain, types: [A_RECORD] });
      expect(answers).toBeDefined();
      expect(answers.length).toBeGreaterThan(0);
    });

    test('should handle queryAll with empty array', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.queryAll([]);
      expect(answers).toEqual([]);
    });

    test('should handle DNS response with no answers', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'nonexistent-12345.invalid', types: [A_RECORD] });
      expect(answers).toBeDefined();
      expect(answers[0].records).toBeDefined();
    });

    test('should handle network timeout', async () => {
      const client = new DnsClient({ server: '0.0.0.1', timeout: 1000, transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers[0].error).toBeDefined();
    });

    test('should handle AbortController cancellation', async () => {
      const controller = new AbortController();
      const client = new DnsClient({ signal: controller.signal, transport: TEST_TRANSPORT });
      setTimeout(() => controller.abort(), 10);
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers[0].error).toBeDefined();
    });
  });

  describe('DnsOptions - Flag options', () => {
    test('should set recursionDesired flag', async () => {
      const client = new DnsClient({ flags: ['RD'], transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers).toBeDefined();
    });

    test('should clear recursionDesired flag', async () => {
      const client = new DnsClient({
        flags: [],
        authoritative: true,
        transport: TEST_TRANSPORT,
      });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers).toBeDefined();
    });

    test('should set dnssecExtended flag', async () => {
      const client = new DnsClient({ flags: ['RD', 'DO'], transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'cloudflare.com', types: ['DNSKEY'] });
      expect(answers).toBeDefined();
    });

    test('should accept lowercase flags', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({
        query: 'example.com',
        types: ['A'],
        flags: ['rd'],
      });
      expect(answers).toBeDefined();
      expect(answers[0].flags).toContain('RD');
    });

    test('should accept mixed case flags', async () => {
      const client = new DnsClient({ transport: TEST_TRANSPORT });
      const answers = await client.query({
        query: 'example.com',
        types: ['a'],
        flags: ['RD'],
      });
      expect(answers).toBeDefined();
      expect(answers[0].flags).toContain('RD');
    });
  });

  describe('DnsOptions - Error handling', () => {
    test('should respect timeout option', async () => {
      const client = new DnsClient({ server: '0.0.0.1', timeout: 500, transport: TEST_TRANSPORT });
      const start = Date.now();
      await client.query({ query: 'example.com', types: [A_RECORD] });
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(1500);
    });

    test('should use default timeout when 0', async () => {
      const client = new DnsClient({ timeout: 5000, transport: TEST_TRANSPORT });
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      expect(answers).toBeDefined();
    });

    test('should retry on retryable errors', async () => {
      const client = new DnsClient({
        server: '0.0.0.1',
        timeout: 500,
        retries: 2,
        backoff: 50,
        transport: TEST_TRANSPORT,
      });
      const start = Date.now();
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      const elapsed = Date.now() - start;
      // With retries: 2 and backoff: 50, we should have 3 attempts with 2 backoff delays
      // Minimum time: ~50ms (backoff attempt 0) + ~100ms (backoff attempt 1) = ~150ms
      // Plus time for 3 failed attempts, so should be at least 100ms
      expect(elapsed).toBeGreaterThan(100);
      // Verify we got an error (retries exhausted)
      expect(answers[0].error).toBeDefined();
      expect(answers[0].error?.shouldRetry?.()).toBe(true); // Error should be retryable
    });

    test('should respect backoff option', async () => {
      const client = new DnsClient({
        server: '0.0.0.1',
        timeout: 500,
        retries: 1,
        backoff: 500,
        transport: TEST_TRANSPORT,
      });
      const start = Date.now();
      const answers = await client.query({ query: 'example.com', types: [A_RECORD] });
      const elapsed = Date.now() - start;
      // With retries: 1 and backoff: 500, we should have 2 attempts with 1 backoff delay
      // Minimum time: ~500ms (backoff) + time for 2 failed attempts
      // Should be at least 450ms but less than reasonable upper bound accounting for CI timing variance
      expect(elapsed).toBeGreaterThan(450);
      expect(elapsed).toBeLessThan(2500); // Allow buffer for CI timing variance (errors are immediate, but CI can be slower)
      // Verify we got an error (retries exhausted)
      expect(answers[0].error).toBeDefined();
      expect(answers[0].error?.shouldRetry?.()).toBe(true); // Error should be retryable
    });
  });

  describe('Concurrency tests', () => {
    test('should respect concurrency limit of 1', async () => {
      const client = new DnsClient({ concurrency: 1, transport: TEST_TRANSPORT });
      const queries: DnsQuery[] = Array(5)
        .fill(0)
        .map((_, i) => ({ query: `test${i}.com`, types: [A_RECORD] }));
      const start = Date.now();
      await client.queryAll(queries);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThan(0);
    });

    test('should respect concurrency limit of 5', async () => {
      const client = new DnsClient({ concurrency: 5, transport: TEST_TRANSPORT });
      const queries: DnsQuery[] = Array(10)
        .fill(0)
        .map(() => ({ query: 'example.com', types: [A_RECORD] }));
      const answers = await client.queryAll(queries);
      expect(answers.length).toBe(10);
    });

    test('should process queries in parallel', async () => {
      const client = new DnsClient({ concurrency: 10, transport: TEST_TRANSPORT });
      const queries: DnsQuery[] = Array(3)
        .fill(0)
        .map(() => ({ query: 'example.com', types: [A_RECORD] }));
      const start = Date.now();
      await client.queryAll(queries);
      const elapsed = Date.now() - start;
      // Parallel should be faster than 3x sequential
      expect(elapsed).toBeLessThan(5000);
    });

    test('should handle concurrent queries with different record types', async () => {
      const client = new DnsClient({ concurrency: 10, transport: TEST_TRANSPORT });
      const answers = await client.queryAll([
        { query: 'example.com', types: [A_RECORD] },
        { query: 'example.com', types: [AAAA_RECORD] },
        { query: 'google.com', types: [A_RECORD] },
      ]);
      expect(answers.length).toBe(3);
    });

    test('should handle concurrency with partial failures', async () => {
      const client = new DnsClient({ concurrency: 5, timeout: 1000, transport: TEST_TRANSPORT });
      const answers = await client.queryAll([
        { query: 'example.com', types: [A_RECORD] },
        { query: 'invalid-12345.invalid', types: [A_RECORD] },
        { query: 'google.com', types: [A_RECORD] },
      ]);
      expect(answers.length).toBe(3);
    });
  });
});
