import { getRecordTypesFromFixtures, testDomain, DNS_DOH_SERVER_URLS } from './dns-test-helpers';
import { DNS_TRANSPORT_DOH, FLAG_RECURSION_DESIRED } from '../src/constants';
import { DnsClient } from '../src/index';
import { dohQuery } from '../src/transports/doh';
import type { DnsQuestion, DnsOptions } from '../src/types';

describe('DNS DoH (DNS over HTTPS) Integration Tests', () => {
  jest.setTimeout(60000);

  // Test all Cloudflare fixtures comprehensively
  const cloudflareRecords = getRecordTypesFromFixtures('doh', 'cloudflare');
  test.each(cloudflareRecords)(
    'should match $recordType for $domain via Cloudflare DoH',
    async ({ domain, recordType, server }) => {
      await testDomain(domain, [recordType], server, DNS_TRANSPORT_DOH);
    }
  );

  // Test all Google fixtures comprehensively
  const googleRecords = getRecordTypesFromFixtures('doh', 'google');
  test.each(googleRecords)(
    'should match $recordType for $domain via Google DoH',
    async ({ domain, recordType, server }) => {
      await testDomain(domain, [recordType], server, DNS_TRANSPORT_DOH);
    }
  );

  test('should query multiple domains in parallel', async () => {
    const client = new DnsClient({
      transport: DNS_TRANSPORT_DOH,
      server: DNS_DOH_SERVER_URLS.google,
    });
    const answers = await client.queryAll([
      { query: 'google.com', types: ['A'] },
      { query: 'example.com', types: ['A'] },
    ]);
    expect(answers.length).toBeGreaterThanOrEqual(2);
  });

  test('should handle DNSSEC with DoH', async () => {
    const client = new DnsClient({
      transport: DNS_TRANSPORT_DOH,
      server: DNS_DOH_SERVER_URLS.cloudflare,
      flags: ['RD', 'DO'],
    });
    const answers = await client.query({ query: 'cloudflare.com', types: ['DNSKEY'] });
    expect(answers.length).toBeGreaterThan(0);
  });

  describe('Error handling', () => {
    const mockQuestion: DnsQuestion = {
      query: 'example.com',
      type: 'A',
      server: 'https://cloudflare-dns.com/dns-query',
      flags: [FLAG_RECURSION_DESIRED],
    };

    const mockOptions: DnsOptions = {
      server: 'https://cloudflare-dns.com/dns-query',
      transport: 'doh',
      authoritative: false,
      flags: [FLAG_RECURSION_DESIRED],
      tcpFallback: true,
      timeout: 5000,
      retries: 0,
      backoff: 100,
      cache: false,
      cacheSize: 1000,
      concurrency: 10,
    };

    test('should handle timeout', async () => {
      const shortTimeout: DnsOptions = { ...mockOptions, timeout: 1 };
      await expect(dohQuery(mockQuestion, shortTimeout)).rejects.toThrow();
    }, 10000);

    test('should handle invalid server URL', async () => {
      const invalidQuestion: DnsQuestion = {
        ...mockQuestion,
        server: 'https://invalid-dns-server-12345.example.invalid/dns-query',
      };
      await expect(dohQuery(invalidQuestion, mockOptions)).rejects.toThrow();
    }, 10000);
  });
});
