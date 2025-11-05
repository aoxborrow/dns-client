import { testDomain, DNS_TEST_SERVER_IPS, getRecordTypesFromFixtures } from './dns-test-helpers.js';
import { DNS_TRANSPORT_UDP } from '../src/constants.js';
import { DnsClient } from '../src/index.js';

describe('DNS UDP Integration Tests', () => {
  jest.setTimeout(60000);

  // Test all Cloudflare fixtures comprehensively
  const cloudflareRecords = getRecordTypesFromFixtures('udp', 'cloudflare');
  test.each(cloudflareRecords)(
    'should match $recordType for $domain via Cloudflare UDP',
    async ({ domain, recordType, server }) => {
      await testDomain(domain, [recordType], server, DNS_TRANSPORT_UDP);
    }
  );

  // Test all Google fixtures comprehensively
  const googleRecords = getRecordTypesFromFixtures('udp', 'google');
  test.each(googleRecords)(
    'should match $recordType for $domain via Google UDP',
    async ({ domain, recordType, server }) => {
      await testDomain(domain, [recordType], server, DNS_TRANSPORT_UDP);
    }
  );

  test('should query multiple domains in parallel', async () => {
    const client = new DnsClient({
      transport: DNS_TRANSPORT_UDP,
      server: DNS_TEST_SERVER_IPS.cloudflare,
    });
    const answers = await client.queryAll([
      { query: 'google.com', types: ['A'] },
      { query: 'example.com', types: ['A'] },
    ]);
    expect(answers.length).toBeGreaterThanOrEqual(2);
  });

  test('should handle large DNSSEC responses', async () => {
    const client = new DnsClient({
      transport: DNS_TRANSPORT_UDP,
      server: '8.8.8.8',
      flags: ['RD', 'DO'],
    });
    const answers = await client.query({ query: 'cloudflare.com', types: ['DNSKEY'] });
    expect(answers.length).toBeGreaterThan(0);
  });
});
