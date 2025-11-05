import { testDomain, DNS_TEST_SERVER_IPS, getRecordTypesFromFixtures } from './dns-test-helpers.js';
import { DNS_TRANSPORT_TCP } from '../src/constants.js';
import { DnsClient } from '../src/index.js';

// note: Cloudflare (1.1.1.1) via TCP returns slightly different results for some queries
// (e.g., different MX records, A/AAAA addresses) compared to UDP/DoH, so we only test
// against Google (8.8.8.8) which is consistent across all transports.

describe('DNS TCP Integration Tests', () => {
  jest.setTimeout(60000);

  // Test all Google fixtures comprehensively
  const googleRecords = getRecordTypesFromFixtures('tcp', 'google');
  test.each(googleRecords)(
    'should match $recordType for $domain via Google TCP',
    async ({ domain, recordType, server }) => {
      await testDomain(domain, [recordType], server, DNS_TRANSPORT_TCP);
    }
  );

  test('should query multiple domains in parallel', async () => {
    const client = new DnsClient({
      transport: DNS_TRANSPORT_TCP,
      server: DNS_TEST_SERVER_IPS.google,
    });
    const answers = await client.queryAll([
      { query: 'google.com', types: ['A'] },
      { query: 'example.com', types: ['A'] },
    ]);
    expect(answers.length).toBeGreaterThanOrEqual(2);
  });
});
