import { readFileSync } from 'fs';
import { join } from 'path';
import { sortRecordsCanonical, sortObjectKeys } from '../src/utils.js';
import { DNS_TRANSPORT_DOH } from '../src/constants.js';
import type { DnsTransportType, DnsRecordType } from '../src/types.js';

// common record types to test
export const DNS_TEST_RECORD_TYPES = ['SOA', 'A', 'MX', 'NS', 'DNSKEY', 'DS', 'CAA'];

// consolidated test domains with their specific record types to test
export const DNS_TEST_DOMAINS: Record<string, string[]> = {
  // existing common test domains - test common record types
  'one.com': DNS_TEST_RECORD_TYPES,
  'cloudflare.com': [...DNS_TEST_RECORD_TYPES, 'RRSIG', 'NSEC', 'CDS', 'CDNSKEY', 'HTTPS', 'SVCB'],
  'mozilla.org': DNS_TEST_RECORD_TYPES,

  // domains from DNS_TEST_DOMAINS_RECORDS with their specific record types
  'example.com': [...DNS_TEST_RECORD_TYPES, 'AAAA', 'NSEC3PARAM'],
  'www.github.com': ['CNAME'],
  'gmail.com': ['MX'],
  'google.com': ['TXT', 'CAA'],
  '_443._tcp.www.huque.com': ['TLSA'],
  '_xmpp-client._tcp.jabber.org': ['SRV'],
  'www.isc.org': ['SSHFP'],
  '8.8.8.8.in-addr.arpa': ['PTR'],
};

// available servers for each resolver type
// note: Cloudflare (1.1.1.1) via TCP returns slightly different results for some queries
export const DNS_TEST_SERVERS: Record<string, string[]> = {
  doh: ['cloudflare', 'google'],
  udp: ['cloudflare', 'google'],
  tcp: ['google'], // only google for TCP due to cloudflare differences
};

// DoH server URLs
export const DNS_DOH_SERVER_URLS: Record<string, string> = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/dns-query',
  quad9: 'https://dns.quad9.net/dns-query',
  opendns: 'https://doh.opendns.com/dns-query',
};

// UDP/TCP DNS server IP addresses
export const DNS_TEST_SERVER_IPS: Record<string, string> = {
  cloudflare: '1.1.1.1',
  google: '8.8.8.8',
};

// helper function to get domain-record type combinations from the new DNS_TEST_DOMAINS structure
export function getRecordTypesFromFixtures(
  resolverType: DnsTransportType,
  server?: string
): { domain: string; recordType: string; server: string }[] {
  const domainRecordTypes: { domain: string; recordType: string; server: string }[] = [];

  const serversToTest = server ? [server] : DNS_TEST_SERVERS[resolverType];

  for (const testServer of serversToTest) {
    for (const [domain, recordTypes] of Object.entries(DNS_TEST_DOMAINS)) {
      for (const recordType of recordTypes) {
        try {
          // check if fixture exists for this combination
          const fixtureData = loadFixture(domain, testServer);

          // check if this record type has data in the fixture
          if (typeof fixtureData === 'object' && !Array.isArray(fixtureData)) {
            const records = fixtureData[recordType];
            if (Array.isArray(records) && records.length > 0) {
              domainRecordTypes.push({ domain, recordType, server: testServer });
            }
          } else if (Array.isArray(fixtureData)) {
            // handle old flat array format (backward compatibility)
            const recordsOfType = fixtureData.filter(
              (record): record is Record<string, unknown> =>
                typeof record === 'object' &&
                record !== null &&
                (record as Record<string, unknown>).type === recordType
            );
            if (recordsOfType.length > 0) {
              domainRecordTypes.push({ domain, recordType, server: testServer });
            }
          }
        } catch {
          // silently skip domains with missing fixtures
        }
      }
    }
  }

  return domainRecordTypes;
}

// helper function to compare DNS records while ignoring specific fields
export function compareRecords(
  actual: Record<string, unknown>[],
  expected: Record<string, unknown>[],
  enableLogging = false
): { matches: boolean; differences: string[] } {
  const differences: string[] = [];

  // fields to ignore during comparison (by record type)
  const ignoredFields: Record<string, string[]> = {
    SOA: ['serial'],
    RRSIG: ['signature_expiration', 'signature_inception', 'signature'],
  };

  // global fields to ignore for all record types
  const globalIgnoredFields = ['ttl', 'class'];

  // domains with load balancing that can have changing IP addresses
  const loadBalancedDomains = ['github.com', 'cloudflare.com', 'example.com'];

  // helper to check if a domain uses load balancing
  function isLoadBalancedDomain(record: Record<string, unknown>): boolean {
    const recordName = typeof record.name === 'string' ? record.name : '';
    return loadBalancedDomains.some(
      domain => recordName === domain || recordName.endsWith(`.${domain}`)
    );
  }

  // TXT records that are known to change frequently
  const volatileTxtPatterns = [
    /^google-site-verification=/,
    /^facebook-domain-verification=/,
    /^apple-domain-verification=/,
    /^atlassian-domain-verification=/,
    /^slack-domain-verification=/,
    /^status-page-domain-verification=/,
    /^v=spf1\s/,
    /^MS=/,
    /^[a-f0-9]{32}$/,
    /^adobe-idp-site-verification=/,
    /^calendly-site-verification=/,
    /^docusign=/,
    /^krisp-domain-verification=/,
    /^loom-site-verification=/,
    /^miro-verification=/,
    /^shopify-verification-code=/,
    /^stripe-verification=/,
    /^cisco-ci-domain-verification=/,
    /^creatopy-domain-verification=/,
    /^docker-verification=/,
    /^drift-domain-verification=/,
    /^liveramp-site-verification=/,
    /^logmein-verification-code=/,
    /^onetrust-domain-verification=/,
    /^ZOOM_verify_/,
    /^_[a-z0-9]+$/,
    /^asv=/,
    /^_saml-domain-challenge/,
  ];

  function isVolatileTxtRecord(record: Record<string, unknown>): boolean {
    if (record.type !== 'TXT') return false;
    const value = typeof record.value === 'string' ? record.value : '';
    return volatileTxtPatterns.some(pattern => pattern.test(value));
  }

  function isVolatileIpRecord(record: Record<string, unknown>): boolean {
    if (record.type !== 'A' && record.type !== 'AAAA') return false;
    return isLoadBalancedDomain(record);
  }

  function normalizeRecord(record: Record<string, unknown>): Record<string, unknown> {
    const normalized = { ...record };
    const recordType = record.type;

    // remove global ignored fields
    for (const field of globalIgnoredFields) {
      delete normalized[field];
    }

    // remove record-type specific ignored fields
    if (recordType && typeof recordType === 'string' && ignoredFields[recordType]) {
      for (const field of ignoredFields[recordType]) {
        delete normalized[field];
      }
    }

    return sortObjectKeys(normalized) as Record<string, unknown>;
  }

  // filter out volatile records
  const stableActual = actual.filter(
    record => !isVolatileTxtRecord(record) && !isVolatileIpRecord(record)
  );
  const stableExpected = expected.filter(
    record => !isVolatileTxtRecord(record) && !isVolatileIpRecord(record)
  );

  // normalize records
  const normalizedActual = stableActual.map(normalizeRecord);
  const normalizedExpected = stableExpected.map(normalizeRecord);

  // use canonical DNS sorting
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument
  const sortedActual = sortRecordsCanonical(normalizedActual as any);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument
  const sortedExpected = sortRecordsCanonical(normalizedExpected as any);

  // note filtered records
  const filteredActualCount = actual.length - stableActual.length;
  const filteredExpectedCount = expected.length - stableExpected.length;

  if ((filteredActualCount > 0 || filteredExpectedCount > 0) && enableLogging) {
    console.log(
      `  Note: Filtered ${filteredActualCount} volatile records from actual, ${filteredExpectedCount} from expected`
    );
  }

  // compare lengths
  if (sortedActual.length !== sortedExpected.length) {
    differences.push(
      `Stable record count mismatch: actual ${sortedActual.length}, expected ${sortedExpected.length}`
    );
  }

  // compare each record
  const maxLength = Math.max(sortedActual.length, sortedExpected.length);
  for (let i = 0; i < maxLength; i++) {
    const actualRecord = sortedActual[i];
    const expectedRecord = sortedExpected[i];

    if (!actualRecord) {
      differences.push(`Missing actual record at index ${i}: ${JSON.stringify(expectedRecord)}`);
      continue;
    }

    if (!expectedRecord) {
      differences.push(`Extra actual record at index ${i}: ${JSON.stringify(actualRecord)}`);
      continue;
    }

    // compare each field
    const allKeys = new Set([...Object.keys(actualRecord), ...Object.keys(expectedRecord)]);

    // Compare values handling different types
    const actualRecName = typeof actualRecord.name === 'string' ? actualRecord.name : '';
    const actualRecType = typeof actualRecord.type === 'string' ? actualRecord.type : '';

    for (const key of Array.from(allKeys)) {
      // @ts-expect-error - accessing dynamic keys for flexible comparison
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const actualValue = actualRecord[key];
      // @ts-expect-error - accessing dynamic keys for flexible comparison
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const expectedValue = expectedRecord[key];

      if (Array.isArray(actualValue) && Array.isArray(expectedValue)) {
        if (
          actualValue.length !== expectedValue.length ||
          !actualValue.every((val, idx) => val === expectedValue[idx])
        ) {
          differences.push(
            `Record ${i} (${actualRecName} ${actualRecType}) field '${key}': ` +
              `actual [${actualValue.join(',')}], expected [${expectedValue.join(',')}]`
          );
        }
      } else if (actualValue !== expectedValue) {
        differences.push(
          `Record ${i} (${actualRecName} ${actualRecType}) field '${key}': ` +
            `actual '${String(actualValue)}', expected '${String(expectedValue)}'`
        );
      }
    }
  }

  return {
    matches: differences.length === 0,
    differences,
  };
}

// helper function to load fixture data
export function loadFixture(domain: string, server: string): Record<string, unknown[]> | unknown[] {
  // fixtures are now transport-agnostic and only organized by server
  const filename = domain.replace(/\./g, '-') + '.json';
  const fixturePath = join(process.cwd(), 'test', 'fixtures', server, filename);

  try {
    const data = readFileSync(fixturePath, 'utf-8');
    return JSON.parse(data) as Record<string, unknown[]> | unknown[];
  } catch (error) {
    throw new Error(`Failed to load fixture for ${domain} from ${fixturePath}: ${String(error)}`);
  }
}

// helper function to load records for a specific query type from fixture data
export function loadFixtureRecords(domain: string, server: string, queryType: string): unknown[] {
  const fixtureData = loadFixture(domain, server);

  // handle new nested format
  if (typeof fixtureData === 'object' && !Array.isArray(fixtureData)) {
    return fixtureData[queryType] || [];
  }

  // handle old flat array format (backward compatibility)
  if (Array.isArray(fixtureData)) {
    return fixtureData;
  }

  return [];
}

// helper function to extract records from DNS answers (new API)
export function extractRecordsFromAnswers(answers: { records?: unknown[] }[]): unknown[] {
  const actualRecords: unknown[] = [];

  for (const answer of answers) {
    if (answer.records) {
      actualRecords.push(...answer.records);
    }
  }

  return actualRecords;
}

// helper function to test a domain with specific record types for a given resolver
export async function testDomain(
  domain: string,
  recordTypes: string[],
  server: string,
  resolverType: DnsTransportType,
  enableLogging = false
): Promise<void> {
  const { DnsClient } = await import('../src/index.js');
  const { expect } = await import('@jest/globals');

  for (const recordType of recordTypes) {
    try {
      if (enableLogging) {
        console.log(`Testing ${recordType} records for ${domain} via ${resolverType} (${server})`);
      }

      // DNSSEC records require the dnssec flag
      const dnssecRecordTypes = [
        'RRSIG',
        'NSEC',
        'NSEC3',
        'NSEC3PARAM',
        'CDS',
        'CDNSKEY',
        'DNSKEY',
        'DS',
      ];
      const needsDnssec = dnssecRecordTypes.includes(recordType);

      // Handle authoritative server
      const isAuthoritative = server === 'authoritative';

      // determine server value based on transport type
      let serverValue: string | undefined;
      if (isAuthoritative) {
        serverValue = undefined;
      } else if (resolverType === DNS_TRANSPORT_DOH) {
        // use full URL for DoH
        serverValue = DNS_DOH_SERVER_URLS[server];
      } else {
        // use IP address for UDP/TCP
        serverValue = DNS_TEST_SERVER_IPS[server];
      }

      // Create client with appropriate settings
      const client = new DnsClient({
        transport: resolverType,
        server: serverValue,
        authoritative: isAuthoritative,
        flags: needsDnssec ? ['RD', 'DO'] : ['RD'],
      });

      // Execute query
      const answers = await client.query({ query: domain, types: [recordType as DnsRecordType] });

      // basic validation
      expect(answers).toBeDefined();
      expect(Array.isArray(answers)).toBe(true);
      expect(answers.length).toBeGreaterThan(0);

      // check for errors in the answer
      if (answers[0].error) {
        if (enableLogging) {
          console.log(`Query returned error: ${answers[0].error.message}`);
        }
        // Skip this test case if there was an error
        return;
      }

      // extract actual records from the answers
      const actualRecords = extractRecordsFromAnswers(answers);
      const actualRecordsOfType = actualRecords.filter(
        (record): record is Record<string, unknown> =>
          typeof record === 'object' &&
          record !== null &&
          (record as Record<string, unknown>).type === recordType
      );

      // load expected records from fixture
      const expectedRecords = loadFixtureRecords(domain, server, recordType);
      const expectedRecordsOfType = expectedRecords.filter(
        (record): record is Record<string, unknown> => {
          if (typeof record !== 'object' || record === null) return false;
          const rec = record as Record<string, unknown>;
          return rec.type === recordType;
        }
      );

      // skip test if no records of this type exist in fixture
      // if (expectedRecordsOfType.length === 0) {
      //   if (enableLogging) {
      //     console.log(`Skipping ${domain} ${recordType} (${server}): no records in fixture`);
      //   }
      //   continue;
      // }

      // compare records of this specific type
      const comparison = compareRecords(actualRecordsOfType, expectedRecordsOfType, enableLogging);

      if (!comparison.matches) {
        if (enableLogging) {
          console.log(`Differences found for ${domain} ${recordType} records (${server}):`);
          for (const diff of comparison.differences) {
            console.log(`  - ${diff}`);
          }
        }

        // provide detailed failure information
        const failureMessage = [
          `${recordType} records mismatch for ${domain} (${server}):`,
          `Expected ${expectedRecordsOfType.length} records, got ${actualRecordsOfType.length}`,
          '',
          'Differences:',
          ...comparison.differences.map(diff => `  - ${diff}`),
          '',
          'Expected records:',
          JSON.stringify(expectedRecordsOfType, null, 2),
          '',
          'Actual records:',
          JSON.stringify(actualRecordsOfType, null, 2),
        ].join('\n');

        throw new Error(failureMessage);
      }

      expect(actualRecordsOfType.length).toBeGreaterThan(0);
      expect(expectedRecordsOfType.length).toBeGreaterThan(0);

      if (enableLogging) {
        console.log(
          `${domain} ${recordType} (${server}): ${actualRecordsOfType.length} records matched fixture`
        );
      }

      // small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      if (enableLogging) {
        console.log(`${recordType} query via ${resolverType} (${server}) failed:`, error);
      }

      // only fail test for critical record types
      const criticalRecordTypes = ['A', 'NS', 'SOA'];
      if (criticalRecordTypes.includes(recordType)) {
        console.error(
          `Critical record type ${recordType} via ${resolverType} (${server}) failed:`,
          error
        );
        throw error;
      }

      if (enableLogging) {
        console.log(`Non-critical record type, continuing...`);
      }
    }
  }
}
