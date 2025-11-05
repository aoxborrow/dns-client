import {
  getRecords,
  detectDohServer,
  getRandomRootServer,
  naturalCompare,
  naturalSort,
  sortObjectKeys,
  deduplicateRecords,
  normalizeHost,
  isValidIp,
  isValidIpv4,
  isValidIpv6,
  reverseIp,
  isEmpty,
  stripProtocol,
  sanitizeString,
} from '../src/utils.js';
import type { DnsAnswer, DnsRecord } from '../src/types.js';

describe('Utility Functions', () => {
  describe('getRecords', () => {
    test('should extract records from DnsAnswer array', () => {
      const answers: DnsAnswer[] = [
        {
          query: 'example.com',
          type: 'A',
          records: [
            { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.1' },
            { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.2' },
          ],
        } as DnsAnswer,
      ];
      const records = getRecords(answers);
      expect(records).toHaveLength(2);
      expect((records[0] as { address: string }).address).toBe('192.0.2.1');
    });

    test('should handle empty answers array', () => {
      const records = getRecords([]);
      expect(records).toEqual([]);
    });

    test('should handle answers with no records', () => {
      const answers: DnsAnswer[] = [
        {
          query: 'example.com',
          type: 'A',
          records: [],
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
          authorities: [],
          additionals: [],
          trace: [],
        } as DnsAnswer,
      ];
      const records = getRecords(answers);
      expect(records).toEqual([]);
    });

    test('should flatten multiple answer records', () => {
      const answers: DnsAnswer[] = [
        {
          query: 'example.com',
          type: 'A',
          records: [
            { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.1' },
          ],
        } as DnsAnswer,
        {
          query: 'example.com',
          type: 'AAAA',
          records: [{ type: 'AAAA', name: 'example.com', ttl: 300, address: '2001:db8::1' }],
        } as DnsAnswer,
      ];
      const records = getRecords(answers);
      expect(records).toHaveLength(2);
    });
  });

  describe('detectDohServer', () => {
    test('should identify DoH URLs with https', () => {
      expect(detectDohServer('https://cloudflare-dns.com/dns-query')).toBe(true);
    });

    test('should identify DoH URLs with http', () => {
      expect(detectDohServer('http://localhost/dns-query')).toBe(true);
    });

    test('should identify URLs ending with /dns-query', () => {
      expect(detectDohServer('cloudflare-dns.com/dns-query')).toBe(true);
    });

    test('should identify URLs ending with /resolve', () => {
      expect(detectDohServer('dns.google/resolve')).toBe(true);
    });

    test('should reject IP addresses', () => {
      expect(detectDohServer('1.1.1.1')).toBe(false);
    });

    test('should reject plain hostnames', () => {
      expect(detectDohServer('dns.example.com')).toBe(false);
    });
  });

  describe('getRandomRootServer', () => {
    test('should return valid root server', () => {
      const server = getRandomRootServer();
      expect(typeof server).toBe('string');
      expect(server).toMatch(/^[a-m]\.root-servers\.net$/);
    });

    test('should return different servers (eventually)', () => {
      const servers = new Set();
      for (let i = 0; i < 20; i++) {
        servers.add(getRandomRootServer());
      }
      expect(servers.size).toBeGreaterThan(1);
    });
  });

  describe('naturalCompare', () => {
    test('should sort numeric strings correctly', () => {
      expect(naturalCompare('file1', 'file10')).toBeLessThan(0);
      expect(naturalCompare('file10', 'file2')).toBeGreaterThan(0);
    });

    test('should sort alphabetically', () => {
      expect(naturalCompare('apple', 'banana')).toBeLessThan(0);
    });

    test('should handle equal strings', () => {
      expect(naturalCompare('test', 'test')).toBe(0);
    });
  });

  describe('naturalSort', () => {
    test('should preserve array order when already sorted', () => {
      const arr = ['a', 'b', 'c'];
      expect(naturalSort(arr)).toEqual(['a', 'b', 'c']);
    });

    test('should sort mixed alphanumeric strings', () => {
      const arr = ['file10', 'file2', 'file1'];
      expect(naturalSort(arr)).toEqual(['file1', 'file2', 'file10']);
    });
  });

  describe('sortObjectKeys', () => {
    test('should sort object keys naturally', () => {
      const obj = { z: 1, a: 2, m: 3 };
      const sorted = sortObjectKeys(obj) as Record<string, number>;
      expect(Object.keys(sorted)).toEqual(['a', 'm', 'z']);
    });

    test('should handle null', () => {
      expect(sortObjectKeys(null)).toBeNull();
    });

    test('should handle arrays', () => {
      const arr = [1, 2, 3];
      expect(sortObjectKeys(arr)).toEqual(arr);
    });
  });

  describe('deduplicateRecords', () => {
    test('should remove duplicate records', () => {
      const records: DnsRecord[] = [
        { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.1' },
        { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.1' },
      ];
      const result = deduplicateRecords(records);
      expect(result).toHaveLength(1);
    });

    test('should preserve unique records', () => {
      const records: DnsRecord[] = [
        { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.1' },
        { name: 'example.com', ttl: 300, type: 'A', class: 'IN', address: '192.0.2.2' },
      ];
      const result = deduplicateRecords(records);
      expect(result).toHaveLength(2);
    });

    test('should handle empty array', () => {
      const result = deduplicateRecords([]);
      expect(result).toEqual([]);
    });
  });

  describe('Record flattening - all record types', () => {
    test('should flatten A records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [{ name: 'test.com', ttl: 300, type: 'A', class: 'IN', address: '1.2.3.4' }],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten AAAA records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [{ name: 'test.com', ttl: 300, type: 'AAAA', class: 'IN', address: '::1' }],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten CNAME records', () => {
      const answers: Partial<DnsAnswer>[] = [
        {
          records: [
            { name: 'www.test.com', ttl: 300, type: 'CNAME', class: 'IN', value: 'test.com' },
          ],
        },
      ];
      expect(getRecords(answers as DnsAnswer[])).toHaveLength(1);
    });

    test('should flatten MX records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            { type: 'MX', name: 'test.com', ttl: 300, priority: 10, exchange: 'mail.test.com' },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten NS records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [{ type: 'NS', name: 'test.com', ttl: 300, value: 'ns1.test.com' }],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten PTR records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [{ type: 'PTR', name: '1.0.0.127.in-addr.arpa', ttl: 300, value: 'localhost' }],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten SOA records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            {
              type: 'SOA',
              name: 'test.com',
              ttl: 300,
              nsname: 'ns1.test.com',
              hostmaster: 'admin.test.com',
              serial: 1,
              refresh: 3600,
              retry: 600,
              expire: 86400,
              minimum: 300,
            },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten SRV records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            {
              type: 'SRV',
              name: '_http._tcp.test.com',
              ttl: 300,
              priority: 10,
              weight: 5,
              port: 80,
              target: 'server.test.com',
            },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten TXT records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [{ type: 'TXT', name: 'test.com', ttl: 300, value: 'v=spf1 -all' }],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten CAA records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            {
              type: 'CAA',
              name: 'test.com',
              ttl: 300,
              flags: 0,
              tag: 'issue',
              value: 'ca.example.com',
            },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten DNSKEY records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            {
              type: 'DNSKEY',
              name: 'test.com',
              ttl: 300,
              flags: 256,
              algorithm: 13,
              protocol: 3,
              public_key: 'abc123',
            },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten DS records', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            {
              type: 'DS',
              name: 'test.com',
              ttl: 300,
              key_tag: 12345,
              algorithm: 13,
              digest_type: 2,
              digest: 'abc',
            },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(1);
    });

    test('should flatten mixed record types', () => {
      const answers: DnsAnswer[] = [
        {
          records: [
            { name: 'test.com', ttl: 300, type: 'A', class: 'IN', address: '1.2.3.4' },
            { name: 'test.com', ttl: 300, type: 'AAAA', class: 'IN', address: '::1' },
            { type: 'MX', name: 'test.com', ttl: 300, priority: 10, exchange: 'mail.test.com' },
          ],
        } as DnsAnswer,
      ];
      expect(getRecords(answers)).toHaveLength(3);
    });

    test('should deduplicate mixed record types', () => {
      const records: DnsRecord[] = [
        { name: 'test.com', ttl: 300, type: 'A', class: 'IN', address: '1.2.3.4' },
        { name: 'test.com', ttl: 300, type: 'A', class: 'IN', address: '1.2.3.4' },
        { name: 'test.com', ttl: 300, type: 'AAAA', class: 'IN', address: '::1' },
      ];
      const result = deduplicateRecords(records);
      expect(result).toHaveLength(2);
    });
  });

  describe('normalizeHost', () => {
    test('should normalize hostname', () => {
      expect(normalizeHost('EXAMPLE.COM')).toBe('example.com');
      expect(normalizeHost('  example.com  ')).toBe('example.com');
    });

    test('should remove leading and trailing periods', () => {
      expect(normalizeHost('.example.com.')).toBe('example.com');
      expect(normalizeHost('...example.com...')).toBe('example.com');
    });

    test('should remove protocol by default', () => {
      expect(normalizeHost('https://example.com')).toBe('example.com');
      expect(normalizeHost('http://example.com')).toBe('example.com');
    });

    test('should preserve protocol when removeProtocol is false', () => {
      expect(normalizeHost('https://example.com', false)).toBe('https://example.com');
    });

    test('should remove trailing slash', () => {
      expect(normalizeHost('example.com/')).toBe('example.com');
    });

    test('should handle empty strings', () => {
      expect(normalizeHost('')).toBe('');
      expect(normalizeHost('   ')).toBe('');
    });

    test('should handle null/undefined gracefully', () => {
      expect(normalizeHost(null as unknown as string)).toBe('');
      expect(normalizeHost(undefined as unknown as string)).toBe('');
    });
  });

  describe('isValidIp', () => {
    test('should validate IPv4 addresses', () => {
      expect(isValidIp('192.168.1.1')).toBe(true);
      expect(isValidIp('1.1.1.1')).toBe(true);
      expect(isValidIp('0.0.0.0')).toBe(true);
      expect(isValidIp('255.255.255.255')).toBe(true);
    });

    test('should validate IPv6 addresses', () => {
      expect(isValidIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
      expect(isValidIp('2001:db8::1')).toBe(true);
      expect(isValidIp('::1')).toBe(true);
    });

    test('should reject invalid IPs', () => {
      expect(isValidIp('not.an.ip')).toBe(false);
      expect(isValidIp('256.1.1.1')).toBe(false);
      expect(isValidIp('example.com')).toBe(false);
      expect(isValidIp('')).toBe(false);
    });

    test('should reject hostnames', () => {
      expect(isValidIp('google.com')).toBe(false);
      expect(isValidIp('sub.domain.com')).toBe(false);
      expect(isValidIp('localhost')).toBe(false);
      expect(isValidIp('www.example.com')).toBe(false);
      expect(isValidIp('123.com')).toBe(false);
      expect(isValidIp('a.b.c')).toBe(false);
      expect(isValidIp('sub.1.2.3')).toBe(false);
    });

    test('should handle CIDR notation', () => {
      expect(isValidIp('192.168.1.0/24')).toBe(true);
      expect(isValidIp('2001:db8::/32')).toBe(true);
    });
  });

  describe('isValidIpv4', () => {
    test('should validate IPv4 addresses', () => {
      expect(isValidIpv4('192.168.1.1')).toBe(true);
      expect(isValidIpv4('1.1.1.1')).toBe(true);
    });

    test('should reject IPv6 addresses', () => {
      expect(isValidIpv4('2001:db8::1')).toBe(false);
    });

    test('should require at least 3 octets', () => {
      expect(isValidIpv4('1.1')).toBe(false);
      expect(isValidIpv4('1.1.1')).toBe(true);
    });

    test('should handle CIDR notation', () => {
      expect(isValidIpv4('192.168.1.0/24')).toBe(true);
    });
  });

  describe('isValidIpv6', () => {
    test('should validate IPv6 addresses', () => {
      expect(isValidIpv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
      expect(isValidIpv6('2001:db8::1')).toBe(true);
      expect(isValidIpv6('::1')).toBe(true);
    });

    test('should reject IPv4 addresses', () => {
      expect(isValidIpv6('192.168.1.1')).toBe(false);
    });

    test('should require at least 3 parts', () => {
      expect(isValidIpv6('1')).toBe(false);
      expect(isValidIpv6('1:2')).toBe(false);
      expect(isValidIpv6('2001::1')).toBe(true);
      expect(isValidIpv6('::1')).toBe(true);
    });

    test('should handle CIDR notation', () => {
      expect(isValidIpv6('2001:db8::/32')).toBe(true);
    });
  });

  describe('reverseIp', () => {
    test('should reverse IPv4 addresses', () => {
      expect(reverseIp('1.0.0.1')).toBe('1.0.0.1.in-addr.arpa');
      expect(reverseIp('192.168.1.1')).toBe('1.1.168.192.in-addr.arpa');
      expect(reverseIp('8.8.8.8')).toBe('8.8.8.8.in-addr.arpa');
    });

    test('should reverse IPv6 addresses', () => {
      expect(reverseIp('2001:db8::1')).toBe(
        '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
      );
      expect(reverseIp('::1')).toBe(
        '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa'
      );
    });

    test('should handle invalid IPs', () => {
      expect(reverseIp('not.an.ip')).toBe('not.an.ip');
      expect(reverseIp('')).toBe('');
    });

    test('should trim whitespace', () => {
      expect(reverseIp('  1.0.0.1  ')).toBe('1.0.0.1.in-addr.arpa');
    });
  });

  describe('isEmpty', () => {
    test('should detect empty strings', () => {
      expect(isEmpty('')).toBe(true);
      expect(isEmpty('   ')).toBe(true);
      expect(isEmpty('null')).toBe(true);
      expect(isEmpty('undefined')).toBe(true);
    });

    test('should detect empty arrays', () => {
      expect(isEmpty([])).toBe(true);
      expect(isEmpty([null, undefined, ''])).toBe(true);
    });

    test('should detect empty objects', () => {
      expect(isEmpty({})).toBe(true);
    });

    test('should detect falsy values', () => {
      expect(isEmpty(null)).toBe(true);
      expect(isEmpty(undefined)).toBe(true);
      expect(isEmpty(0)).toBe(true);
      expect(isEmpty(false)).toBe(true);
    });

    test('should detect non-empty values', () => {
      expect(isEmpty('hello')).toBe(false);
      expect(isEmpty([1, 2, 3])).toBe(false);
      expect(isEmpty({ a: 1 })).toBe(false);
      expect(isEmpty(1)).toBe(false);
      expect(isEmpty(true)).toBe(false);
    });
  });

  describe('stripProtocol', () => {
    test('should strip http protocol', () => {
      expect(stripProtocol('http://example.com')).toBe('example.com');
    });

    test('should strip https protocol', () => {
      expect(stripProtocol('https://example.com')).toBe('example.com');
    });

    test('should strip whois protocol', () => {
      expect(stripProtocol('whois://example.com')).toBe('example.com');
    });

    test('should handle strings without protocol', () => {
      expect(stripProtocol('example.com')).toBe('example.com');
    });

    test('should trim whitespace', () => {
      expect(stripProtocol('  https://example.com  ')).toBe('example.com');
    });
  });

  describe('sanitizeString', () => {
    test('should remove null bytes', () => {
      expect(sanitizeString('hello\u0000world')).toBe('helloworld');
    });

    test('should remove control characters', () => {
      expect(sanitizeString('hello\x01world')).toBe('helloworld');
      expect(sanitizeString('hello\x7Fworld')).toBe('helloworld');
    });

    test('should trim whitespace', () => {
      expect(sanitizeString('  hello  ')).toBe('hello');
    });

    test('should preserve normal strings', () => {
      expect(sanitizeString('example.com')).toBe('example.com');
    });
  });
});
