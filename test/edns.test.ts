import { EDNS_OPTIONS } from '../src/constants';
import {
  parsePacketOptions,
  parseExtendedDnsErrors,
  parseEdnsOptions,
  parseEdnsOption,
} from '../src/edns';
import type {
  PacketAnswer,
  DnsExtendedErrors,
  EdnsNsid,
  EdnsClientSubnet,
  EdnsCookie,
  EdnsTcpKeepAlive,
  EdnsPadding,
  EdnsDnssecCapability,
  EdnsKeyTag,
  RawEdnsOption,
  OptRecord,
} from '../src/types';

// Helper functions to create valid test PacketAnswer objects
const createOptAnswer = (options: RawEdnsOption[] = []): PacketAnswer => {
  const optAnswer = {
    type: 'OPT' as const,
    name: '.',
    udpPayloadSize: 4096,
    extendedRcode: 0,
    ednsVersion: 0,
    flags: 0,
    flag_do: false,
    options,
  };
  return optAnswer as unknown as PacketAnswer;
};

const createAAnswer = (name = 'example.com', data = '192.0.2.1'): PacketAnswer => ({
  type: 'A',
  name,
  ttl: 300,
  data,
});

// Helper function that converts incomplete OPT records to proper PacketAnswers and calls parsePacketOptions
const parseTestPacketOptions = (additionals: unknown[]): OptRecord[] => {
  const properAdditionals = additionals.map(additional => {
    const opt = additional as { type?: string; udpPayloadSize?: number; options?: RawEdnsOption[] };
    // If it's an incomplete OPT record, convert it using createOptAnswer
    if (opt.type === 'OPT' && !opt.udpPayloadSize) {
      return createOptAnswer(opt.options || []);
    }
    return additional as PacketAnswer;
  });
  return parsePacketOptions(properAdditionals as unknown as PacketAnswer[]);
};

describe('EDNS Functions', () => {
  describe('parsePacketOptions', () => {
    test('should parse OPT records from additionals', () => {
      const additionals = [
        createOptAnswer([
          {
            code: 8, // CLIENT_SUBNET
            data: Buffer.from([0x00, 0x01, 0x18, 0x00, 0xc0, 0x00, 0x02]),
          },
        ]),
        createAAnswer(),
      ];

      const result = parsePacketOptions(additionals);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        type: 'OPT',
        name: '.',
        udp_payload_size: 4096,
        extended_rcode: 0,
        edns_version: 0,
        flags: 0,
        flag_do: false,
        options: [
          {
            code: 8,
            data: Buffer.from([0x00, 0x01, 0x18, 0x00, 0xc0, 0x00, 0x02]),
          },
        ],
      });
    });

    test('should handle wrapped data format', () => {
      const additionals = [
        createOptAnswer([
          {
            code: 15,
            data: {
              data: Buffer.from([0, 1, 116, 101, 115, 116]), // 'test' as bytes
            } as unknown as Buffer,
          },
        ]),
      ];

      const result = parsePacketOptions(additionals);
      expect(result[0].options[0].data).toEqual(Buffer.from([0, 1, 116, 101, 115, 116]));
    });

    test('should filter out non-OPT records', () => {
      const additionals = [
        createAAnswer('example.com', '192.0.2.1'),
        createOptAnswer([]),
        { type: 'AAAA', name: 'example.com', ttl: 300, data: '2001:db8::1' } as PacketAnswer,
      ];

      const result = parsePacketOptions(additionals);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('OPT');
    });
  });
  describe('parseExtendedDnsErrors', () => {
    test('should parse extended DNS errors from OPT record', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: 15, // EDE option code
              data: Buffer.concat([
                Buffer.from([0, 1]), // Error code 1 (Unsupported DNSKEY Algorithm)
                Buffer.from('Algorithm not supported', 'utf8'), // Error text
              ]),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      const expected: DnsExtendedErrors = {
        1: 'Algorithm not supported',
      };

      expect(result).toEqual(expected);
    });

    test('should parse multiple extended DNS errors', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: 15,
              data: Buffer.concat([
                Buffer.from([0, 1]), // Error code 1
                Buffer.from('First error', 'utf8'),
              ]),
            },
            {
              code: 15,
              data: Buffer.concat([
                Buffer.from([0, 6]), // Error code 6 (DNSSEC Bogus)
                Buffer.from('DNSSEC validation failed', 'utf8'),
              ]),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      const expected: DnsExtendedErrors = {
        1: 'First error',
        6: 'DNSSEC validation failed',
      };

      expect(result).toEqual(expected);
    });

    test('should use default error message when no error text provided', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: 15,
              data: Buffer.from([0, 3]), // Error code 3 (Stale Answer), no text
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      const expected: DnsExtendedErrors = {
        3: 'Stale Answer', // Should use default from EXTENDED_DNS_ERRORS
      };

      expect(result).toEqual(expected);
    });

    test('should handle non-Buffer data gracefully', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: 15,
              data: {
                data: Buffer.concat([
                  Buffer.from([0, 5]), // Error code 5
                  Buffer.from('Wrapped buffer', 'utf8'),
                ]),
              },
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      expect(result[5]).toBe('Wrapped buffer');
    });

    test('should ignore unknown error codes', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: 15,
              data: Buffer.from([99, 99]), // Unknown error code 25443
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      expect(result).toEqual({});
    });

    test('should ignore non-OPT records', () => {
      const additionals = [
        {
          type: 'A',
          data: '192.0.2.1',
        },
        {
          type: 'TXT',
          data: 'some text',
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      expect(result).toEqual({});
    });

    test('should ignore OPT records without options', () => {
      const additionals = [
        {
          type: 'OPT',
          udpPayloadSize: 4096,
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseExtendedDnsErrors(packetOptions);
      expect(result).toEqual({});
    });

    test('should handle empty additionals array', () => {
      const result = parseExtendedDnsErrors([]);
      expect(result).toEqual({});
    });

    test('should handle null/undefined additionals', () => {
      const packetOptionsNull = parsePacketOptions(null as unknown as PacketAnswer[]);
      const packetOptionsUndefined = parsePacketOptions(undefined as unknown as PacketAnswer[]);
      expect(parseExtendedDnsErrors(packetOptionsNull)).toEqual({});
      expect(parseExtendedDnsErrors(packetOptionsUndefined)).toEqual({});
    });
  });

  describe('parseEdnsOptions', () => {
    test('should parse NSID option', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.NSID,
              data: Buffer.from('ns1.example.com', 'utf8'),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.NSID,
        nsid: 'ns1.example.com',
      } as EdnsNsid);
    });

    test('should parse CLIENT_SUBNET option', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.CLIENT_SUBNET,
              data: Buffer.concat([
                Buffer.from([0, 1]), // family = 1 (IPv4)
                Buffer.from([24]), // source prefix length = 24
                Buffer.from([0]), // scope prefix length = 0
                Buffer.from([192, 0, 2]), // IP address bytes (192.0.2.0/24)
              ]),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.CLIENT_SUBNET,
        family: 1, // IPv4
        sourcePrefixLength: 24,
        scopePrefixLength: 0,
        ip: '192.0.2.0',
      } as EdnsClientSubnet);
    });

    test('should parse COOKIE option', () => {
      const clientCookie = Buffer.from('1234567890abcdef', 'hex'); // 8 bytes
      const serverCookie = Buffer.from('fedcba0987654321', 'hex'); // 8 bytes
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.COOKIE,
              data: Buffer.concat([clientCookie, serverCookie]),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.COOKIE,
        clientCookie: '1234567890abcdef',
        serverCookie: 'fedcba0987654321',
        valid: true,
      } as EdnsCookie);
    });

    test('should parse TCP_KEEPALIVE option', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.TCP_KEEPALIVE,
              data: Buffer.from([0, 100]), // 100 centiseconds
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.TCP_KEEPALIVE,
        timeout: 100,
        unit: 'centiseconds',
      } as EdnsTcpKeepAlive);
    });

    test('should parse PADDING option', () => {
      const paddingData = Buffer.alloc(32, 0); // 32 bytes of padding
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.PADDING,
              data: paddingData,
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.PADDING,
        paddingLength: 32,
        purpose: 'Traffic analysis protection',
      } as EdnsPadding);
    });

    test('should parse DNSSEC capability options (DAU, DHU, N3U)', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.DAU,
              data: Buffer.from([7, 8, 10]), // DNSSEC algorithms
            },
            {
              code: EDNS_OPTIONS.DHU,
              data: Buffer.from([1, 2]), // DS hash algorithms
            },
            {
              code: EDNS_OPTIONS.N3U,
              data: Buffer.from([1]), // NSEC3 hash algorithms
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(3);

      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.DAU,
        algorithms: [7, 8, 10],
        algorithmType: 'DNSSEC algorithms',
      } as EdnsDnssecCapability);

      expect(result[1]).toEqual({
        code: EDNS_OPTIONS.DHU,
        algorithms: [1, 2],
        algorithmType: 'DS hash algorithms',
      } as EdnsDnssecCapability);

      expect(result[2]).toEqual({
        code: EDNS_OPTIONS.N3U,
        algorithms: [1],
        algorithmType: 'NSEC3 hash algorithms',
      } as EdnsDnssecCapability);
    });

    test('should parse KEY_TAG option', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.KEY_TAG,
              data: Buffer.concat([
                Buffer.from([0x30, 0x39]), // Key tag 12345
                Buffer.from([0x67, 0x89]), // Key tag 26505
              ]),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        code: EDNS_OPTIONS.KEY_TAG,
        tags: [12345, 26505],
      } as EdnsKeyTag);
    });

    test('should parse multiple options from single OPT record', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: EDNS_OPTIONS.NSID,
              data: Buffer.from('server1', 'utf8'),
            },
            {
              code: EDNS_OPTIONS.PADDING,
              data: Buffer.alloc(16, 0),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(2);
      expect(result[0].code).toBe(EDNS_OPTIONS.NSID);
      expect(result[1].code).toBe(EDNS_OPTIONS.PADDING);
    });

    test('should ignore unknown option codes', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [
            {
              code: 9999, // Unknown option code
              data: Buffer.from('unknown'),
            },
            {
              code: EDNS_OPTIONS.NSID,
              data: Buffer.from('known', 'utf8'),
            },
          ],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toHaveLength(1);
      expect(result[0].code).toBe(EDNS_OPTIONS.NSID);
    });

    test('should handle empty options array', () => {
      const additionals = [
        {
          type: 'OPT',
          options: [],
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toEqual([]);
    });

    test('should ignore non-OPT records', () => {
      const additionals = [
        {
          type: 'A',
          data: '192.0.2.1',
        },
      ];

      const packetOptions = parseTestPacketOptions(additionals);
      const result = parseEdnsOptions(packetOptions);
      expect(result).toEqual([]);
    });
  });

  describe('parseEdnsOption', () => {
    test('should parse NSID with printable text', () => {
      const opt = {
        code: EDNS_OPTIONS.NSID,
        data: Buffer.from('ns1.example.com', 'utf8'),
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.NSID,
        nsid: 'ns1.example.com',
      } as EdnsNsid);
    });

    test('should parse NSID with non-printable data as hex', () => {
      const opt = {
        code: EDNS_OPTIONS.NSID,
        data: Buffer.from([0x01, 0x02, 0x03, 0x04]),
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.NSID,
        nsid: '01020304',
      } as EdnsNsid);
    });

    test('should handle CLIENT_SUBNET with IPv6', () => {
      const opt = {
        code: EDNS_OPTIONS.CLIENT_SUBNET,
        data: Buffer.concat([
          Buffer.from([0, 2]), // family = 2 (IPv6)
          Buffer.from([64]), // source prefix length = 64
          Buffer.from([0]), // scope prefix length = 0
          Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]), // 2001:db8::/64
        ]),
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.CLIENT_SUBNET,
        family: 2, // IPv6
        sourcePrefixLength: 64,
        scopePrefixLength: 0,
        ip: '20010db800000000',
      } as EdnsClientSubnet);
    });

    test('should handle CLIENT_SUBNET with insufficient data', () => {
      const opt = {
        code: EDNS_OPTIONS.CLIENT_SUBNET,
        data: Buffer.from([0, 1]), // Only 2 bytes, need at least 4
      };

      const result = parseEdnsOption(opt);
      expect(result).toBeNull();
    });

    test('should handle COOKIE with only client cookie', () => {
      const opt = {
        code: EDNS_OPTIONS.COOKIE,
        data: Buffer.from('1234567890abcdef', 'hex'), // Exactly 8 bytes (client cookie only)
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.COOKIE,
        clientCookie: '1234567890abcdef',
        serverCookie: null,
        valid: false, // No server cookie
      } as EdnsCookie);
    });

    test('should handle COOKIE with insufficient data', () => {
      const opt = {
        code: EDNS_OPTIONS.COOKIE,
        data: Buffer.from([1, 2, 3]), // Less than 8 bytes
      };

      const result = parseEdnsOption(opt);
      expect(result).toBeNull();
    });

    test('should handle TCP_KEEPALIVE with wrong data length', () => {
      const opt = {
        code: EDNS_OPTIONS.TCP_KEEPALIVE,
        data: Buffer.from([1]), // Should be 2 bytes
      };

      const result = parseEdnsOption(opt);
      expect(result).toBeNull();
    });

    test('should handle KEY_TAG with odd number of bytes', () => {
      const opt = {
        code: EDNS_OPTIONS.KEY_TAG,
        data: Buffer.from([0x30, 0x39, 0x67]), // 3 bytes, incomplete last tag
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.KEY_TAG,
        tags: [12345], // Only complete tags
      } as EdnsKeyTag);
    });

    test('should handle KEY_TAG with empty data', () => {
      const opt = {
        code: EDNS_OPTIONS.KEY_TAG,
        data: Buffer.alloc(0),
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.KEY_TAG,
        tags: [],
      } as EdnsKeyTag);
    });

    test('should return null for unknown option codes', () => {
      const opt = {
        code: 9999,
        data: Buffer.from('unknown'),
      };

      const result = parseEdnsOption(opt);
      expect(result).toBeNull();
    });

    test('should handle NSID parsing errors gracefully', () => {
      const mockData = {
        toString: jest.fn((encoding: string) => {
          if (encoding === 'utf8') {
            throw new Error('UTF8 conversion error');
          }
          if (encoding === 'hex') {
            return 'deadbeef'; // Fallback hex representation
          }
          throw new Error('Unknown encoding');
        }),
      };

      const opt = {
        code: EDNS_OPTIONS.NSID,
        data: mockData as unknown as Buffer,
      };

      const result = parseEdnsOption(opt);
      expect(result).toEqual({
        code: EDNS_OPTIONS.NSID,
        nsid: 'deadbeef', // Should fall back to hex
      } as EdnsNsid);
      expect(mockData.toString).toHaveBeenCalledWith('utf8');
      expect(mockData.toString).toHaveBeenCalledWith('hex');
    });
  });
});
