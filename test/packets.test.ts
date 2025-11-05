import {
  createDnsPacket,
  getQueryFlagsBitmask,
  parsePacketAnswer,
  createGenericRecord,
  parseDnssecAlgorithm,
  parseRawCdnskeyRecord,
  parseRawCdsRecord,
  parseRawNsec3paramRecord,
  parseRawTsigRecord,
  parseRawCertRecord,
  parseRawKeyRecord,
  parseRawSigRecord,
  parseRawUriRecord,
  parseRawLocRecord,
} from '../src/packets';
import {
  FLAG_RECURSION_DESIRED,
  FLAG_CHECKING_DISABLED,
  FLAG_DNSSEC_OK,
  DNS_FLAGS,
  DNSKEY_RECORD,
  DS_RECORD,
  HINFO_RECORD,
  NAPTR_RECORD,
  NSEC_RECORD,
  NSEC3_RECORD,
  RP_RECORD,
  RRSIG_RECORD,
  SSHFP_RECORD,
  TLSA_RECORD,
  DNAME_RECORD,
  OPT_RECORD,
  TXT_RECORD,
  CDNSKEY_RECORD,
  CDS_RECORD,
  NSEC3PARAM_RECORD,
  TSIG_RECORD,
  CERT_RECORD,
  KEY_RECORD,
  SIG_RECORD,
  URI_RECORD,
  LOC_RECORD,
} from '../src/constants';
import { ParsingError } from '../src/errors';
import type { DnsQuestion, PacketAnswer, DnsRecordType } from '../src/types';

describe('DNS Packet Functions', () => {
  describe('getQueryFlagsBitmask', () => {
    test('should create bitmask for RD flag', () => {
      const mask = getQueryFlagsBitmask([FLAG_RECURSION_DESIRED]);
      expect(mask).toBe(DNS_FLAGS.RD);
    });

    test('should exclude DO flag from bitmask', () => {
      const mask = getQueryFlagsBitmask([FLAG_DNSSEC_OK]);
      expect(mask).toBe(0);
    });

    test('should combine multiple flags', () => {
      const mask = getQueryFlagsBitmask([FLAG_RECURSION_DESIRED, FLAG_CHECKING_DISABLED]);
      expect(mask).toBe(DNS_FLAGS.RD | DNS_FLAGS.CD);
    });
  });

  describe('createDnsPacket', () => {
    test('should create packet with DNSSEC_OK flag', () => {
      const question: DnsQuestion = {
        query: 'example.com',
        type: 'A',
        server: '1.1.1.1',
        flags: [FLAG_DNSSEC_OK, FLAG_RECURSION_DESIRED],
      };
      const packet = createDnsPacket(question);
      expect(Buffer.isBuffer(packet)).toBe(true);
      expect(packet.length).toBeGreaterThan(0);
    });

    test('should create packet without DNSSEC_OK flag', () => {
      const question: DnsQuestion = {
        query: 'example.com',
        type: 'A',
        server: '1.1.1.1',
        flags: [FLAG_RECURSION_DESIRED],
      };
      const packet = createDnsPacket(question);
      expect(Buffer.isBuffer(packet)).toBe(true);
    });

    test('should include EDNS options', () => {
      const question: DnsQuestion = {
        query: 'test.com',
        type: 'AAAA',
        server: '8.8.8.8',
        flags: [],
      };
      const packet = createDnsPacket(question);
      expect(packet.length).toBeGreaterThan(12); // DNS header is 12 bytes
    });
  });

  describe('parsePacketAnswer', () => {
    test('should parse A record', () => {
      const answer: PacketAnswer = {
        type: 'A',
        name: 'example.com',
        ttl: 300,
        data: '192.0.2.1',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toEqual({
        name: 'example.com',
        ttl: 300,
        type: 'A',
        class: 'IN',
        address: '192.0.2.1',
      });
    });

    test('should parse AAAA record', () => {
      const answer: PacketAnswer = {
        type: 'AAAA',
        name: 'example.com',
        ttl: 300,
        data: '2001:db8::1',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toEqual({
        name: 'example.com',
        ttl: 300,
        type: 'AAAA',
        class: 'IN',
        address: '2001:db8::1',
      });
    });

    test('should parse CNAME record', () => {
      const answer: PacketAnswer = {
        type: 'CNAME',
        name: 'www.example.com',
        ttl: 300,
        data: 'example.com',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toEqual({
        name: 'www.example.com',
        ttl: 300,
        type: 'CNAME',
        class: 'IN',
        value: 'example.com',
      });
    });

    test('should parse MX record', () => {
      const answer: PacketAnswer = {
        type: 'MX',
        name: 'example.com',
        ttl: 300,
        data: { preference: 10, exchange: 'mail.example.com' },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: 'MX',
        priority: 10,
        exchange: 'mail.example.com',
      });
    });

    test('should parse NS record', () => {
      const answer: PacketAnswer = {
        type: 'NS',
        name: 'example.com',
        ttl: 300,
        data: 'ns1.example.com',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toEqual({
        name: 'example.com',
        ttl: 300,
        type: 'NS',
        class: 'IN',
        value: 'ns1.example.com',
      });
    });

    test('should parse PTR record', () => {
      const answer: PacketAnswer = {
        type: 'PTR',
        name: '1.2.0.192.in-addr.arpa',
        ttl: 300,
        data: 'example.com',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toEqual({
        name: '1.2.0.192.in-addr.arpa',
        ttl: 300,
        type: 'PTR',
        class: 'IN',
        value: 'example.com',
      });
    });

    test('should parse TXT record', () => {
      const answer: PacketAnswer = {
        type: 'TXT',
        name: 'example.com',
        ttl: 300,
        data: Buffer.from('v=spf1 -all'),
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: 'TXT',
        value: 'v=spf1 -all',
      });
    });

    test('should parse SOA record', () => {
      const answer: PacketAnswer = {
        type: 'SOA',
        name: 'example.com',
        ttl: 300,
        data: {
          mname: 'ns1.example.com',
          rname: 'admin.example.com',
          serial: 2021010101,
          refresh: 7200,
          retry: 3600,
          expire: 1209600,
          minimum: 300,
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: 'SOA',
        nsname: 'ns1.example.com',
        hostmaster: 'admin.example.com',
        serial: 2021010101,
      });
    });

    test('should parse SRV record', () => {
      const answer: PacketAnswer = {
        type: 'SRV',
        name: '_http._tcp.example.com',
        ttl: 300,
        data: {
          priority: 10,
          weight: 5,
          port: 80,
          target: 'server.example.com',
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: 'SRV',
        priority: 10,
        weight: 5,
        port: 80,
        target: 'server.example.com',
      });
    });

    test('should parse CAA record', () => {
      const answer: PacketAnswer = {
        type: 'CAA',
        name: 'example.com',
        ttl: 300,
        data: {
          flags: 0,
          tag: 'issue',
          value: 'letsencrypt.org',
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: 'CAA',
        flags: 0,
        tag: 'issue',
        value: 'letsencrypt.org',
      });
    });

    test('should parse DNSKEY record', () => {
      const answer: PacketAnswer = {
        type: DNSKEY_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          flags: 256,
          algorithm: 13,
          key: Buffer.from('test-key-data'),
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: DNSKEY_RECORD,
        flags: 256,
        protocol: 3,
        algorithm: 13,
      });
      expect(result).toHaveProperty('public_key');
    });

    test('should parse DS record', () => {
      const answer: PacketAnswer = {
        type: DS_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          keyTag: 12345,
          algorithm: 13,
          digestType: 2,
          digest: Buffer.from('abc123', 'hex'),
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: DS_RECORD,
        key_tag: 12345,
        algorithm: 13,
        digest_type: 2,
      });
      expect(result).toHaveProperty('digest');
    });

    test('should parse HINFO record', () => {
      const answer: PacketAnswer = {
        type: HINFO_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          cpu: 'x86-64',
          os: 'Linux',
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: HINFO_RECORD,
        cpu: 'x86-64',
        os: 'Linux',
      });
    });

    test('should parse NAPTR record', () => {
      const answer: PacketAnswer = {
        type: NAPTR_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          order: 100,
          preference: 10,
          flags: 'u',
          services: 'sip+E2U',
          regexp: '',
          replacement: 'example.com',
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: NAPTR_RECORD,
        order: 100,
        preference: 10,
        flags: 'u',
        service: 'sip+E2U',
        replacement: 'example.com',
      });
    });

    test('should parse NSEC record', () => {
      const answer: PacketAnswer = {
        type: NSEC_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          nextDomain: 'next.example.com',
          rrtypes: ['A', 'AAAA', 'MX'],
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: NSEC_RECORD,
        next_domain: 'next.example.com',
        rr_types: ['A', 'AAAA', 'MX'],
      });
    });

    test('should parse NSEC3 record', () => {
      const answer: PacketAnswer = {
        type: NSEC3_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          algorithm: 1,
          flags: 0,
          iterations: 5,
          salt: Buffer.from('salt', 'hex'),
          nextDomain: Buffer.from('next'),
          rrtypes: ['A', 'AAAA'],
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: NSEC3_RECORD,
        algorithm: 1,
        flags: 0,
        iterations: 5,
        rr_types: ['A', 'AAAA'],
      });
      expect(result).toHaveProperty('salt');
      expect(result).toHaveProperty('next_domain');
    });

    test('should parse RP record', () => {
      const answer: PacketAnswer = {
        type: RP_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          mbox: 'admin.example.com',
          txt: 'contact.example.com',
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: RP_RECORD,
        mbox: 'admin.example.com',
        txt: 'contact.example.com',
      });
    });

    test('should parse RRSIG record', () => {
      const answer: PacketAnswer = {
        type: RRSIG_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          typeCovered: 'A',
          algorithm: 13,
          labels: 2,
          originalTTL: 300,
          expiration: 1234567890,
          inception: 1234567800,
          keyTag: 12345,
          signersName: 'example.com',
          signature: Buffer.from('signature-data'),
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: RRSIG_RECORD,
        type_covered: 'A',
        algorithm: 13,
        labels: 2,
        original_ttl: 300,
        key_tag: 12345,
        signer_name: 'example.com',
      });
      expect(result).toHaveProperty('signature');
    });

    test('should parse SSHFP record', () => {
      const answer: PacketAnswer = {
        type: SSHFP_RECORD,
        name: 'example.com',
        ttl: 300,
        data: {
          algorithm: 1,
          hash: 1,
          fingerprint: 'abc123def456',
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: SSHFP_RECORD,
        algorithm: 1,
        fp_type: 1,
        fingerprint: 'abc123def456',
      });
    });

    test('should parse TLSA record', () => {
      const answer: PacketAnswer = {
        type: TLSA_RECORD,
        name: '_443._tcp.example.com',
        ttl: 300,
        data: {
          usage: 3,
          selector: 1,
          matchingType: 1,
          certificate: Buffer.from('cert-data', 'hex'),
        },
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: TLSA_RECORD,
        usage: 3,
        selector: 1,
        mtype: 1,
      });
      expect(result).toHaveProperty('cert');
    });

    test('should parse DNAME record', () => {
      const answer: PacketAnswer = {
        type: DNAME_RECORD,
        name: 'example.com',
        ttl: 300,
        data: 'new.example.com',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toEqual({
        name: 'example.com',
        ttl: 300,
        type: DNAME_RECORD,
        class: 'IN',
        value: 'new.example.com',
      });
    });

    test('should parse TXT record with array data', () => {
      const answer: PacketAnswer = {
        type: TXT_RECORD,
        name: 'example.com',
        ttl: 300,
        data: [Buffer.from('v=spf1'), Buffer.from(' -all')],
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: TXT_RECORD,
        value: 'v=spf1 -all',
      });
    });

    test('should parse TXT record with string data', () => {
      const answer: PacketAnswer = {
        type: TXT_RECORD,
        name: 'example.com',
        ttl: 300,
        data: 'v=spf1 -all',
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: TXT_RECORD,
        value: 'v=spf1 -all',
      });
    });

    test('should return null for OPT record', () => {
      const answer = {
        type: OPT_RECORD,
        name: '',
        data: Buffer.from([]),
      } as unknown as PacketAnswer;
      const result = parsePacketAnswer(answer);
      expect(result).toBeNull();
    });

    test('should handle unknown record type with generic record fallback', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      const answer = {
        type: 'UNKNOWN_TYPE' as unknown as PacketAnswer['type'],
        name: 'example.com',
        ttl: 300,
        data: Buffer.from('test-data'),
      } as PacketAnswer;
      const result = parsePacketAnswer(answer);

      expect(consoleSpy).toHaveBeenCalledWith('Unknown record type: UNKNOWN_TYPE');
      expect(result).toBeDefined();
      expect(result).toHaveProperty('type', 'UNKNOWN_TYPE');
      expect(result).toHaveProperty('name', 'example.com');
      expect(result).toHaveProperty('ttl', 300);
      expect(result).toHaveProperty('data');

      consoleSpy.mockRestore();
    });

    test('should handle parsing errors with generic record fallback', () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      const answer = {
        type: 'DNSKEY' as PacketAnswer['type'],
        name: 'example.com',
        ttl: 300,
        data: null, // invalid data that will cause parsing to fail
      } as unknown as PacketAnswer;
      const result = parsePacketAnswer(answer);

      expect(consoleSpy).toHaveBeenCalled();
      expect(result).toBeDefined();
      expect(result).toHaveProperty('type');
      expect(result).toHaveProperty('name', 'example.com');
      expect(result).toHaveProperty('data');

      consoleSpy.mockRestore();
    });

    test('should create generic record for unknown type with Buffer data (hex encoding)', () => {
      const baseData = {
        name: 'example.com',
        type: 'UNKNOWN_TYPE' as DnsRecordType,
        ttl: 300,
      };
      const answer: PacketAnswer = {
        type: 'UNKNOWN_TYPE' as unknown as PacketAnswer['type'],
        name: 'example.com',
        ttl: 300,
        data: Buffer.from([0x01, 0x02, 0x03, 0x04]),
      } as PacketAnswer;
      const result = createGenericRecord(baseData, answer);

      expect(result).toMatchObject({
        type: 'UNKNOWN_TYPE',
        name: 'example.com',
        ttl: 300,
      });
      expect((result as { data?: string }).data).toBe('01020304'); // hex encoded
    });

    test('should create generic record for unknown type with string data', () => {
      const baseData = {
        name: 'example.com',
        type: 'UNKNOWN_TYPE' as DnsRecordType,
        ttl: 300,
      };
      const answer: PacketAnswer = {
        type: 'UNKNOWN_TYPE' as unknown as PacketAnswer['type'],
        name: 'example.com',
        ttl: 300,
        data: 'test-string',
      } as PacketAnswer;
      const result = createGenericRecord(baseData, answer);

      expect(result).toMatchObject({
        type: 'UNKNOWN_TYPE',
        name: 'example.com',
        ttl: 300,
      });
      expect((result as { data?: string }).data).toBe('test-string');
    });

    test('should create generic record for text record type with Buffer (UTF-8 encoding)', () => {
      const baseData = {
        name: 'example.com',
        type: 'TXT' as DnsRecordType,
        ttl: 300,
      };
      const answer: PacketAnswer = {
        type: 'TXT' as PacketAnswer['type'],
        name: 'example.com',
        ttl: 300,
        data: Buffer.from('test-text', 'utf8'),
      } as PacketAnswer;
      // simulate unknown type by using createGenericRecord directly
      const result = createGenericRecord(baseData, answer);

      expect(result).toMatchObject({
        type: 'TXT',
        name: 'example.com',
        ttl: 300,
      });
      // text types should use UTF-8 encoding
      expect(typeof (result as { data?: string }).data).toBe('string');
    });

    test('should handle invalid data gracefully', () => {
      const answer = {
        type: 'TXT',
        name: 'example.com',
        ttl: 300,
        data: null,
      } as unknown as PacketAnswer;
      const result = parsePacketAnswer(answer);
      // should handle invalid data gracefully via generic record fallback
      expect(result).toBeDefined();
      expect(result).toHaveProperty('type');
      expect(result).toHaveProperty('name', 'example.com');
    });

    test('should parse CDNSKEY record via parsePacketAnswer', () => {
      const buffer = Buffer.alloc(20);
      buffer.writeUInt16BE(256, 0); // flags
      buffer[2] = 3; // protocol
      buffer[3] = 13; // algorithm
      buffer.write('test-key-data', 4, 'utf8'); // public key

      const answer: PacketAnswer = {
        type: CDNSKEY_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: CDNSKEY_RECORD,
        flags: 256,
        protocol: 3,
        algorithm: 13,
      });
      expect(result).toHaveProperty('public_key');
    });

    test('should parse CDS record via parsePacketAnswer', () => {
      const buffer = Buffer.alloc(10);
      buffer.writeUInt16BE(12345, 0); // key_tag
      buffer[2] = 13; // algorithm
      buffer[3] = 2; // digest_type
      buffer.write('abc123', 4, 'hex'); // digest

      const answer: PacketAnswer = {
        type: CDS_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: CDS_RECORD,
        key_tag: 12345,
        algorithm: 13,
        digest_type: 2,
      });
      expect(result).toHaveProperty('digest');
    });

    test('should parse NSEC3PARAM record via parsePacketAnswer', () => {
      const buffer = Buffer.alloc(10);
      buffer[0] = 1; // algorithm
      buffer[1] = 0; // flags
      buffer.writeUInt16BE(5, 2); // iterations
      buffer[4] = 4; // salt length
      buffer.write('salt', 5, 'hex'); // salt

      const answer: PacketAnswer = {
        type: NSEC3PARAM_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: NSEC3PARAM_RECORD,
        algorithm: 1,
        flags: 0,
        iterations: 5,
      });
      expect(result).toHaveProperty('salt');
    });

    test('should parse TSIG record via parsePacketAnswer', () => {
      // algorithm name: "hmac-sha256" (11 bytes + null terminator = 12 bytes)
      const algorithmName = Buffer.from([11, ...Buffer.from('hmac-sha256'), 0]);
      const buffer = Buffer.alloc(algorithmName.length + 20);
      algorithmName.copy(buffer, 0);
      let offset = algorithmName.length;

      // time_signed (6 bytes)
      buffer[offset] = 0;
      buffer[offset + 1] = 0;
      buffer[offset + 2] = 0x12;
      buffer[offset + 3] = 0x34;
      buffer[offset + 4] = 0x56;
      buffer[offset + 5] = 0x78;
      offset += 6;

      // fudge (2 bytes)
      buffer.writeUInt16BE(300, offset);
      offset += 2;

      // mac_size (2 bytes)
      buffer.writeUInt16BE(4, offset);
      offset += 2;

      // mac (4 bytes)
      buffer.write('MAC1', offset, 'utf8');
      offset += 4;

      // original_id (2 bytes)
      buffer.writeUInt16BE(1234, offset);
      offset += 2;

      // error (2 bytes)
      buffer.writeUInt16BE(0, offset);
      offset += 2;

      // other_len (2 bytes)
      buffer.writeUInt16BE(0, offset);

      const answer: PacketAnswer = {
        type: TSIG_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: TSIG_RECORD,
        algorithm: 'hmac-sha256',
        fudge: 300,
        mac_size: 4,
        original_id: 1234,
        error: 0,
        other_len: 0,
      });
      expect(result).toHaveProperty('mac');
    });

    test('should parse CERT record via parsePacketAnswer', () => {
      const buffer = Buffer.alloc(15);
      buffer.writeUInt16BE(1, 0); // certificate_type
      buffer.writeUInt16BE(12345, 2); // key_tag
      buffer[4] = 13; // algorithm
      buffer.write('cert-data', 5, 'utf8'); // certificate

      const answer: PacketAnswer = {
        type: CERT_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: CERT_RECORD,
        certificate_type: '1',
        key_tag: 12345,
        algorithm: 13,
      });
      expect(result).toHaveProperty('certificate');
    });

    test('should parse KEY record via parsePacketAnswer', () => {
      const buffer = Buffer.alloc(20);
      buffer.writeUInt16BE(256, 0); // flags
      buffer[2] = 3; // protocol
      buffer[3] = 13; // algorithm
      buffer.write('key-data', 4, 'utf8'); // public key

      const answer: PacketAnswer = {
        type: KEY_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: KEY_RECORD,
        flags: 256,
        protocol: 3,
        algorithm: 13,
      });
      expect(result).toHaveProperty('public_key');
    });

    test('should parse SIG record via parsePacketAnswer', () => {
      // SIG record: type_covered (2) + algorithm (1) + labels (1) + original_ttl (4) +
      // signature_expiration (4) + signature_inception (4) + key_tag (2) + signer_name + signature
      const signerName = Buffer.from([7, ...Buffer.from('example'), 3, ...Buffer.from('com'), 0]);
      const signature = Buffer.from('signature-data');
      const buffer = Buffer.alloc(18 + signerName.length + signature.length);

      buffer.writeUInt16BE(1, 0); // type_covered (A = 1)
      buffer[2] = 13; // algorithm
      buffer[3] = 2; // labels
      buffer.writeUInt32BE(300, 4); // original_ttl
      buffer.writeUInt32BE(1234567890, 8); // signature_expiration
      buffer.writeUInt32BE(1234567800, 12); // signature_inception
      buffer.writeUInt16BE(12345, 16); // key_tag
      signerName.copy(buffer, 18);
      signature.copy(buffer, 18 + signerName.length);

      const answer: PacketAnswer = {
        type: SIG_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: SIG_RECORD,
        type_covered: '1',
        algorithm: 13,
        labels: 2,
        original_ttl: 300,
        key_tag: 12345,
        signer_name: 'example.com',
      });
      expect(result).toHaveProperty('signature');
    });

    test('should parse URI record via parsePacketAnswer', () => {
      const target = 'https://example.com';
      const buffer = Buffer.alloc(4 + target.length);
      buffer.writeUInt16BE(10, 0); // priority
      buffer.writeUInt16BE(5, 2); // weight
      buffer.write(target, 4, 'utf8'); // target

      const answer: PacketAnswer = {
        type: URI_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: URI_RECORD,
        priority: 10,
        weight: 5,
        target: target,
      });
    });

    test('should parse LOC record via parsePacketAnswer', () => {
      const buffer = Buffer.alloc(16);
      buffer[0] = 0; // version
      buffer[1] = 0x12; // size (mantissa=1, exponent=2)
      buffer[2] = 0x34; // horiz_pre (mantissa=3, exponent=4)
      buffer[3] = 0x56; // vert_pre (mantissa=5, exponent=6)
      // latitude: 37.7749 degrees = 135914640 thousandths of arc seconds
      const latThousandths = 135914640 + 0x80000000;
      buffer.writeUInt32BE(latThousandths, 4);
      // longitude: -122.4194 degrees = -440698400 thousandths of arc seconds
      const lonThousandths = -440698400 + 0x80000000;
      buffer.writeUInt32BE(lonThousandths, 8);
      // altitude: 100 meters = 10000 cm + 10000000 (reference)
      buffer.writeUInt32BE(10000000 + 10000, 12);

      const answer: PacketAnswer = {
        type: LOC_RECORD,
        name: 'example.com',
        ttl: 300,
        data: buffer,
      };
      const result = parsePacketAnswer(answer);
      expect(result).toMatchObject({
        type: LOC_RECORD,
        version: 0,
      });
      expect(typeof (result as { latitude?: number }).latitude).toBe('number');
      expect(typeof (result as { longitude?: number }).longitude).toBe('number');
      expect(typeof (result as { altitude?: number }).altitude).toBe('number');
      expect(result).toHaveProperty('size');
      expect(result).toHaveProperty('horiz_pre');
      expect(result).toHaveProperty('vert_pre');
    });
  });

  describe('parseDnssecAlgorithm', () => {
    test('should parse numeric algorithm', () => {
      expect(parseDnssecAlgorithm('13', 'DNSKEY')).toBe(13);
      expect(parseDnssecAlgorithm('8', 'DS')).toBe(8);
    });

    test('should parse string mnemonic algorithms', () => {
      expect(parseDnssecAlgorithm('RSASHA1', 'DNSKEY')).toBe(5);
      expect(parseDnssecAlgorithm('RSASHA256', 'DS')).toBe(8);
      expect(parseDnssecAlgorithm('ECDSAP256SHA256', 'DNSKEY')).toBe(13);
      expect(parseDnssecAlgorithm('ED25519', 'DNSKEY')).toBe(15);
      expect(parseDnssecAlgorithm('ED448', 'DNSKEY')).toBe(16);
    });

    test('should throw error for unknown algorithm', () => {
      expect(() => parseDnssecAlgorithm('UNKNOWN_ALG', 'DNSKEY')).toThrow(ParsingError);
      expect(() => parseDnssecAlgorithm('UNKNOWN_ALG', 'DNSKEY')).toThrow(
        'Unknown DNSKEY algorithm'
      );
    });
  });

  describe('Raw record parsing functions', () => {
    describe('parseRawCdnskeyRecord', () => {
      test('should parse CDNSKEY record from buffer', () => {
        const buffer = Buffer.alloc(20);
        buffer.writeUInt16BE(256, 0); // flags
        buffer[2] = 3; // protocol
        buffer[3] = 13; // algorithm
        buffer.write('test-key', 4, 'utf8'); // public key

        const result = parseRawCdnskeyRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: CDNSKEY_RECORD,
          name: 'example.com',
          ttl: 300,
          flags: 256,
          protocol: 3,
          algorithm: 13,
        });
        expect(result.public_key).toBeTruthy();
      });
    });

    describe('parseRawCdsRecord', () => {
      test('should parse CDS record from buffer', () => {
        const digestHex = 'abc123';
        const digestLength = digestHex.length / 2; // 2 hex chars per byte
        const buffer = Buffer.alloc(4 + digestLength);
        buffer.writeUInt16BE(12345, 0); // key_tag
        buffer[2] = 13; // algorithm
        buffer[3] = 2; // digest_type
        buffer.write(digestHex, 4, 'hex'); // digest

        const result = parseRawCdsRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: CDS_RECORD,
          name: 'example.com',
          ttl: 300,
          key_tag: 12345,
          algorithm: 13,
          digest_type: 2,
        });
        expect(result.digest).toBe(digestHex.toLowerCase());
      });
    });

    describe('parseRawNsec3paramRecord', () => {
      test('should parse NSEC3PARAM record with salt', () => {
        const saltHex = 'abcd';
        const saltLength = saltHex.length / 2; // 2 hex chars per byte
        const buffer = Buffer.alloc(5 + saltLength);
        buffer[0] = 1; // algorithm
        buffer[1] = 0; // flags
        buffer.writeUInt16BE(5, 2); // iterations
        buffer[4] = saltLength; // salt length
        buffer.write(saltHex, 5, 'hex'); // salt

        const result = parseRawNsec3paramRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: NSEC3PARAM_RECORD,
          name: 'example.com',
          ttl: 300,
          algorithm: 1,
          flags: 0,
          iterations: 5,
          salt: saltHex.toLowerCase(),
        });
      });

      test('should parse NSEC3PARAM record without salt', () => {
        const buffer = Buffer.alloc(5);
        buffer[0] = 1; // algorithm
        buffer[1] = 0; // flags
        buffer.writeUInt16BE(5, 2); // iterations
        buffer[4] = 0; // salt length = 0

        const result = parseRawNsec3paramRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: NSEC3PARAM_RECORD,
          salt: '',
        });
      });

      test('should handle NSEC3PARAM with insufficient buffer length', () => {
        const buffer = Buffer.alloc(4); // too short for salt length byte
        buffer[0] = 1;
        buffer[1] = 0;
        buffer.writeUInt16BE(5, 2);

        const result = parseRawNsec3paramRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: NSEC3PARAM_RECORD,
          salt: '',
        });
      });
    });

    describe('parseRawTsigRecord', () => {
      test('should parse TSIG record', () => {
        const algorithmName = Buffer.from([11, ...Buffer.from('hmac-sha256'), 0]);
        const buffer = Buffer.alloc(algorithmName.length + 20);
        algorithmName.copy(buffer, 0);
        let offset = algorithmName.length;

        buffer[offset] = 0;
        buffer[offset + 1] = 0;
        buffer[offset + 2] = 0x12;
        buffer[offset + 3] = 0x34;
        buffer[offset + 4] = 0x56;
        buffer[offset + 5] = 0x78;
        offset += 6;

        buffer.writeUInt16BE(300, offset);
        offset += 2;

        buffer.writeUInt16BE(4, offset);
        offset += 2;

        buffer.write('MAC1', offset, 'utf8');
        offset += 4;

        buffer.writeUInt16BE(1234, offset);
        offset += 2;

        buffer.writeUInt16BE(0, offset);
        offset += 2;

        buffer.writeUInt16BE(0, offset);

        const result = parseRawTsigRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: TSIG_RECORD,
          name: 'example.com',
          ttl: 300,
          algorithm: 'hmac-sha256',
          fudge: 300,
          mac_size: 4,
          original_id: 1234,
          error: 0,
          other_len: 0,
          other_data: '',
        });
        expect(result.mac).toBeTruthy();
      });

      test('should parse TSIG record with other data', () => {
        const algorithmName = Buffer.from([11, ...Buffer.from('hmac-sha256'), 0]);
        const buffer = Buffer.alloc(algorithmName.length + 30);
        algorithmName.copy(buffer, 0);
        let offset = algorithmName.length;

        buffer[offset] = 0;
        buffer[offset + 1] = 0;
        buffer[offset + 2] = 0x12;
        buffer[offset + 3] = 0x34;
        buffer[offset + 4] = 0x56;
        buffer[offset + 5] = 0x78;
        offset += 6;

        buffer.writeUInt16BE(300, offset);
        offset += 2;

        buffer.writeUInt16BE(4, offset);
        offset += 2;

        buffer.write('MAC1', offset, 'utf8');
        offset += 4;

        buffer.writeUInt16BE(1234, offset);
        offset += 2;

        buffer.writeUInt16BE(0, offset);
        offset += 2;

        buffer.writeUInt16BE(4, offset);
        offset += 2;

        buffer.write('data', offset, 'utf8');

        const result = parseRawTsigRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          other_len: 4,
        });
        expect(typeof result.other_data).toBe('string');
      });

      test('should throw error for TSIG record too short', () => {
        const buffer = Buffer.alloc(10); // too short
        expect(() => parseRawTsigRecord('example.com', buffer, 300)).toThrow(ParsingError);
        expect(() => parseRawTsigRecord('example.com', buffer, 300)).toThrow(
          'TSIG record too short'
        );
      });

      test('should throw error for TSIG MAC data beyond buffer', () => {
        const algorithmName = Buffer.from([11, ...Buffer.from('hmac-sha256'), 0]);
        const buffer = Buffer.alloc(algorithmName.length + 20); // enough for header but not MAC
        algorithmName.copy(buffer, 0);
        let offset = algorithmName.length;

        buffer[offset] = 0;
        buffer[offset + 1] = 0;
        buffer[offset + 2] = 0x12;
        buffer[offset + 3] = 0x34;
        buffer[offset + 4] = 0x56;
        buffer[offset + 5] = 0x78;
        offset += 6;

        buffer.writeUInt16BE(300, offset);
        offset += 2;

        buffer.writeUInt16BE(100, offset); // MAC size too large
        offset += 2;

        expect(() => parseRawTsigRecord('example.com', buffer, 300)).toThrow(ParsingError);
        expect(() => parseRawTsigRecord('example.com', buffer, 300)).toThrow(
          'MAC data extends beyond buffer'
        );
      });

      test('should throw error for TSIG other data beyond buffer', () => {
        const algorithmName = Buffer.from([11, ...Buffer.from('hmac-sha256'), 0]);
        const buffer = Buffer.alloc(algorithmName.length + 20);
        algorithmName.copy(buffer, 0);
        let offset = algorithmName.length;

        buffer[offset] = 0;
        buffer[offset + 1] = 0;
        buffer[offset + 2] = 0x12;
        buffer[offset + 3] = 0x34;
        buffer[offset + 4] = 0x56;
        buffer[offset + 5] = 0x78;
        offset += 6;

        buffer.writeUInt16BE(300, offset);
        offset += 2;

        buffer.writeUInt16BE(4, offset);
        offset += 2;

        buffer.write('MAC1', offset, 'utf8');
        offset += 4;

        buffer.writeUInt16BE(1234, offset);
        offset += 2;

        buffer.writeUInt16BE(0, offset);
        offset += 2;

        buffer.writeUInt16BE(100, offset); // other_len too large

        expect(() => parseRawTsigRecord('example.com', buffer, 300)).toThrow(ParsingError);
        expect(() => parseRawTsigRecord('example.com', buffer, 300)).toThrow(
          'other data extends beyond buffer'
        );
      });
    });

    describe('parseRawCertRecord', () => {
      test('should parse CERT record from buffer', () => {
        const buffer = Buffer.alloc(15);
        buffer.writeUInt16BE(1, 0); // certificate_type
        buffer.writeUInt16BE(12345, 2); // key_tag
        buffer[4] = 13; // algorithm
        buffer.write('cert-data', 5, 'utf8'); // certificate

        const result = parseRawCertRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: CERT_RECORD,
          name: 'example.com',
          ttl: 300,
          certificate_type: '1',
          key_tag: 12345,
          algorithm: 13,
        });
        expect(result.certificate).toBeTruthy();
      });
    });

    describe('parseRawKeyRecord', () => {
      test('should parse KEY record from buffer', () => {
        const buffer = Buffer.alloc(20);
        buffer.writeUInt16BE(256, 0); // flags
        buffer[2] = 3; // protocol
        buffer[3] = 13; // algorithm
        buffer.write('key-data', 4, 'utf8'); // public key

        const result = parseRawKeyRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: KEY_RECORD,
          name: 'example.com',
          ttl: 300,
          flags: 256,
          protocol: 3,
          algorithm: 13,
        });
        expect(result.public_key).toBeTruthy();
      });
    });

    describe('parseRawSigRecord', () => {
      test('should parse SIG record from buffer', () => {
        const signerName = Buffer.from([7, ...Buffer.from('example'), 3, ...Buffer.from('com'), 0]);
        const signature = Buffer.from('signature-data');
        const buffer = Buffer.alloc(18 + signerName.length + signature.length);

        buffer.writeUInt16BE(1, 0); // type_covered
        buffer[2] = 13; // algorithm
        buffer[3] = 2; // labels
        buffer.writeUInt32BE(300, 4); // original_ttl
        buffer.writeUInt32BE(1234567890, 8); // signature_expiration
        buffer.writeUInt32BE(1234567800, 12); // signature_inception
        buffer.writeUInt16BE(12345, 16); // key_tag
        signerName.copy(buffer, 18);
        signature.copy(buffer, 18 + signerName.length);

        const result = parseRawSigRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: SIG_RECORD,
          name: 'example.com',
          ttl: 300,
          type_covered: '1',
          algorithm: 13,
          labels: 2,
          original_ttl: 300,
          signature_expiration: 1234567890,
          signature_inception: 1234567800,
          key_tag: 12345,
          signer_name: 'example.com',
        });
        expect(result.signature).toBeTruthy();
      });
    });

    describe('parseRawUriRecord', () => {
      test('should parse URI record from buffer', () => {
        const target = 'https://example.com';
        const buffer = Buffer.alloc(4 + target.length);
        buffer.writeUInt16BE(10, 0); // priority
        buffer.writeUInt16BE(5, 2); // weight
        buffer.write(target, 4, 'utf8'); // target

        const result = parseRawUriRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: URI_RECORD,
          name: 'example.com',
          ttl: 300,
          priority: 10,
          weight: 5,
          target: target,
        });
      });
    });

    describe('parseRawLocRecord', () => {
      test('should parse LOC record from buffer', () => {
        const buffer = Buffer.alloc(16);
        buffer[0] = 0; // version
        buffer[1] = 0x12; // size
        buffer[2] = 0x34; // horiz_pre
        buffer[3] = 0x56; // vert_pre
        const latThousandths = 135914640 + 0x80000000;
        buffer.writeUInt32BE(latThousandths, 4);
        const lonThousandths = -440698400 + 0x80000000;
        buffer.writeUInt32BE(lonThousandths, 8);
        buffer.writeUInt32BE(10000000 + 10000, 12);

        const result = parseRawLocRecord('example.com', buffer, 300);
        expect(result).toMatchObject({
          type: LOC_RECORD,
          name: 'example.com',
          ttl: 300,
          version: 0,
        });
        expect(result).toHaveProperty('size');
        expect(result).toHaveProperty('horiz_pre');
        expect(result).toHaveProperty('vert_pre');
        expect(result).toHaveProperty('latitude');
        expect(result).toHaveProperty('longitude');
        expect(result).toHaveProperty('altitude');
      });

      test('should throw error for unsupported LOC version', () => {
        const buffer = Buffer.alloc(16);
        buffer[0] = 1; // unsupported version
        expect(() => parseRawLocRecord('example.com', buffer, 300)).toThrow(ParsingError);
        expect(() => parseRawLocRecord('example.com', buffer, 300)).toThrow(
          'Unsupported LOC record version'
        );
      });
    });
  });
});
