import dnsPacket from 'dns-packet';
// @ts-expect-error dns-packet ships no types for this module
import * as packetTypes from 'dns-packet/types';
import {
  decodeMessage,
  decodeRecord,
  decodeRecords,
  isKnownRecordType,
  ParseError,
  RECORD_TYPES,
  typeCode,
  typeName,
  type DnsRecord,
  type ResourceRecord,
} from '../../src/index';
import {
  decodeDnskey,
  decodeDs,
  decodeNsec,
  decodeNsec3,
  decodeNsec3Param,
  decodeRrsig,
  decodeTypeBitmap,
  formatRecordData,
  parseRecordData,
} from '../../src/records/index';
import { escapeText, toBase32Hex, unescapeText } from '../../src/wire/bytes';
import { CORPUS, corpusAnswer, seededRandom } from '../support/corpus';

// ---- helpers

const hex = (text: string) => Uint8Array.from(Buffer.from(text.replace(/\s+/g, ''), 'hex'));
const ascii = (text: string) => [...Buffer.from(text, 'latin1')];
const name = (text: string) =>
  text === '.' ? [0] : [...text.split('.').flatMap(label => [label.length, ...ascii(label)]), 0];

// a record of the given type with hand-built data
const record = (type: string, rdata: Uint8Array | number[]): ResourceRecord => ({
  name: 'example.com',
  type: typeCode(type),
  class: 1,
  ttl: 300,
  rdata: Uint8Array.from(rdata),
  section: 'answer',
});

// the type-specific fields of a decoded record
const fields = (decoded: DnsRecord): Record<string, unknown> => {
  const { name: _name, type: _type, class: _class, ttl: _ttl, ...rest } = decoded;
  return rest;
};

// the same type as dns-packet spells it. Its table is older and shorter than ours, so a
// type it has no mnemonic for comes back as `UNKNOWN_<code>`
const packetTypeName = (mnemonic: string) => packetTypes.toString(typeCode(mnemonic));

// dns-packet returns a name's bytes as they are; this library escapes the ones that are
// not plain text. Undo the escapes to compare
const rawName = (escaped: string) =>
  escaped.replace(/\\(\d{3}|.)/g, (_, sequence: string) =>
    sequence.length === 3 ? String.fromCharCode(Number(sequence)) : sequence
  );
// dns-packet returns a character-string as plain text; this library escapes backslashes
// and bytes that are not UTF-8
const text = (plain: string) => escapeText(Buffer.from(plain));
const NAME_FIELDS = [
  'target',
  'exchange',
  'mname',
  'rname',
  'signerName',
  'replacement',
  'mbox',
  'txt',
];

// dns-packet's decoding of a record, renamed into this library's fields. Returns undefined
// for a type dns-packet has no decoder for
function fromPacket(answer: dnsPacket.Answer): Record<string, unknown> | undefined {
  const data = (answer as { data: any }).data;
  switch (answer.type) {
    case 'A':
    case 'AAAA':
      return { address: data };
    case 'NS':
    case 'CNAME':
    case 'PTR':
    case 'DNAME':
      return { target: data };
    case 'SOA':
      return {
        mname: data.mname,
        rname: data.rname,
        serial: data.serial,
        refresh: data.refresh,
        retry: data.retry,
        expire: data.expire,
        minimum: data.minimum,
      };
    case 'MX':
      return { preference: data.preference, exchange: data.exchange };
    case 'TXT':
      return {
        strings: (Array.isArray(data) ? data : [data]).map((part: Buffer) => escapeText(part)),
      };
    case 'CAA':
      return { flags: data.flags, tag: text(data.tag), value: text(data.value) };
    case 'DS':
      return {
        keyTag: data.keyTag,
        algorithm: data.algorithm,
        digestType: data.digestType,
        digest: data.digest.toString('hex'),
      };
    case 'DNSKEY':
      return {
        flags: data.flags,
        protocol: 3,
        algorithm: data.algorithm,
        publicKey: data.key.toString('base64'),
      };
    case 'RRSIG':
      return {
        typeCovered: data.typeCovered,
        algorithm: data.algorithm,
        labels: data.labels,
        originalTtl: data.originalTTL,
        signatureExpiration: data.expiration,
        signatureInception: data.inception,
        keyTag: data.keyTag,
        signerName: data.signersName,
        signature: data.signature.toString('base64'),
      };
    case 'NSEC':
      return { nextDomain: data.nextDomain, types: data.rrtypes };
    case 'NSEC3':
      return {
        algorithm: data.algorithm,
        flags: data.flags,
        iterations: data.iterations,
        salt: data.salt.toString('hex'),
        nextDomain: toBase32Hex(data.nextDomain),
        types: data.rrtypes,
      };
    case 'SRV':
      return { priority: data.priority, weight: data.weight, port: data.port, target: data.target };
    case 'NAPTR':
      return {
        order: data.order,
        preference: data.preference,
        flags: text(data.flags),
        services: text(data.services),
        regexp: text(data.regexp),
        replacement: data.replacement,
      };
    case 'TLSA':
      return {
        usage: data.usage,
        selector: data.selector,
        matchingType: data.matchingType,
        certificate: data.certificate.toString('hex'),
      };
    case 'SSHFP':
      return {
        algorithm: data.algorithm,
        fingerprintType: data.hash,
        fingerprint: String(data.fingerprint).toLowerCase(),
      };
    case 'HINFO':
      return { cpu: data.cpu, os: data.os };
    case 'RP':
      return { mbox: data.mbox, txt: data.txt };
    default:
      return undefined;
  }
}

// our fields with type mnemonics spelled dns-packet's way, for comparison
function comparable(decoded: DnsRecord): Record<string, unknown> {
  const out = fields(decoded);
  if (Array.isArray(out.types)) out.types = (out.types as string[]).map(packetTypeName);
  if (typeof out.typeCovered === 'string') out.typeCovered = packetTypeName(out.typeCovered);
  for (const field of NAME_FIELDS) {
    if (typeof out[field] === 'string') out[field] = rawName(out[field]);
  }
  // NSEC3's next owner is a hash, not a name
  if (decoded.type === 'NSEC') out.nextDomain = rawName(decoded.nextDomain);
  return out;
}

// ---------------------------------------------------------------------------

describe('decodeRecord over the corpus', () => {
  it('decodes every record of a known type, strictly', () => {
    let decoded = 0;
    const types = new Set<number>();
    for (const { label, response } of CORPUS) {
      const message = decodeMessage(response);
      for (const rr of [...message.answers, ...message.authorities, ...message.additionals]) {
        expect(isKnownRecordType(rr.type), `${label}: ${typeName(rr.type)}`).toBe(true);
        const result = decodeRecord(rr, { strict: true });
        expect(result.type, label).toBe(typeName(rr.type));
        expect(result.name, label).toBe(rr.name);
        types.add(rr.type);
        decoded++;
      }
    }
    expect(decoded).toBeGreaterThan(2000);
    // and the corpus holds a record of every type the library decodes
    const missing = Object.entries(RECORD_TYPES)
      .filter(([, code]) => isKnownRecordType(code) && !types.has(code))
      .map(([name]) => name);
    expect(missing).toEqual([]);
  });

  it('agrees with dns-packet on every field of every type dns-packet decodes', () => {
    const compared = new Map<string, number>();
    for (const { label, response } of CORPUS) {
      const ours = decodeMessage(response);
      const theirs = dnsPacket.decode(Buffer.from(response));
      const sections: [ResourceRecord[], dnsPacket.Answer[] | undefined][] = [
        [ours.answers, theirs.answers],
        [ours.authorities, theirs.authorities],
        [ours.additionals, theirs.additionals?.filter(answer => answer.type !== 'OPT')],
      ];
      for (const [ourRecords, theirRecords = []] of sections) {
        ourRecords.forEach((rr, index) => {
          const expected = fromPacket(theirRecords[index]);
          if (!expected) return;
          expect(comparable(decodeRecord(rr)), `${label}: ${typeName(rr.type)} ${rr.name}`).toEqual(
            expected
          );
          compared.set(typeName(rr.type), (compared.get(typeName(rr.type)) ?? 0) + 1);
        });
      }
    }
    // the types the corpus gave us to compare
    expect([...compared.keys()].sort()).toEqual([
      'A',
      'AAAA',
      'CAA',
      'CNAME',
      'DNAME',
      'DNSKEY',
      'DS',
      'HINFO',
      'MX',
      'NAPTR',
      'NS',
      'NSEC',
      'NSEC3',
      'PTR',
      'RP',
      'RRSIG',
      'SOA',
      'SRV',
      'SSHFP',
      'TLSA',
      'TXT',
    ]);
  });
});

describe('decodeRecord against dns-packet-encoded records', () => {
  // records dns-packet can encode, covering the types real traffic did not
  const cases: { type: string; data: unknown }[] = [
    { type: 'A', data: '192.0.2.200' },
    { type: 'AAAA', data: '2001:db8::ff00:42:8329' },
    { type: 'NS', data: 'ns1.example.net' },
    { type: 'CNAME', data: 'target.example.net' },
    { type: 'PTR', data: 'host.example.net' },
    { type: 'DNAME', data: 'elsewhere.example' },
    {
      type: 'SOA',
      data: {
        mname: 'ns1.example.net',
        rname: 'hostmaster.example.net',
        serial: 2026110901,
        refresh: 7200,
        retry: 900,
        expire: 1209600,
        minimum: 86400,
      },
    },
    { type: 'MX', data: { preference: 10, exchange: 'mail.example.net' } },
    { type: 'MX', data: { preference: 0, exchange: '.' } },
    { type: 'TXT', data: ['v=spf1 -all', 'second string', ''] },
    { type: 'CAA', data: { flags: 128, tag: 'issuewild', value: 'ca.example; policy=ev' } },
    { type: 'SRV', data: { priority: 1, weight: 65535, port: 5060, target: 'sip.example.net' } },
    { type: 'HINFO', data: { cpu: 'RFC8482', os: '' } },
    { type: 'RP', data: { mbox: 'admin.example.net', txt: 'contact.example.net' } },
    {
      type: 'NAPTR',
      data: {
        order: 100,
        preference: 50,
        flags: 'u',
        services: 'E2U+sip',
        regexp: '!^.*$!sip:info@example.com!',
        replacement: '.',
      },
    },
    {
      type: 'DS',
      data: {
        keyTag: 60485,
        algorithm: 5,
        digestType: 1,
        digest: Buffer.from('2bb183af5f22588179a53b0a98631fad1a292118', 'hex'),
      },
    },
    {
      type: 'DNSKEY',
      data: {
        flags: 256,
        algorithm: 15,
        key: Buffer.from('l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=', 'base64'),
      },
    },
    {
      type: 'RRSIG',
      data: {
        typeCovered: 'MX',
        algorithm: 13,
        labels: 2,
        originalTTL: 3600,
        expiration: 1764547200,
        inception: 1762128000,
        keyTag: 34505,
        signersName: 'example.net',
        signature: Buffer.from('c2lnbmF0dXJlLWJ5dGVzLWhlcmU=', 'base64'),
      },
    },
    {
      type: 'NSEC',
      data: { nextDomain: 'b.example.net', rrtypes: ['A', 'MX', 'RRSIG', 'NSEC', 'CAA'] },
    },
    {
      type: 'NSEC3',
      data: {
        algorithm: 1,
        flags: 1,
        iterations: 12,
        salt: Buffer.from('aabbccdd', 'hex'),
        nextDomain: Buffer.from('0123456789abcdef0123456789abcdef01234567', 'hex'),
        rrtypes: ['A', 'RRSIG'],
      },
    },
    {
      type: 'NSEC3',
      data: {
        algorithm: 1,
        flags: 0,
        iterations: 0,
        salt: Buffer.alloc(0),
        nextDomain: Buffer.alloc(20, 0xff),
        rrtypes: [],
      },
    },
    {
      type: 'TLSA',
      data: {
        usage: 3,
        selector: 1,
        matchingType: 1,
        certificate: Buffer.from(
          '0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6',
          'hex'
        ),
      },
    },
    {
      type: 'SSHFP',
      data: {
        algorithm: 4,
        hash: 2,
        fingerprint: 'A14497AC5B5050E4E78055D08C33F1912F1367F92B7CEF9C6F6C8EDFD8B0D839',
      },
    },
  ];

  it.each(cases)('$type $data', ({ type, data }) => {
    const answer = {
      name: 'example.com',
      type,
      ttl: 300,
      class: 'IN',
      data,
    } as unknown as dnsPacket.Answer;
    const encoded = dnsPacket.encode({ type: 'response', id: 1, answers: [answer] });
    const [rr] = decodeMessage(Uint8Array.from(encoded)).answers;
    // what dns-packet reads back from its own encoding is the reference
    const [reference] = dnsPacket.decode(encoded).answers!;
    expect(comparable(decodeRecord(rr))).toEqual(fromPacket(reference));
  });
});

describe('decodeRecord: types with no second opinion', () => {
  it('reads the HTTPS record captured from cloudflare.com', () => {
    const message = decodeMessage(corpusAnswer('cloudflare.com', 'HTTPS'));
    expect(fields(decodeRecord(message.answers[0]))).toEqual({
      priority: 1,
      target: '.',
      params: {
        alpn: ['h3', 'h2'],
        ipv4Hint: ['104.16.132.229', '104.16.133.229'],
        ipv6Hint: ['2606:4700::6810:84e5', '2606:4700::6810:85e5'],
      },
    });
  });

  it('reads the SVCB records a resolver publishes about itself', () => {
    const message = decodeMessage(corpusAnswer('_dns.resolver.arpa', 'SVCB'));
    expect(decodeRecords(message.answers).map(fields)).toEqual([
      {
        priority: 1,
        target: 'one.one.one.one',
        params: {
          alpn: ['h2', 'h3'],
          port: 443,
          ipv4Hint: ['1.1.1.1', '1.0.0.1'],
          ipv6Hint: ['2606:4700:4700::1111', '2606:4700:4700::1001'],
          dohPath: '/dns-query{?dns}',
        },
      },
      {
        priority: 2,
        target: 'one.one.one.one',
        params: {
          alpn: ['dot'],
          port: 853,
          ipv4Hint: ['1.1.1.1', '1.0.0.1'],
          ipv6Hint: ['2606:4700:4700::1111', '2606:4700:4700::1001'],
        },
      },
    ]);
  });

  it('reads SVCB data built to the RFC 9460 layout', () => {
    const svcb = (rdata: number[]) => fields(decodeRecord(record('SVCB', rdata)));
    // alias mode: priority 0 and a target, no parameters
    expect(svcb([0, 0, ...name('foo.example.com')])).toEqual({
      priority: 0,
      target: 'foo.example.com',
      params: {},
    });
    // service mode pointing at the owner itself
    expect(svcb([0, 1, 0])).toEqual({ priority: 1, target: '.', params: {} });
    expect(svcb([0, 16, ...name('foo.example.com'), 0, 3, 0, 2, 0, 53])).toEqual({
      priority: 16,
      target: 'foo.example.com',
      params: { port: 53 },
    });
    // a key the library has no name for
    expect(svcb([0, 1, ...name('foo.example.com'), 0x02, 0x9b, 0, 5, ...ascii('hello')])).toEqual({
      priority: 1,
      target: 'foo.example.com',
      params: { other: { 667: '68656c6c6f' } },
    });
    expect(
      svcb([
        0,
        16,
        ...name('foo.example.org'),
        0,
        0,
        0,
        4,
        0,
        1,
        0,
        4, // mandatory = alpn, ipv4hint
        0,
        1,
        0,
        9,
        2,
        ...ascii('h2'),
        5,
        ...ascii('h3-19'), // alpn
        0,
        2,
        0,
        0, // no-default-alpn
        0,
        4,
        0,
        4,
        192,
        0,
        2,
        1, // ipv4hint
        0,
        5,
        0,
        3,
        1,
        2,
        3, // ech
        0,
        6,
        0,
        16,
        ...hex('20010db8000000000000000000000001'), // ipv6hint
        0,
        8,
        0,
        0, // ohttp
      ])
    ).toEqual({
      priority: 16,
      target: 'foo.example.org',
      params: {
        mandatory: ['alpn', 'ipv4hint'],
        alpn: ['h2', 'h3-19'],
        noDefaultAlpn: true,
        ipv4Hint: ['192.0.2.1'],
        ech: 'AQID',
        ipv6Hint: ['2001:db8::1'],
        ohttp: true,
      },
    });
  });

  it('rejects SVCB parameters that break the RFC 9460 rules', () => {
    const bad = (rdata: number[]) => () => decodeRecord(record('HTTPS', rdata), { strict: true });
    expect(bad([0, 1, 0, 0, 3, 0, 2, 0, 53, 0, 1, 0, 3, 2, ...ascii('h2')])).toThrow(
      /out of order/
    );
    expect(bad([0, 1, 0, 0, 3, 0, 2, 0, 53, 0, 3, 0, 2, 0, 53])).toThrow(/out of order/);
    expect(bad([0, 1, 0, 0, 3, 0, 1, 53])).toThrow(/port/);
    expect(bad([0, 1, 0, 0, 4, 0, 3, 192, 0, 2])).toThrow(/address hint/);
    expect(bad([0, 1, 0, 0, 2, 0, 1, 0])).toThrow(/no-default-alpn/);
    expect(bad([0, 1, 0, 0, 1, 0, 0])).toThrow(/alpn/);
    expect(bad([0, 1, 0, 0, 3, 0, 9, 0, 53])).toThrow(ParseError);
  });

  it('reads CDS and CDNSKEY as DS and DNSKEY, from cloudflare.com', () => {
    const cds = decodeMessage(corpusAnswer('cloudflare.com', 'CDS'));
    expect(fields(decodeRecord(cds.answers[0]))).toEqual({
      keyTag: 2371,
      algorithm: 13,
      digestType: 2,
      digest: '32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9',
    });
    const cdnskey = decodeMessage(corpusAnswer('cloudflare.com', 'CDNSKEY'));
    expect(fields(decodeRecord(cdnskey.answers[0]))).toEqual({
      flags: 257,
      protocol: 3,
      algorithm: 13,
      publicKey:
        'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==',
    });
  });

  it('reads LOC the way dig prints it', () => {
    // dig: 42 21 43.528 N 71 5 6.284 W -25.00m 1m 3000m 10m
    const message = decodeMessage(corpusAnswer('ckdhr.com', 'LOC'));
    const loc = fields(decodeRecord(message.answers[0]));
    expect(loc).toMatchObject({
      version: 0,
      size: 1,
      horizontalPrecision: 3000,
      verticalPrecision: 10,
      altitude: -25,
    });
    expect(loc.latitude).toBeCloseTo(42 + 21 / 60 + 43.528 / 3600, 9);
    expect(loc.longitude).toBeCloseTo(-(71 + 5 / 60 + 6.284 / 3600), 9);
  });

  it('reads KEY and SIG with the DNSKEY and RRSIG layouts', () => {
    expect(fields(decodeRecord(record('KEY', [0x01, 0x00, 3, 8, 1, 2, 3, 4])))).toEqual({
      flags: 256,
      protocol: 3,
      algorithm: 8,
      publicKey: 'AQIDBA==',
    });
    const sig = [
      0,
      1,
      13,
      2,
      0,
      0,
      0x0e,
      0x10,
      0x69,
      0x2c,
      0xd3,
      0x80,
      0x69,
      0x07,
      0xe9,
      0x80,
      0x86,
      0xc9,
      ...name('example.net'),
      9,
      8,
      7,
    ];
    expect(fields(decodeRecord(record('SIG', sig)))).toEqual({
      typeCovered: 'A',
      algorithm: 13,
      labels: 2,
      originalTtl: 3600,
      signatureExpiration: 1764545408,
      signatureInception: 1762126208,
      keyTag: 34505,
      signerName: 'example.net',
      signature: 'CQgH',
    });
  });

  it('reads NSEC3PARAM, with and without a salt', () => {
    expect(
      fields(decodeRecord(record('NSEC3PARAM', [1, 0, 0, 10, 4, 0xaa, 0xbb, 0xcc, 0xdd])))
    ).toEqual({
      algorithm: 1,
      flags: 0,
      iterations: 10,
      salt: 'aabbccdd',
    });
    expect(fields(decodeRecord(record('NSEC3PARAM', [1, 0, 0, 0, 0])))).toEqual({
      algorithm: 1,
      flags: 0,
      iterations: 0,
      salt: '',
    });
  });

  it('reads CERT, URI and OPENPGPKEY', () => {
    expect(
      fields(decodeRecord(record('CERT', [0, 1, 0x30, 0x39, 8, 0xde, 0xad, 0xbe, 0xef])))
    ).toEqual({
      certificateType: 1,
      keyTag: 12345,
      algorithm: 8,
      certificate: '3q2+7w==',
    });
    expect(
      fields(decodeRecord(record('URI', [0, 10, 0, 1, ...ascii('https://example.com/')])))
    ).toEqual({
      priority: 10,
      weight: 1,
      target: 'https://example.com/',
    });
    expect(fields(decodeRecord(record('OPENPGPKEY', [0x99, 0x01, 0x0d])))).toEqual({ key: 'mQEN' });
  });

  it('reads TSIG, including its 48-bit time', () => {
    const tsig = [
      ...name('hmac-sha256'),
      0x00,
      0x01,
      0x69,
      0x11,
      0x3f,
      0x80, // time signed: 2^32 + 0x69113f80
      0x01,
      0x2c, // fudge 300
      0,
      4,
      1,
      2,
      3,
      4, // mac
      0xab,
      0xcd, // original id
      0,
      0, // error
      0,
      0, // no other data
    ];
    expect(fields(decodeRecord(record('TSIG', tsig)))).toEqual({
      algorithm: 'hmac-sha256',
      timeSigned: 0x100000000 + 0x69113f80,
      fudge: 300,
      mac: 'AQIDBA==',
      originalId: 0xabcd,
      error: 0,
      otherData: '',
    });
  });

  it('names types in a bitmap that have no mnemonic', () => {
    // window 0 with A, and window 255 with type 65280
    const nsec = [...name('next.example.com'), 0, 1, 0x40, 0xff, 1, 0x80];
    expect(fields(decodeRecord(record('NSEC', nsec)))).toEqual({
      nextDomain: 'next.example.com',
      types: ['A', 'TYPE65280'],
    });
  });
});

describe('decodeRecord: unknown and malformed', () => {
  it('returns a type it has no fields for in the generic form', () => {
    const unknown = decodeRecord({ ...record('A', [1, 2, 3]), type: 65280 });
    expect(unknown).toEqual({
      name: 'example.com',
      type: 'TYPE65280',
      class: 'IN',
      ttl: 300,
      data: '010203',
    });
    // a known type with no decoder of its own is treated the same way
    expect(decodeRecord(record('WKS', [1])).type).toBe('TYPE11');
  });

  const malformed: [string, number[], RegExp][] = [
    ['A', [192, 0, 2], /too short/],
    ['A', [192, 0, 2, 1, 9], /left over/],
    ['AAAA', [0, 1, 2, 3], /too short/],
    ['MX', [0], /too short/],
    ['TXT', [5, 1, 2], /too short/],
    ['NSEC', [...name('a.example'), 0, 0], /type bitmap/],
    ['NSEC', [...name('a.example'), 0, 33, ...Array(33).fill(0)], /type bitmap/],
    ['LOC', [1, 0x12, 0x12, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], /LOC version/],
    ['LOC', [0, 0xa2, 0x12, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], /LOC size/],
    ['SOA', [...name('ns.example'), ...name('admin.example'), 0, 0, 0, 1], /too short/],
    ['CNAME', [3, 0x77, 0x77], /Label runs past/],
  ];

  it.each(malformed)('rejects a malformed %s record when strict', (type, rdata, message) => {
    const decode = () => decodeRecord(record(type, rdata), { strict: true });
    expect(decode).toThrow(ParseError);
    expect(decode).toThrow(message);
    // the error says which record, and where
    expect(decode).toThrow(new RegExp(`Malformed ${type} record at example.com`));
  });

  it('returns a malformed record in the generic form unless strict', () => {
    expect(decodeRecord(record('A', [192, 0, 2]))).toEqual({
      name: 'example.com',
      type: 'TYPE1',
      class: 'IN',
      ttl: 300,
      data: 'c00002',
    });
  });

  it('never throws anything but ParseError, whatever the record data', () => {
    const random = seededRandom(1109);
    const sources = CORPUS;
    for (let round = 0; round < 4000; round++) {
      const message = decodeMessage(sources[Math.floor(random() * sources.length)].response);
      const records = [...message.answers, ...message.authorities, ...message.additionals];
      if (records.length === 0) continue;
      const rr = records[Math.floor(random() * records.length)];
      const mangled = Uint8Array.from(rr.rdata.subarray(0, Math.ceil(random() * rr.rdata.length)));
      if (mangled.length > 0)
        mangled[Math.floor(random() * mangled.length)] = Math.floor(random() * 256);
      try {
        decodeRecord({ ...rr, rdata: mangled }, { strict: true });
      } catch (error) {
        if (!(error instanceof ParseError)) {
          throw new Error(
            `round ${round}: ${String(error)} for ${typeName(rr.type)} ${Buffer.from(mangled).toString('hex')}`,
            { cause: error }
          );
        }
      }
    }
  });
});

describe('the DNSSEC field decoders', () => {
  // an RRSIG over A by Example.COM, with a 4-byte signature
  const rrsig = [
    0,
    1,
    13,
    2,
    0,
    0,
    1,
    44,
    0x77,
    0x35,
    0x94,
    0x00,
    0x3b,
    0x9a,
    0xca,
    0x00,
    0x04,
    0xd2,
    ...name('Example.COM'),
    0xde,
    0xad,
    0xbe,
    0xef,
  ];

  it('reads an RRSIG as numbers and bytes, with the signer as it was sent', () => {
    expect(decodeRrsig(Uint8Array.from(rrsig))).toEqual({
      typeCovered: 1,
      algorithm: 13,
      labels: 2,
      originalTtl: 300,
      expiration: 0x77359400,
      inception: 0x3b9aca00,
      keyTag: 1234,
      signerName: 'Example.COM',
      signature: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
    });
  });

  it('is the same decoder decodeRecord presents', () => {
    expect(fields(decodeRecord(record('RRSIG', rrsig)))).toMatchObject({
      typeCovered: 'A',
      signatureExpiration: 0x77359400,
      signerName: 'Example.COM',
      signature: '3q2+7w==',
    });
    const nsec3 = [1, 1, 0, 10, 2, 0xab, 0xcd, 2, 0x01, 0x02, 0, 1, 0x40];
    expect(decodeNsec3(Uint8Array.from(nsec3))).toEqual({
      hashAlgorithm: 1,
      flags: 1,
      iterations: 10,
      salt: Uint8Array.from([0xab, 0xcd]),
      nextHashed: Uint8Array.from([1, 2]),
      types: [1],
    });
    expect(fields(decodeRecord(record('NSEC3', nsec3)))).toEqual({
      algorithm: 1,
      flags: 1,
      iterations: 10,
      salt: 'abcd',
      nextDomain: toBase32Hex(Uint8Array.from([1, 2])),
      types: ['A'],
    });
  });

  it('reads DS, DNSKEY, NSEC and NSEC3PARAM', () => {
    expect(decodeDs(Uint8Array.from([0x04, 0xd2, 8, 2, 0xaa]))).toEqual({
      keyTag: 1234,
      algorithm: 8,
      digestType: 2,
      digest: Uint8Array.from([0xaa]),
    });
    expect(decodeDnskey(Uint8Array.from([1, 1, 3, 13, 0xbb]))).toEqual({
      flags: 257,
      protocol: 3,
      algorithm: 13,
      publicKey: Uint8Array.from([0xbb]),
    });
    expect(decodeNsec(Uint8Array.from([...name('B.example'), 0, 1, 0x62]))).toEqual({
      nextDomain: 'B.example',
      types: [1, 2, 6],
    });
    expect(decodeNsec3Param(Uint8Array.from([1, 0, 0, 0, 0]))).toEqual({
      hashAlgorithm: 1,
      flags: 0,
      iterations: 0,
      salt: new Uint8Array(0),
    });
    expect(decodeTypeBitmap(Uint8Array.from([0, 1, 0x40, 1, 1, 0x80]))).toEqual([1, 256]);
  });

  const malformed: [string, (rdata: Uint8Array) => unknown, number[], RegExp][] = [
    ['an RRSIG cut short', decodeRrsig, rrsig.slice(0, 17), /too short/],
    ['an RRSIG with a broken signer', decodeRrsig, [...rrsig.slice(0, 18), 5, 0x61], /Label/],
    ['a DS with no digest type', decodeDs, [0, 1, 8], /too short/],
    ['a DNSKEY cut short', decodeDnskey, [1, 1, 3], /too short/],
    ['an NSEC with an empty bitmap window', decodeNsec, [0, 0, 0], /type bitmap/],
    ['an NSEC3 whose salt runs off the end', decodeNsec3, [1, 0, 0, 0, 9, 1], /too short/],
    ['an NSEC3PARAM with bytes left over', decodeNsec3Param, [1, 0, 0, 0, 0, 7], /left over/],
    ['a bitmap window cut short', decodeTypeBitmap, [0, 2, 0x40], /too short/],
  ];

  it.each(malformed)('throws ParseError, never null, for %s', (_, decode, rdata, message) => {
    expect(() => decode(Uint8Array.from(rdata))).toThrow(ParseError);
    expect(() => decode(Uint8Array.from(rdata))).toThrow(message);
  });
});

describe('character-strings', () => {
  const txt = (...parts: number[][]) =>
    decodeRecord(
      record(
        'TXT',
        parts.flatMap(part => [part.length, ...part])
      )
    ) as Extract<DnsRecord, { type: 'TXT' }>;

  it('keeps every byte: UTF-8 as it is, a backslash as \\\\, anything else as \\DDD', () => {
    const decoded = txt([0x22, 0x5c, 0xff], []);
    expect(decoded.strings).toEqual(['"\\\\\\255', '']);
    // as dig writes it
    expect(formatRecordData(decoded)).toBe('"\\"\\\\\\255" ""');
    expect(txt([...Buffer.from('größe')]).strings).toEqual(['größe']);
  });

  it('decodes two different strings to two different fields', () => {
    expect(txt([...Buffer.from('\\255')]).strings).not.toEqual(txt([0xff]).strings);
  });

  it('survives decode, format and parse with any bytes', () => {
    const random = seededRandom(0x5c);
    for (let run = 0; run < 500; run++) {
      const parts = Array.from({ length: 1 + Math.floor(random() * 3) }, () =>
        Array.from({ length: Math.floor(random() * 40) }, () => Math.floor(random() * 256))
      );
      const decoded = txt(...parts);
      expect(decoded.strings.map(field => [...unescapeText(field)])).toEqual(parts);
      expect(parseRecordData('TXT', formatRecordData(decoded))).toEqual({
        strings: decoded.strings,
      });
    }
  });

  it('carries the same escapes in the other types with character-strings', () => {
    const naptr = decodeRecord(
      record('NAPTR', [0, 100, 0, 10, 1, 0x75, 1, 0xe9, 8, ...ascii('!^.*$!\\1'), 0])
    );
    expect(fields(naptr)).toMatchObject({ flags: 'u', services: '\\233', regexp: '!^.*$!\\\\1' });
    expect(parseRecordData('NAPTR', formatRecordData(naptr))).toEqual(fields(naptr));
  });
});
