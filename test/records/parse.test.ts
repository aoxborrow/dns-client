import {
  decodeMessage,
  decodeRecord,
  formatRecordData,
  hasRecordParser,
  parseRecordData,
  RecordSyntaxError,
  type DnsRecord,
} from '../../src/index';
import { CORPUS } from '../support/corpus';

const base = { name: 'example.com', class: 'IN', ttl: 300 };

const fields = (decoded: DnsRecord): Record<string, unknown> => {
  const { name: _name, type: _type, class: _class, ttl: _ttl, ...rest } = decoded;
  return rest;
};

describe('parseRecordData is the inverse of formatRecordData', () => {
  it('reads back every record in the corpus exactly', () => {
    const seen = new Map<string, number>();
    for (const { label, response } of CORPUS) {
      const message = decodeMessage(response);
      for (const rr of [...message.answers, ...message.authorities, ...message.additionals]) {
        const decoded = decodeRecord(rr);
        const text = formatRecordData(decoded);
        expect(parseRecordData(decoded.type, text), `${label}: ${decoded.type} ${text}`).toEqual(
          fields(decoded)
        );
        seen.set(decoded.type, (seen.get(decoded.type) ?? 0) + 1);
      }
    }
    expect(seen.size).toBeGreaterThanOrEqual(33);
  });

  // one of each type the corpus does not contain, and the awkward values of those it does
  const records: DnsRecord[] = [
    { ...base, type: 'DNAME', target: 'elsewhere.example' },
    { ...base, type: 'MX', preference: 0, exchange: '.' },
    {
      ...base,
      type: 'TXT',
      strings: ['one', '', 'say "hi"', 'back\\\\slash', 'tab\there', 'größe', 'semi;colon (paren)'],
    },
    { ...base, type: 'CAA', flags: 128, tag: 'issuewild', value: 'ca.example; policy=ev' },
    { ...base, type: 'KEY', flags: 256, protocol: 3, algorithm: 8, publicKey: 'AQIDBA==' },
    {
      ...base,
      type: 'SIG',
      typeCovered: 'A',
      algorithm: 13,
      labels: 2,
      originalTtl: 3600,
      signatureExpiration: 1764545408,
      signatureInception: 1762126208,
      keyTag: 34505,
      signerName: 'example.net',
      signature: 'CQgH',
    },
    {
      ...base,
      type: 'NSEC',
      nextDomain: '\\000.example.com',
      types: ['A', 'RRSIG', 'NSEC', 'TYPE65280'],
    },
    {
      ...base,
      type: 'NSEC3',
      algorithm: 1,
      flags: 1,
      iterations: 0,
      salt: '',
      nextDomain: '2T7B4G4VSA5SMI47K61MV5BV1A22BOJR',
      types: [],
    },
    { ...base, type: 'NSEC3PARAM', algorithm: 1, flags: 0, iterations: 10, salt: 'aabbccdd' },
    {
      ...base,
      type: 'CERT',
      certificateType: 1,
      keyTag: 12345,
      algorithm: 8,
      certificate: '3q2+7w==',
    },
    { ...base, type: 'HINFO', cpu: 'RFC8482', os: '' },
    {
      ...base,
      type: 'TSIG',
      algorithm: 'hmac-sha256',
      timeSigned: 0x100000000 + 0x69113f80,
      fudge: 300,
      mac: 'AQIDBA==',
      originalId: 43981,
      error: 0,
      otherData: '',
    },
    { ...base, type: 'OPENPGPKEY', key: 'mQEN' },
    { ...base, type: 'RP', mbox: 'admin.example.net', txt: '.' },
    { ...base, type: 'URI', priority: 10, weight: 1, target: 'https://example.com/?q="x"' },
    { ...base, type: 'SVCB', priority: 0, target: 'foo.example.com', params: {} },
    {
      ...base,
      type: 'HTTPS',
      priority: 1,
      target: '.',
      params: {
        mandatory: ['alpn', 'key667'],
        alpn: ['h2', 'a,b', 'c\\d'],
        noDefaultAlpn: true,
        port: 8443,
        ipv4Hint: ['192.0.2.1'],
        ech: 'AQID',
        ipv6Hint: ['2001:db8::1'],
        dohPath: '/dns-query{?dns}',
        ohttp: true,
        other: { 667: '68656c6c6f', 700: '' },
      },
    },
    {
      ...base,
      type: 'LOC',
      version: 0,
      size: 0.5,
      horizontalPrecision: 10000,
      verticalPrecision: 10,
      latitude: -33.8675,
      longitude: 151.207,
      altitude: 58.25,
    },
    { ...base, type: 'TYPE65280', data: '010203' },
    { ...base, type: 'TYPE65280', data: '' },
  ];

  it.each(records)('reads back $type $0', record => {
    expect(parseRecordData(record.type, formatRecordData(record))).toEqual(fields(record));
  });
});

describe('parseRecordData: what it accepts', () => {
  it('reads an address in any valid spelling and returns the canonical one', () => {
    expect(parseRecordData('AAAA', '2001:0DB8:0:0:0:0:0:1')).toEqual({ address: '2001:db8::1' });
    expect(parseRecordData('a', ' 192.0.2.1 ')).toEqual({ address: '192.0.2.1' });
  });

  it('takes names with or without the trailing dot, in the case given', () => {
    expect(parseRecordData('MX', '10 Mail.Example.NET.')).toEqual({
      preference: 10,
      exchange: 'Mail.Example.NET',
    });
    expect(parseRecordData('MX', '10 mail.example.net')).toEqual({
      preference: 10,
      exchange: 'mail.example.net',
    });
    expect(parseRecordData('CNAME', '.')).toEqual({ target: '.' });
  });

  it('reads TXT strings quoted, unquoted, and with escapes', () => {
    expect(parseRecordData('TXT', 'v=spf1 "include:_spf.example.com" -all')).toEqual({
      strings: ['v=spf1', 'include:_spf.example.com', '-all'],
    });
    expect(parseRecordData('TXT', '"a \\"quoted\\" word" "\\065\\066" ""')).toEqual({
      strings: ['a "quoted" word', 'AB', ''],
    });
  });

  it('reads long fields split across tokens, lines, parentheses and comments', () => {
    expect(
      parseRecordData(
        'DNSKEY',
        '257 3 13 (\n  mdsswUyr3DPW132mOi8V9xESWE8jTo0d ; first half\n  xCjjnopKl+GqJxpVXckHAeF+KkxLbxIL\n)'
      )
    ).toEqual({
      flags: 257,
      protocol: 3,
      algorithm: 13,
      publicKey: 'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxIL',
    });
    expect(parseRecordData('DS', '2371 13 2 32996839 A6D808AF')).toMatchObject({
      digest: '32996839a6d808af',
    });
  });

  it('accepts algorithm and certificate type mnemonics', () => {
    expect(parseRecordData('DS', '2371 ECDSAP256SHA256 2 ab')).toMatchObject({ algorithm: 13 });
    expect(parseRecordData('DNSKEY', '256 3 rsasha256 AQID')).toMatchObject({ algorithm: 8 });
    expect(parseRecordData('CERT', 'PKIX 1 RSASHA256 AQID')).toEqual({
      certificateType: 1,
      keyTag: 1,
      algorithm: 8,
      certificate: 'AQID',
    });
  });

  it('reads signature times as dates or as seconds', () => {
    const data = (expiration: string) => `A 13 2 3600 ${expiration} 0 34505 example.net. CQgH`;
    expect(parseRecordData('RRSIG', data('20231114221320'))).toMatchObject({
      signatureExpiration: 1700000000,
      signatureInception: 0,
    });
    expect(parseRecordData('RRSIG', data('1700000000'))).toMatchObject({
      signatureExpiration: 1700000000,
    });
  });

  it('fills in the LOC defaults and accepts partial coordinates', () => {
    expect(parseRecordData('LOC', '42 N 71 W 0m')).toEqual({
      version: 0,
      size: 1,
      horizontalPrecision: 10000,
      verticalPrecision: 10,
      latitude: 42,
      longitude: -71,
      altitude: 0,
    });
    expect(
      parseRecordData('LOC', '52 22 23.000 n 4 53 32.000 e -2.00m 0.00m 10000m 10m')
    ).toMatchObject({
      size: 0,
      altitude: -2,
    });
  });

  it('reads service parameters quoted or not, in any order', () => {
    expect(
      parseRecordData('HTTPS', '1 . port=443 alpn=h2,h3 ipv4hint="192.0.2.1,192.0.2.2"')
    ).toEqual({
      priority: 1,
      target: '.',
      params: { port: 443, alpn: ['h2', 'h3'], ipv4Hint: ['192.0.2.1', '192.0.2.2'] },
    });
  });

  it('reads service parameters spread over lines with parentheses and comments', () => {
    expect(parseRecordData('HTTPS', '1 . (\n  alpn="h2" ; the protocols\n  port=443\n)')).toEqual({
      priority: 1,
      target: '.',
      params: { alpn: ['h2'], port: 443 },
    });
    expect(parseRecordData('SVCB', '1 svc.example.com. alpn=h3 ; trailing comment')).toEqual({
      priority: 1,
      target: 'svc.example.com',
      params: { alpn: ['h3'] },
    });
    // a quoted value keeps the spaces, parentheses and semicolons inside it
    expect(parseRecordData('HTTPS', '( 1 . dohpath="/q (x); y" )')).toEqual({
      priority: 1,
      target: '.',
      params: { dohPath: '/q (x); y' },
    });
    expect(() => parseRecordData('HTTPS', '1 . alpn="h2')).toThrow(/not closed/);
  });

  it('drops a root dot written after an escaped backslash', () => {
    expect(parseRecordData('CNAME', 'foo\\\\.')).toEqual({ target: 'foo\\\\' });
    expect(parseRecordData('CNAME', 'foo\\.')).toEqual({ target: 'foo\\.' });
  });

  it('takes any type in the generic form', () => {
    expect(parseRecordData('A', '\\# 4 c0000201')).toEqual({ address: '192.0.2.1' });
    expect(parseRecordData('MX', '\\# 8 000a 046d61696c 00')).toEqual({
      preference: 10,
      exchange: 'mail',
    });
    expect(parseRecordData('TYPE65280', '\\# 3 01 02 03')).toEqual({ data: '010203' });
    expect(parseRecordData('WKS', '\\# 0')).toEqual({ data: '' });
  });

  it('says which types it has a text parser for', () => {
    expect(hasRecordParser('mx')).toBe(true);
    expect(hasRecordParser('HTTPS')).toBe(true);
    expect(hasRecordParser('WKS')).toBe(false);
    expect(hasRecordParser('constructor')).toBe(false);
  });
});

describe('parseRecordData: what it rejects', () => {
  const invalid: [string, string, RegExp][] = [
    ['A', '192.0.2.300', /not an IPv4 address/],
    ['A', '192.0.2.1 192.0.2.2', /unexpected extra data/],
    ['A', '', /has no data/],
    ['AAAA', '2001:db8::g', /not an IPv6 address/],
    ['MX', 'ten mail.example.net.', /preference must be a whole number/],
    ['MX', '70000 mail.example.net.', /from 0 to 65535/],
    ['MX', '10', /missing its mail server/],
    ['MX', '10 "mail.example.net."', /must not be in quotes/],
    ['CNAME', `${'a'.repeat(64)}.example.com.`, /not a valid name/],
    ['CNAME', 'a..example.com.', /not a valid name/],
    ['SOA', 'ns1.example.net. admin.example.net. 1 2 3 4', /missing its minimum/],
    ['SOA', 'ns1.example.net. admin.example.net. 4294967296 2 3 4 5', /from 0 to 4294967295/],
    ['TXT', '"unterminated', /not closed/],
    ['TXT', `"${'x'.repeat(256)}"`, /longer than 255 bytes/],
    ['TXT', '"bad \\999 escape"', /Invalid escape/],
    ['DS', '2371 13 2 abc', /not valid hex/],
    ['DS', '2371 NOPE 2 ab', /Unknown algorithm/],
    ['DNSKEY', '257 3 13 not*base64', /not valid base64/],
    ['RRSIG', 'A 13 2 3600 20230230000000 0 1 example.net. CQgH', /not a valid time/],
    ['RRSIG', 'NOPE 13 2 3600 0 0 1 example.net. CQgH', /Unknown record type/],
    ['NSEC', 'next.example.com. A NOPE', /Unknown record type/],
    ['NSEC3', '1 0 0 zz ABCDEF A', /salt is not valid hex/],
    ['NSEC3', '1 0 0 - ABC!EF A', /not valid base32hex/],
    ['SRV', '0 0 70000 target.example.', /from 0 to 65535/],
    ['HTTPS', '1 . port=443 port=8443', /appears twice/],
    ['HTTPS', '1 . nonsense=1', /Unknown service parameter/],
    ['HTTPS', '1 . port=http', /port is not valid/],
    ['HTTPS', '1 . ipv4hint=192.0.2.300', /invalid address/],
    ['HTTPS', '1 . no-default-alpn=yes', /takes no value/],
    ['HTTPS', '1 . alpn=', /needs a value/],
    ['LOC', '91 N 0 E 0m', /latitude is out of range/],
    ['LOC', '42 60 N 71 W 0m', /out of range/],
    ['LOC', '42 N 71 W 0m 1234m', /single digit followed by zeros/],
    ['LOC', '42 N 71 0m', /longitude is not valid/],
    ['TLSA', '3 1 1', /missing its certificate data/],
    ['WKS', '192.0.2.1 6 25', /only be given in the generic form/],
    ['NOPE', 'anything', /Unknown record type/],
    ['A', '\\# 4 c00002', /does not match its stated length/],
    ['A', '\\# 3 c00002', /not a valid A record/],
  ];

  it.each(invalid)('%s %s', (type, data, message) => {
    expect(() => parseRecordData(type, data)).toThrow(RecordSyntaxError);
    expect(() => parseRecordData(type, data)).toThrow(message);
  });
});
