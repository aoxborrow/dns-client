import {
  compareNames,
  decodeMessage,
  decodeRecord,
  decodeRecords,
  deduplicateRecords,
  flattenRecord,
  formatRecord,
  formatRecordData,
  formatSignatureTime,
  InvalidQueryError,
  parseIpv4,
  parseIpv6,
  reverseIp,
  sortRecords,
  type DnsRecord,
} from '../../src/index';
import { formatIpv6 } from '../../src/wire/bytes';
import { CAPTURED, CORPUS, seededRandom } from '../support/corpus';

const base = { name: 'example.com', class: 'IN', ttl: 300 };

// the answers of a captured response, as presentation-format data
const captured = (label: string) =>
  decodeRecords(
    decodeMessage(CAPTURED.find(m => m.label === `captured: ${label}`)!.response).answers
  )
    .filter(record => record.type !== 'RRSIG')
    .map(record => formatRecordData(record));

describe('formatRecordData against dig', () => {
  // each expectation is what `dig +short` printed for the same record when it was captured
  it('writes SRV, CAA, NAPTR and LOC the way dig does', () => {
    expect(captured('_xmpp-server._tcp.jabber.org SRV')).toEqual([
      '30 30 5269 scarlet.jabber.org.',
    ]);
    expect(captured('google.com CAA')).toEqual(['0 issue "pki.goog"']);
    expect(captured('isc.org NAPTR')).toEqual(['20 0 "S" "SIP+D2U" "" _sip._udp.isc.org.']);
    expect(captured('ckdhr.com LOC')).toEqual(['42 21 43.528 N 71 5 6.284 W -25.00m 1m 3000m 10m']);
  });

  it('writes fingerprints and digests as dig does, in lowercase', () => {
    expect(captured('master.debian.org SSHFP').slice(0, 2)).toEqual([
      '1 1 bc3f0910a4fded0ae5584d8775ca47de9263e89f',
      '1 2 a14497ac5b5050e4e78055d08c33f1912f1367f92b7cef9c6f6c8edfd8b0d839',
    ]);
    expect(captured('_25._tcp.mail.ietf.org TLSA')).toEqual([
      '3 1 1 38a88126a15ae8e643ce9447c3ce9a874ea0e05255d07ee12227809edbe5c7f1',
    ]);
  });

  it('writes HTTPS and SVCB parameters in key order', () => {
    expect(captured('cloudflare.com HTTPS')).toEqual([
      '1 . alpn="h3,h2" ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5',
    ]);
    expect(captured('_dns.resolver.arpa SVCB')[0]).toBe(
      '1 one.one.one.one. alpn="h2,h3" port=443 ipv4hint=1.1.1.1,1.0.0.1 ipv6hint=2606:4700:4700::1111,2606:4700:4700::1001 dohpath="/dns-query{?dns}"'
    );
  });
});

describe('formatRecordData', () => {
  const cases: [DnsRecord, string][] = [
    [{ ...base, type: 'A', address: '192.0.2.1' }, '192.0.2.1'],
    [{ ...base, type: 'AAAA', address: '2001:db8::1' }, '2001:db8::1'],
    [{ ...base, type: 'NS', target: 'ns1.example.net' }, 'ns1.example.net.'],
    [{ ...base, type: 'CNAME', target: '.' }, '.'],
    [
      {
        ...base,
        type: 'SOA',
        mname: 'ns1.example.net',
        rname: 'hostmaster.example.net',
        serial: 2026110901,
        refresh: 7200,
        retry: 900,
        expire: 1209600,
        minimum: 86400,
      },
      'ns1.example.net. hostmaster.example.net. 2026110901 7200 900 1209600 86400',
    ],
    [{ ...base, type: 'MX', preference: 10, exchange: 'mail.example.net' }, '10 mail.example.net.'],
    [{ ...base, type: 'MX', preference: 0, exchange: '.' }, '0 .'],
    [{ ...base, type: 'TXT', strings: ['v=spf1 -all'] }, '"v=spf1 -all"'],
    [
      {
        ...base,
        type: 'TXT',
        strings: ['one', '', 'say "hi"', 'back\\slash', 'tab\there', 'größe'],
      },
      '"one" "" "say \\"hi\\"" "back\\\\slash" "tab\\009here" "größe"',
    ],
    [
      { ...base, type: 'CAA', flags: 128, tag: 'issuewild', value: 'ca.example; policy=ev' },
      '128 issuewild "ca.example; policy=ev"',
    ],
    [
      { ...base, type: 'DS', keyTag: 2371, algorithm: 13, digestType: 2, digest: '32996839a6d8' },
      '2371 13 2 32996839a6d8',
    ],
    [
      {
        ...base,
        type: 'DNSKEY',
        flags: 257,
        protocol: 3,
        algorithm: 13,
        publicKey: 'mdsswUyr3DPW',
      },
      '257 3 13 mdsswUyr3DPW',
    ],
    [
      {
        ...base,
        type: 'RRSIG',
        typeCovered: 'MX',
        algorithm: 13,
        labels: 2,
        originalTtl: 3600,
        signatureExpiration: 1700000000,
        signatureInception: 0,
        keyTag: 34505,
        signerName: 'example.net',
        signature: 'c2ln',
      },
      'MX 13 2 3600 20231114221320 19700101000000 34505 example.net. c2ln',
    ],
    [
      { ...base, type: 'NSEC', nextDomain: '\\000.example.com', types: ['A', 'RRSIG', 'NSEC'] },
      '\\000.example.com. A RRSIG NSEC',
    ],
    [
      {
        ...base,
        type: 'NSEC3',
        algorithm: 1,
        flags: 1,
        iterations: 0,
        salt: '',
        nextDomain: '2T7B4G4VSA5SMI47K61MV5BV1A22BOJR',
        types: ['NS', 'DS', 'RRSIG'],
      },
      '1 1 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS DS RRSIG',
    ],
    [
      { ...base, type: 'NSEC3PARAM', algorithm: 1, flags: 0, iterations: 10, salt: 'aabbccdd' },
      '1 0 10 aabbccdd',
    ],
    [
      {
        ...base,
        type: 'CERT',
        certificateType: 1,
        keyTag: 12345,
        algorithm: 8,
        certificate: '3q2+7w==',
      },
      '1 12345 8 3q2+7w==',
    ],
    [{ ...base, type: 'HINFO', cpu: 'RFC8482', os: '' }, '"RFC8482" ""'],
    [{ ...base, type: 'RP', mbox: 'admin.example.net', txt: '.' }, 'admin.example.net. .'],
    [
      { ...base, type: 'URI', priority: 10, weight: 1, target: 'https://example.com/' },
      '10 1 "https://example.com/"',
    ],
    [{ ...base, type: 'OPENPGPKEY', key: 'mQEN' }, 'mQEN'],
    [
      {
        ...base,
        type: 'TSIG',
        algorithm: 'hmac-sha256',
        timeSigned: 1762214784,
        fudge: 300,
        mac: 'AQIDBA==',
        originalId: 43981,
        error: 0,
        otherData: '',
      },
      'hmac-sha256. 1762214784 300 AQIDBA== 43981 0 -',
    ],
    [
      { ...base, type: 'SVCB', priority: 0, target: 'foo.example.com', params: {} },
      '0 foo.example.com.',
    ],
    [
      {
        ...base,
        type: 'HTTPS',
        priority: 1,
        target: '.',
        params: {
          other: { 667: '68656c6c6f', 700: '' },
          alpn: ['h2', 'a,b'],
          noDefaultAlpn: true,
          mandatory: ['alpn'],
          ech: 'AQID',
          ohttp: true,
        },
      },
      '1 . mandatory=alpn alpn="h2,a\\\\,b" no-default-alpn ech="AQID" ohttp key667="hello" key700',
    ],
    [
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
      '33 52 3.000 S 151 12 25.200 E 58.25m 0.50m 10000m 10m',
    ],
    [{ ...base, type: 'TYPE65280', data: '010203' }, '\\# 3 010203'],
    [{ ...base, type: 'TYPE65280', data: '' }, '\\# 0'],
  ];

  it.each(cases)('$0.type → %s', (record, expected) => {
    expect(formatRecordData(record)).toBe(expected);
  });

  it('writes signature times in UTC, to the second', () => {
    expect(formatSignatureTime(0)).toBe('19700101000000');
    expect(formatSignatureTime(1700000000)).toBe('20231114221320');
    expect(formatSignatureTime(4294967295)).toBe('21060207062815');
  });

  it('writes a whole zone-file line, tab separated, with absolute names', () => {
    expect(
      formatRecord({ ...base, type: 'MX', preference: 10, exchange: 'mail.example.net' })
    ).toBe('example.com.\t300\tIN\tMX\t10 mail.example.net.');
    expect(
      formatRecord({
        name: '.',
        class: 'IN',
        ttl: 518400,
        type: 'NS',
        target: 'a.root-servers.net',
      })
    ).toBe('.\t518400\tIN\tNS\ta.root-servers.net.');
  });

  it('formats every record in the corpus on one line', () => {
    let formatted = 0;
    for (const { label, response } of [...CORPUS, ...CAPTURED]) {
      const message = decodeMessage(response);
      for (const rr of [...message.answers, ...message.authorities, ...message.additionals]) {
        const text = formatRecordData(decodeRecord(rr));
        expect(text, label).not.toMatch(/[\n\r]/);
        expect(text.length, label).toBeGreaterThan(0);
        formatted++;
      }
    }
    expect(formatted).toBeGreaterThan(6000);
  });
});

describe('record lists', () => {
  const a = (name: string, address: string, ttl = 300): DnsRecord => ({
    name,
    class: 'IN',
    ttl,
    type: 'A',
    address,
  });

  it('flattens a record to name, type, TTL and data', () => {
    expect(
      flattenRecord({ ...base, type: 'MX', preference: 10, exchange: 'mail.example.net' })
    ).toEqual({
      name: 'example.com',
      type: 'MX',
      class: 'IN',
      ttl: 300,
      data: '10 mail.example.net.',
    });
  });

  it('drops repeats, treating TTL and owner case as not part of the record', () => {
    const records = [
      a('example.com', '192.0.2.1', 300),
      a('EXAMPLE.com', '192.0.2.1', 60),
      a('example.com', '192.0.2.2'),
    ];
    expect(deduplicateRecords(records)).toEqual([records[0], records[2]]);
  });

  it('sorts by name in DNS order, then type, then data', () => {
    const records: DnsRecord[] = [
      a('www.example.com', '192.0.2.9'),
      { ...base, type: 'MX', preference: 10, exchange: 'mail.example.net' },
      a('example.com', '192.0.2.2'),
      a('example.com', '192.0.2.1'),
      { ...base, type: 'NS', target: 'ns1.example.net' },
      a('a.example.com', '192.0.2.5'),
    ];
    expect(
      sortRecords(records).map(
        record => `${record.name} ${record.type} ${formatRecordData(record)}`
      )
    ).toEqual([
      'example.com A 192.0.2.1',
      'example.com A 192.0.2.2',
      'example.com NS ns1.example.net.',
      'example.com MX 10 mail.example.net.',
      'a.example.com A 192.0.2.5',
      'www.example.com A 192.0.2.9',
    ]);
    // a new array: the input is not reordered
    expect(records[0].name).toBe('www.example.com');
  });

  it('orders names as RFC 4034 §6.1 does', () => {
    const ordered = [
      'example',
      'a.example',
      'yljkjljk.a.example',
      'Z.a.example',
      'zABC.a.EXAMPLE',
      'z.example',
      '\\001.z.example',
      '*.z.example',
      '\\200.z.example',
    ];
    const random = seededRandom(4034);
    const shuffled = [...ordered].sort(() => random() - 0.5);
    expect(shuffled.sort(compareNames)).toEqual(ordered);
    expect(compareNames('Example.COM', 'example.com.')).toBe(0);
  });
});

describe('IP addresses', () => {
  it('parses dotted-quad IPv4 strictly', () => {
    expect([...parseIpv4('192.0.2.1')!]).toEqual([192, 0, 2, 1]);
    expect([...parseIpv4('0.0.0.0')!]).toEqual([0, 0, 0, 0]);
    for (const bad of [
      '192.0.2',
      '192.0.2.1.5',
      '192.0.2.256',
      '192.0.02.1',
      '192.0.2.',
      'a.b.c.d',
      '1.2.3.4 ',
      '',
    ]) {
      expect(parseIpv4(bad), bad).toBeNull();
    }
  });

  it('parses every RFC 4291 form of an IPv6 address', () => {
    const forms: [string, string][] = [
      ['::', '::'],
      ['::1', '::1'],
      ['2001:db8::', '2001:db8::'],
      ['2001:DB8:0:0:0:0:0:1', '2001:db8::1'],
      ['2001:0db8:0000:0000:0000:ff00:0042:8329', '2001:db8::ff00:42:8329'],
      ['::ffff:192.0.2.1', '::ffff:c000:201'],
      ['64:ff9b::192.0.2.33', '64:ff9b::c000:221'],
      ['1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8'],
      ['1:2:3:4:5:6:192.0.2.1', '1:2:3:4:5:6:c000:201'],
    ];
    for (const [text, canonical] of forms)
      expect(formatIpv6(parseIpv6(text)!), text).toBe(canonical);
  });

  it('rejects what is not an IPv6 address', () => {
    for (const bad of [
      '',
      ':',
      ':::',
      '1::2::3',
      '1:2:3:4:5:6:7',
      '1:2:3:4:5:6:7:8:9',
      '12345::',
      'g::1',
      'fe80::1%eth0',
      '1:2:3:4:5:6:7::8',
      '::192.0.2.1:1',
      '192.0.2.1::1',
      '1:2:3:4:5:6:7:192.0.2.1',
    ]) {
      expect(parseIpv6(bad), bad).toBeNull();
    }
  });

  it('round-trips random addresses through text', () => {
    const random = seededRandom(5952);
    for (let round = 0; round < 500; round++) {
      const bytes = new Uint8Array(16);
      // long runs of zeros are what make the text form interesting
      for (let i = 0; i < 16; i += 2) {
        if (random() < 0.5) continue;
        bytes[i] = Math.floor(random() * 256);
        bytes[i + 1] = Math.floor(random() * 256);
      }
      expect(parseIpv6(formatIpv6(bytes))).toEqual(bytes);
    }
  });

  it('builds the reverse lookup name', () => {
    expect(reverseIp('8.8.8.8')).toBe('8.8.8.8.in-addr.arpa');
    expect(reverseIp(' 192.0.2.1 ')).toBe('1.2.0.192.in-addr.arpa');
    expect(reverseIp('2606:4700:4700::1111')).toBe(
      '1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa'
    );
    expect(() => reverseIp('example.com')).toThrow(InvalidQueryError);
  });
});
