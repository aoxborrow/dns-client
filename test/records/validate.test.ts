import {
  canonicalRecord,
  diffRecords,
  findCnameConflicts,
  findRepeatedRecords,
  flattenRecords,
  parseRecord,
  parseRecordData,
  qualify,
  relativize,
  type FlatRecord,
  type FlatRecordInput,
} from '../../src/records/index';
import { RecordSyntaxError, ParseError, type DnsRecord, type RecordProblem } from '../../src/index';
import { toAsciiName } from '../../src/wire/index';

// a record as a person writes one, with no class
const rec = (name: string, type: string, data: string, ttl = 3600): FlatRecordInput => ({
  name,
  type,
  ttl,
  data,
});

// a record as the validators give it back, with its class
const out = (name: string, type: string, data: string, ttl = 3600): FlatRecord => ({
  name,
  type,
  class: 'IN',
  ttl,
  data,
});

// the problems a call throws
function problems(call: () => unknown): RecordProblem[] {
  try {
    call();
  } catch (error) {
    if (error instanceof RecordSyntaxError) return error.problems;
    throw error;
  }
  throw new Error('expected a RecordSyntaxError');
}

describe('canonicalRecord', () => {
  it('writes a record the one way the library writes it', () => {
    expect(canonicalRecord(rec('WWW.Example.COM.', 'mx', ' 10  Mail.Example.net. '))).toEqual(
      out('www.example.com', 'MX', '10 mail.example.net.')
    );
    expect(canonicalRecord(rec('example.com', 'AAAA', '2001:0DB8:0:0:0:0:0:1'))).toEqual(
      out('example.com', 'AAAA', '2001:db8::1')
    );
    expect(
      canonicalRecord(rec('_sip._tcp.example.com', 'SRV', '0 5 5060 SIP.Example.com.'))
    ).toEqual(out('_sip._tcp.example.com', 'SRV', '0 5 5060 sip.example.com.'));
    expect(canonicalRecord(rec('example.com', 'CAA', '0 ISSUE letsencrypt.org'))).toEqual(
      out('example.com', 'CAA', '0 issue "letsencrypt.org"')
    );
  });

  it('keeps the class, IN when none is given', () => {
    expect(canonicalRecord({ ...rec('example.com', 'A', '192.0.2.1'), class: 'in' }).class).toBe(
      'IN'
    );
    expect(canonicalRecord({ ...rec('version.bind', 'TXT', '"9.18"'), class: 'CH' }).class).toBe(
      'CH'
    );
    expect(
      problems(() => canonicalRecord({ ...rec('example.com', 'A', '192.0.2.1'), class: 'XX' }))
    ).toEqual([
      {
        code: 'unknown-class',
        values: { class: 'XX' },
        name: 'example.com',
        type: 'A',
        detail: 'Unknown record class: "XX"',
      },
    ]);
  });

  it('makes records that differ only in spelling equal', () => {
    const spellings = [
      rec('example.com', 'TXT', 'v=spf1 include:_spf.example.net -all'),
      rec('Example.com.', 'txt', '"v=spf1 include:_spf.example.net -all"'),
    ];
    const canonical = spellings.map(record => canonicalRecord(record));
    expect(canonical[1]).toEqual(canonical[0]);
    expect(canonical[0].data).toBe('"v=spf1 include:_spf.example.net -all"');
  });

  it('keeps TXT strings where they were split, since the boundaries can mean something', () => {
    // DNS-SD reads each string as one key=value pair (RFC 6763 §6)
    expect(canonicalRecord(rec('example.com', 'TXT', '"txtvers=1" "path=/"')).data).toBe(
      '"txtvers=1" "path=/"'
    );
    expect(
      canonicalRecord(rec('example.com', 'TXT', '"v=spf1 include:" "_spf.example.net -all"'))
    ).not.toEqual(
      canonicalRecord(rec('example.com', 'TXT', '"v=spf1 include:_spf.example.net -all"'))
    );
  });

  it('takes unquoted TXT data as one string, cutting it only where it is over 255 bytes', () => {
    expect(canonicalRecord(rec('example.com', 'TXT', 'say "hi" \\ there')).data).toBe(
      '"say \\"hi\\" \\\\ there"'
    );
    expect(canonicalRecord(rec('example.com', 'TXT', 'txtvers=1 path=/')).data).toBe(
      '"txtvers=1 path=/"'
    );
    const long = `v=DKIM1; k=rsa; p=${'A'.repeat(300)}`;
    const { data } = canonicalRecord(rec('s1._domainkey.example.com', 'TXT', long));
    expect(data).toBe(`"${long.slice(0, 255)}" "${long.slice(255)}"`);
    // a character is never split across two strings
    const wide = 'é'.repeat(200);
    expect(canonicalRecord(rec('example.com', 'TXT', wide)).data).toBe(
      `"${'é'.repeat(127)}" "${'é'.repeat(73)}"`
    );
  });

  it('converts Unicode names, in the owner and in the data', () => {
    expect(canonicalRecord(rec('münchen.de', 'CNAME', 'Bücher.example.'))).toEqual(
      out('xn--mnchen-3ya.de', 'CNAME', 'xn--bcher-kva.example.')
    );
  });

  it('accepts underscore labels, one leading wildcard, a null MX and the CDS removal record', () => {
    expect(canonicalRecord(rec('_dmarc.example.com', 'TXT', 'v=DMARC1; p=none')).name).toBe(
      '_dmarc.example.com'
    );
    expect(canonicalRecord(rec('*.example.com', 'A', '192.0.2.1')).name).toBe('*.example.com');
    expect(canonicalRecord(rec('example.com', 'MX', '0 .')).data).toBe('0 .');
    expect(canonicalRecord(rec('example.com', 'CDS', '0 0 0 00')).data).toBe('0 0 0 00');
  });

  it('accepts every name the DNS can hold, classless reverse names included', () => {
    // RFC 2317 delegation of part of a /24
    expect(canonicalRecord(rec('0/25.2.0.192.in-addr.arpa', 'NS', 'ns1.example.net.'))).toEqual(
      out('0/25.2.0.192.in-addr.arpa', 'NS', 'ns1.example.net.')
    );
    expect(
      canonicalRecord(rec('1.2.0.192.in-addr.arpa', 'CNAME', '1.0/25.2.0.192.in-addr.arpa.')).data
    ).toBe('1.0/25.2.0.192.in-addr.arpa.');
    // other bytes as escapes, spelled one way
    expect(canonicalRecord(rec('a\\032b.Example.com', 'A', '192.0.2.1')).name).toBe(
      'a\\032b.example.com'
    );
    expect(canonicalRecord(rec('\\097bc.example.com', 'A', '192.0.2.1')).name).toBe(
      'abc.example.com'
    );
  });

  it('has no ALIAS or ANAME: they are provider features, not record types', () => {
    expect(problems(() => canonicalRecord(rec('example.com', 'ALIAS', 'lb.example.net.')))).toEqual(
      [
        {
          code: 'unknown-type',
          values: { type: 'ALIAS' },
          name: 'example.com',
          type: 'ALIAS',
          detail: 'Unknown record type: "ALIAS"',
        },
      ]
    );
    expect(() => canonicalRecord(rec('example.com', 'redirect', 'https://example.net/'))).toThrow(
      /Unknown record type/
    );
  });

  it('passes the data of a known type it has no parser for through, trimmed', () => {
    expect(canonicalRecord(rec('example.com', 'wks', '  192.0.2.1 6 25  '))).toEqual(
      out('example.com', 'WKS', '192.0.2.1 6 25')
    );
    expect(() => canonicalRecord(rec('example.com', 'WKS', '   '))).toThrow(/no data/);
  });

  it('takes the generic form for known and unknown types', () => {
    expect(canonicalRecord(rec('example.com', 'A', '\\# 4 c0000201')).data).toBe('192.0.2.1');
    expect(canonicalRecord(rec('example.com', 'TYPE65280', '\\# 3 01 02 03')).data).toBe(
      '\\# 3 010203'
    );
    expect(canonicalRecord(rec('example.com', 'WKS', '\\# 2 0102')).data).toBe('\\# 2 0102');
    expect(canonicalRecord(rec('example.com', 'TYPE1', '192.0.2.1')).type).toBe('A');
  });

  const invalid: [FlatRecordInput, RecordProblem['code'], RegExp][] = [
    [rec('@', 'A', '192.0.2.1'), 'zone-relative-name', /only means something relative to a zone/],
    [rec('', 'A', '192.0.2.1'), 'empty-name', /name is empty/],
    [rec('a.*.example.com', 'A', '192.0.2.1'), 'misplaced-wildcard', /only have "\*" as its first/],
    [rec('bad label.example.com', 'A', '192.0.2.1'), 'invalid-label', /must be escaped/],
    [rec(`${'a'.repeat(64)}.example.com`, 'A', '192.0.2.1'), 'invalid-name', /not a valid name/],
    [rec('example.com', '', '192.0.2.1'), 'missing-type', /type is empty/],
    [rec('example.com', 'A', '192.0.2.1', -1), 'invalid-ttl', /TTL/],
    [rec('example.com', 'A', '192.0.2.1', 1.5), 'invalid-ttl', /TTL/],
    [rec('example.com', 'A', '192.0.2.1', 2 ** 31), 'invalid-ttl', /TTL/],
    [rec('example.com', 'A', '192.0.2.300'), 'invalid-address', /not an IPv4 address/],
    [rec('www.example.com', 'CNAME', 'WWW.example.com.'), 'cname-to-self', /its own name/],
    [rec('www.example.com', 'CNAME', '*.example.net.'), 'wildcard-target', /may not be a wildcard/],
    [rec('example.com', 'MX', '10 .'), 'null-mx-preference', /must have preference 0/],
    [rec('example.com', 'MX', '10 mail server.example.net.'), 'extra-data', /unexpected extra/],
    [rec('example.com', 'CAA', '0 issue-wild "ca.example"'), 'invalid-caa-tag', /letters and/],
    [rec('example.com', 'DS', '2371 13 2 abcd'), 'digest-length', /32 bytes, not 2/],
    [rec('example.com', 'TXT', '"unterminated'), 'unclosed-quote', /not closed/],
    [rec('example.com', 'TXT', '   '), 'no-data', /no data/],
    [rec('example.com', 'TXT', `"${'a'.repeat(256)}"`), 'string-too-long', /longer than 255/],
  ];

  it.each(invalid)('rejects %o as %s', (record, code, message) => {
    expect(() => canonicalRecord(record)).toThrow(RecordSyntaxError);
    expect(() => canonicalRecord(record)).toThrow(message);
    const [problem] = problems(() => canonicalRecord(record));
    expect(problem).toMatchObject({ code, name: record.name, type: record.type });
    expect(problem.detail).toMatch(message);
  });

  it('gives the values behind each problem', () => {
    expect(problems(() => canonicalRecord(rec('example.com', 'DS', '2371 13 2 abcd')))[0]).toEqual({
      code: 'digest-length',
      values: { digestType: 2, expected: 32, actual: 2 },
      name: 'example.com',
      type: 'DS',
      detail: 'A digest of type 2 is 32 bytes, not 2',
    });
    expect(problems(() => canonicalRecord(rec('example.com', 'A', '192.0.2.300')))[0]).toEqual({
      code: 'invalid-address',
      values: { field: 'address', text: '192.0.2.300' },
      name: 'example.com',
      type: 'A',
      detail: '"192.0.2.300" is not an IPv4 address',
    });
  });

  it('reports every problem with the name, type, class and TTL at once', () => {
    let error: unknown;
    try {
      canonicalRecord({ name: 'a b.example.com', type: '', class: 'XX', ttl: -1, data: '' });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(RecordSyntaxError);
    const { problems: found, message } = error as RecordSyntaxError;
    expect(found.map(problem => problem.code)).toEqual([
      'invalid-ttl',
      'missing-type',
      'unknown-class',
      'invalid-label',
    ]);
    expect(message).toMatch(/^4 problems: TTL must be/);
  });

  it('rejects a record outside the zone, which catches an unqualified name', () => {
    const options = { zone: 'example.com' };
    expect(canonicalRecord(rec('www.example.com', 'A', '192.0.2.1'), options).name).toBe(
      'www.example.com'
    );
    expect(canonicalRecord(rec('Example.COM', 'A', '192.0.2.1'), options).name).toBe('example.com');
    expect(problems(() => canonicalRecord(rec('www', 'A', '192.0.2.1'), options))).toEqual([
      {
        code: 'outside-zone',
        values: { zone: 'example.com' },
        name: 'www',
        type: 'A',
        detail: 'www is not inside the zone example.com',
      },
    ]);
    expect(() => canonicalRecord(rec('www.example.net', 'A', '192.0.2.1'), options)).toThrow(
      /not inside the zone/
    );
    expect(() => canonicalRecord(rec('notexample.com', 'A', '192.0.2.1'), options)).toThrow(
      /not inside the zone/
    );
  });
});

describe('parseRecord', () => {
  it('returns the typed record, in canonical form', () => {
    const record: DnsRecord = parseRecord(rec('Example.com.', 'mx', '10 Mail.Example.net.'));
    expect(record).toEqual({
      name: 'example.com',
      type: 'MX',
      class: 'IN',
      ttl: 3600,
      preference: 10,
      exchange: 'mail.example.net',
    });
  });

  it('has no fields to give for a type that is not on the wire', () => {
    expect(() => parseRecord(rec('example.com', 'ANAME', 'lb.example.net.'))).toThrow(
      /Unknown record type/
    );
  });
});

describe('parseRecordData', () => {
  it('gives problems without a name or type, since it sees only the data', () => {
    expect(problems(() => parseRecordData('A', '192.0.2.300'))).toEqual([
      {
        code: 'invalid-address',
        values: { field: 'address', text: '192.0.2.300' },
        detail: '"192.0.2.300" is not an IPv4 address',
      },
    ]);
  });
});

describe('qualify and relativize', () => {
  const zone = 'example.com';
  const pairs: [FlatRecordInput, FlatRecordInput][] = [
    [rec('@', 'MX', '10 mail'), rec('example.com', 'MX', '10 mail.example.com.')],
    [rec('www', 'CNAME', '@'), rec('www.example.com', 'CNAME', 'example.com.')],
    [
      rec('www', 'CNAME', 'target.example.net.'),
      rec('www.example.com', 'CNAME', 'target.example.net.'),
    ],
    [
      rec('_sip._tcp', 'SRV', '0 5 5060 sip'),
      rec('_sip._tcp.example.com', 'SRV', '0 5 5060 sip.example.com.'),
    ],
    [rec('@', 'NS', 'ns1'), rec('example.com', 'NS', 'ns1.example.com.')],
    [rec('www', 'A', '192.0.2.1'), rec('www.example.com', 'A', '192.0.2.1')],
    [rec('@', 'TXT', 'v=spf1 -all'), rec('example.com', 'TXT', 'v=spf1 -all')],
    [rec('0/25.2', 'NS', 'ns1.example.net.'), rec('0/25.2.example.com', 'NS', 'ns1.example.net.')],
  ];

  it.each(pairs)('qualifies %o', (relative, full) => {
    expect(qualify(relative, zone)).toEqual(full);
  });

  it.each(pairs)('relativizes back to %o', (relative, full) => {
    expect(relativize(full, zone)).toEqual(relative);
  });

  it('reads a name without a trailing dot as relative to the zone, as a zone file does', () => {
    const record = rec('www.example.com', 'CNAME', 'app.example.com');
    expect(qualify(record, zone)).toEqual(
      rec('www.example.com.example.com', 'CNAME', 'app.example.com.example.com.')
    );
    // a trailing dot says the name is full
    expect(qualify(rec('www.example.com.', 'CNAME', 'app.example.com.'), zone)).toEqual(
      rec('www.example.com', 'CNAME', 'app.example.com.')
    );
  });

  it('keeps the rest of the record, class included', () => {
    expect(qualify(out('www', 'A', '192.0.2.1'), zone)).toEqual(
      out('www.example.com', 'A', '192.0.2.1')
    );
  });

  it('writes a name outside the zone in full, with its dot', () => {
    expect(relativize(rec('www.example.net', 'A', '192.0.2.1'), zone).name).toBe(
      'www.example.net.'
    );
    expect(relativize(rec('example.com', 'MX', '0 .'), zone)).toEqual(rec('@', 'MX', '0 .'));
  });

  it('produces what the validators take', () => {
    const full = qualify(rec('@', 'MX', '10 Mail'), 'Example.COM');
    expect(canonicalRecord(full, { zone: 'example.com' })).toEqual(
      out('example.com', 'MX', '10 mail.example.com.')
    );
  });
});

describe('sets of records', () => {
  it('finds a CNAME that shares its name with other records', () => {
    const clashes = findCnameConflicts([
      rec('www.example.com', 'CNAME', 'app.example.net.'),
      rec('WWW.example.com.', 'A', '192.0.2.1'),
      rec('www.example.com', 'TXT', 'hello'),
      rec('example.com', 'A', '192.0.2.1'),
    ]);
    expect(clashes).toEqual([
      {
        code: 'cname-and-other-data',
        values: { types: ['A', 'TXT'] },
        name: 'www.example.com',
        type: 'CNAME',
        detail: 'www.example.com has a CNAME record, so it cannot also have A, TXT records',
      },
    ]);
  });

  it('finds two different CNAMEs at one name, but lets its DNSSEC records be', () => {
    expect(
      findCnameConflicts([
        rec('www.example.com', 'CNAME', 'a.example.net.'),
        rec('www.example.com', 'CNAME', 'b.example.net.'),
      ])
    ).toEqual([
      {
        code: 'multiple-cnames',
        values: { targets: ['a.example.net.', 'b.example.net.'] },
        name: 'www.example.com',
        type: 'CNAME',
        detail: 'www.example.com has more than one CNAME record',
      },
    ]);
    expect(
      findCnameConflicts([
        rec('www.example.com', 'CNAME', 'a.example.net.'),
        rec('www.example.com', 'NSEC', 'z.example.com. CNAME RRSIG NSEC'),
      ])
    ).toEqual([]);
  });

  it('reports a record that is not valid on its own', () => {
    expect(
      findCnameConflicts([rec('@', 'CNAME', 'a.example.net.'), rec('example.com', 'A', 'nope')])
    ).toEqual([
      {
        code: 'zone-relative-name',
        values: { field: 'name' },
        name: '@',
        type: 'CNAME',
        detail: 'The record name is "@", which only means something relative to a zone',
      },
      {
        code: 'invalid-address',
        values: { field: 'address', text: 'nope' },
        name: 'example.com',
        type: 'A',
        detail: '"nope" is not an IPv4 address',
      },
    ]);
  });

  it('finds records that repeat, whatever their TTL or spelling', () => {
    const clashes = findRepeatedRecords([
      rec('example.com', 'MX', '10 mail.example.net.', 300),
      rec('Example.com.', 'mx', '10 MAIL.example.net', 3600),
      rec('example.com', 'MX', '20 mail.example.net.'),
    ]);
    expect(clashes).toEqual([
      {
        code: 'repeated-record',
        values: { data: '10 mail.example.net.', count: 2 },
        name: 'example.com',
        type: 'MX',
        detail: 'example.com MX 10 mail.example.net. appears 2 times',
      },
    ]);
    expect(
      findRepeatedRecords([
        rec('example.com', 'A', '192.0.2.1'),
        rec('example.com', 'A', '192.0.2.2'),
      ])
    ).toEqual([]);
  });

  it('tells records of different classes apart', () => {
    expect(
      findRepeatedRecords([
        rec('example.com', 'TXT', 'x'),
        { ...rec('example.com', 'TXT', 'x'), class: 'CH' },
      ])
    ).toEqual([]);
  });
});

describe('diffRecords', () => {
  const intended = [
    rec('example.com', 'MX', '10 Mail.Example.net', 3600),
    rec('example.com', 'TXT', 'v=spf1 -all', 3600),
    rec('www.example.com', 'A', '192.0.2.1', 300),
  ];

  it('says nothing when the live records match, however they are spelled or cached', () => {
    // what a resolver returned, decoded and flattened: quoted text, absolute names, the
    // TTL partly counted down
    const live: DnsRecord[] = [
      {
        name: 'example.com',
        class: 'IN',
        ttl: 2417,
        type: 'MX',
        preference: 10,
        exchange: 'mail.example.net',
      },
      { name: 'example.com', class: 'IN', ttl: 2417, type: 'TXT', strings: ['v=spf1 -all'] },
      { name: 'www.example.com', class: 'IN', ttl: 12, type: 'A', address: '192.0.2.1' },
    ];
    expect(diffRecords(intended, flattenRecords(live))).toEqual({ missing: [], unexpected: [] });
  });

  it('lists what is missing and what is there that should not be', () => {
    const actual = [
      rec('example.com', 'MX', '10 mail.example.net.'),
      rec('www.example.com', 'A', '192.0.2.99'),
    ];
    expect(diffRecords(intended, actual)).toEqual({
      missing: [
        out('example.com', 'TXT', '"v=spf1 -all"'),
        out('www.example.com', 'A', '192.0.2.1', 300),
      ],
      unexpected: [out('www.example.com', 'A', '192.0.2.99')],
    });
  });

  it('counts a different TTL only when asked', () => {
    const actual = intended.map(record => ({ ...record, ttl: 60 }));
    expect(diffRecords(intended, actual)).toEqual({ missing: [], unexpected: [] });
    expect(diffRecords(intended, actual, { compareTtl: true }).missing).toHaveLength(3);
  });

  it('refuses to compare records that are not valid, listing them all in one error', () => {
    expect(() => diffRecords([rec('example.com', 'A', 'nope')], [])).toThrow(RecordSyntaxError);
    const found = problems(() =>
      diffRecords([rec('example.com', 'A', 'nope')], [rec('www.example.com', 'MX', '10 .')])
    );
    expect(found.map(problem => [problem.name, problem.code])).toEqual([
      ['example.com', 'invalid-address'],
      ['www.example.com', 'null-mx-preference'],
    ]);
  });
});

describe('toAsciiName', () => {
  it('converts Unicode names to punycode and leaves ASCII names exactly as they are', () => {
    expect(toAsciiName('münchen.de')).toBe('xn--mnchen-3ya.de');
    expect(toAsciiName('_dmarc.Bücher.example.')).toBe('_dmarc.xn--bcher-kva.example.');
    expect(toAsciiName('Example.COM')).toBe('Example.COM');
    expect(toAsciiName('0x7f.1')).toBe('0x7f.1');
    expect(toAsciiName('*.example.com')).toBe('*.example.com');
  });

  it('refuses a name the conversion would turn into something else', () => {
    // a Unicode label with a space in it. An ASCII label is left as written, as an ASCII
    // name is, and the label rules are the validators' to apply
    expect(() => toAsciiName('bad münchen.de')).toThrow(ParseError);
    expect(toAsciiName('bad name.münchen.de')).toBe('bad name.xn--mnchen-3ya.de');
  });
});
