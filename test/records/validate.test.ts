import {
  canonicalRecord,
  diffRecords,
  findCnameConflicts,
  findRepeatedRecords,
  flattenRecords,
  parseRecord,
  qualify,
  RecordSyntaxError,
  relativize,
  toAsciiName,
  ParseError,
  type DnsRecord,
  type FlatRecord,
} from '../../src/index';

const rec = (name: string, type: string, data: string, ttl = 3600): FlatRecord => ({
  name,
  type,
  ttl,
  data,
});

describe('canonicalRecord', () => {
  it('writes a record the one way the library writes it', () => {
    expect(canonicalRecord(rec('WWW.Example.COM.', 'mx', ' 10  Mail.Example.net. '))).toEqual(
      rec('www.example.com', 'MX', '10 mail.example.net.')
    );
    expect(canonicalRecord(rec('example.com', 'AAAA', '2001:0DB8:0:0:0:0:0:1'))).toEqual(
      rec('example.com', 'AAAA', '2001:db8::1')
    );
    expect(
      canonicalRecord(rec('_sip._tcp.example.com', 'SRV', '0 5 5060 SIP.Example.com.'))
    ).toEqual(rec('_sip._tcp.example.com', 'SRV', '0 5 5060 sip.example.com.'));
    expect(canonicalRecord(rec('example.com', 'CAA', '0 ISSUE letsencrypt.org'))).toEqual(
      rec('example.com', 'CAA', '0 issue "letsencrypt.org"')
    );
  });

  it('makes records that differ only in spelling equal', () => {
    const spellings = [
      rec('example.com', 'TXT', 'v=spf1 include:_spf.example.net -all'),
      rec('Example.com.', 'txt', '"v=spf1 include:_spf.example.net -all"'),
      rec('example.com', 'TXT', '"v=spf1 include:" "_spf.example.net -all"'),
    ];
    const canonical = spellings.map(record => canonicalRecord(record));
    expect(canonical[1]).toEqual(canonical[0]);
    expect(canonical[2]).toEqual(canonical[0]);
    expect(canonical[0].data).toBe('"v=spf1 include:_spf.example.net -all"');
  });

  it('takes unquoted TXT data as plain text, and splits long text at 255 bytes', () => {
    expect(canonicalRecord(rec('example.com', 'TXT', 'say "hi" \\ there')).data).toBe(
      '"say \\"hi\\" \\\\ there"'
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
      rec('xn--mnchen-3ya.de', 'CNAME', 'xn--bcher-kva.example.')
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

  it('accepts ALIAS and ANAME as a target name', () => {
    expect(canonicalRecord(rec('example.com', 'alias', 'LB.Example.net'))).toEqual(
      rec('example.com', 'ALIAS', 'lb.example.net.')
    );
    expect(canonicalRecord(rec('example.com', 'ANAME', 'lb.example.net.')).data).toBe(
      'lb.example.net.'
    );
    expect(() => canonicalRecord(rec('example.com', 'ALIAS', 'example.com.'))).toThrow(
      /its own name/
    );
    expect(() => canonicalRecord(rec('example.com', 'ALIAS', '*.example.net'))).toThrow(/wildcard/);
  });

  it('passes a type it does not know through, trimmed', () => {
    expect(canonicalRecord(rec('example.com', 'redirect', '  https://example.net/  '))).toEqual(
      rec('example.com', 'REDIRECT', 'https://example.net/')
    );
    expect(() => canonicalRecord(rec('example.com', 'REDIRECT', '   '))).toThrow(/no data/);
  });

  it('takes the generic form for known and unknown types', () => {
    expect(canonicalRecord(rec('example.com', 'A', '\\# 4 c0000201')).data).toBe('192.0.2.1');
    expect(canonicalRecord(rec('example.com', 'TYPE65280', '\\# 3 01 02 03')).data).toBe(
      '\\# 3 010203'
    );
    expect(canonicalRecord(rec('example.com', 'WKS', '\\# 2 0102')).data).toBe('\\# 2 0102');
  });

  const invalid: [FlatRecord, RegExp][] = [
    [rec('@', 'A', '192.0.2.1'), /only means something relative to a zone/],
    [rec('', 'A', '192.0.2.1'), /name is empty/],
    [rec('a.*.example.com', 'A', '192.0.2.1'), /only have "\*" as its first label/],
    [rec('bad label.example.com', 'A', '192.0.2.1'), /not letters, digits, hyphens or underscores/],
    [rec(`${'a'.repeat(64)}.example.com`, 'A', '192.0.2.1'), /not a valid name/],
    [rec('example.com', '', '192.0.2.1'), /type is empty/],
    [rec('example.com', 'A', '192.0.2.1', -1), /TTL/],
    [rec('example.com', 'A', '192.0.2.1', 1.5), /TTL/],
    [rec('example.com', 'A', '192.0.2.1', 2 ** 31), /TTL/],
    [rec('example.com', 'A', '192.0.2.300'), /not an IPv4 address/],
    [rec('www.example.com', 'CNAME', 'WWW.example.com.'), /cannot point at its own name/],
    [rec('www.example.com', 'CNAME', '*.example.net.'), /may not be a wildcard/],
    [rec('example.com', 'MX', '10 .'), /must have preference 0/],
    [rec('example.com', 'MX', '10 mail server.example.net.'), /unexpected extra data/],
    [rec('example.com', 'CAA', '0 issue-wild "ca.example"'), /letters and digits/],
    [rec('example.com', 'DS', '2371 13 2 abcd'), /32 bytes, not 2/],
    [rec('example.com', 'TXT', '"unterminated'), /not closed/],
    [rec('example.com', 'TXT', '   '), /no data/],
  ];

  it.each(invalid)('rejects %o', (record, message) => {
    expect(() => canonicalRecord(record)).toThrow(RecordSyntaxError);
    expect(() => canonicalRecord(record)).toThrow(message);
  });

  it('rejects a record outside the zone, which catches an unqualified name', () => {
    const options = { zone: 'example.com' };
    expect(canonicalRecord(rec('www.example.com', 'A', '192.0.2.1'), options).name).toBe(
      'www.example.com'
    );
    expect(canonicalRecord(rec('Example.COM', 'A', '192.0.2.1'), options).name).toBe('example.com');
    expect(() => canonicalRecord(rec('www', 'A', '192.0.2.1'), options)).toThrow(
      /not inside the zone/
    );
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
    expect(() => parseRecord(rec('example.com', 'ALIAS', 'lb.example.net.'))).toThrow(
      /provider feature/
    );
    expect(() => parseRecord(rec('example.com', 'REDIRECT', 'https://example.net/'))).toThrow(
      /Unknown record type/
    );
  });
});

describe('qualify and relativize', () => {
  const zone = 'example.com';
  const pairs: [FlatRecord, FlatRecord][] = [
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
    [rec('@', 'ALIAS', 'lb.example.net.'), rec('example.com', 'ALIAS', 'lb.example.net.')],
    [rec('www', 'A', '192.0.2.1'), rec('www.example.com', 'A', '192.0.2.1')],
    [rec('@', 'TXT', 'v=spf1 -all'), rec('example.com', 'TXT', 'v=spf1 -all')],
  ];

  it.each(pairs)('qualifies %o', (relative, full) => {
    expect(qualify(relative, zone)).toEqual(full);
  });

  it.each(pairs)('relativizes back to %o', (relative, full) => {
    expect(relativize(full, zone)).toEqual(relative);
  });

  it('reads a name that already ends in the zone either way', () => {
    const record = rec('www.example.com', 'CNAME', 'app.example.com');
    expect(qualify(record, zone)).toEqual(rec('www.example.com', 'CNAME', 'app.example.com.'));
    expect(qualify(record, zone, { namesEndingInZone: 'relative' })).toEqual(
      rec('www.example.com.example.com', 'CNAME', 'app.example.com.example.com.')
    );
    // a trailing dot settles it under either reading
    expect(
      qualify(rec('www.example.com.', 'A', '192.0.2.1'), zone, { namesEndingInZone: 'relative' })
        .name
    ).toBe('www.example.com');
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
      rec('example.com', 'MX', '10 mail.example.com.')
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
      ]).map(clash => clash.detail)
    ).toEqual(['www.example.com has more than one CNAME record']);
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
        name: '@',
        type: 'CNAME',
        detail: 'The record name is "@", which only means something relative to a zone',
      },
      { name: 'example.com', type: 'A', detail: '"nope" is not an IPv4 address' },
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
        rec('example.com', 'TXT', '"v=spf1 -all"'),
        rec('www.example.com', 'A', '192.0.2.1', 300),
      ],
      unexpected: [rec('www.example.com', 'A', '192.0.2.99')],
    });
  });

  it('counts a different TTL only when asked', () => {
    const actual = intended.map(record => ({ ...record, ttl: 60 }));
    expect(diffRecords(intended, actual)).toEqual({ missing: [], unexpected: [] });
    expect(diffRecords(intended, actual, { compareTtl: true }).missing).toHaveLength(3);
  });

  it('refuses to compare a record that is not valid', () => {
    expect(() => diffRecords([rec('example.com', 'A', 'nope')], [])).toThrow(RecordSyntaxError);
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
    // full-width digits map to ASCII digits, which the URL parser then reads as an address
    expect(() => toAsciiName('１２７.１')).toThrow(ParseError);
    expect(() => toAsciiName('bad name.münchen.de')).toThrow(ParseError);
  });
});
