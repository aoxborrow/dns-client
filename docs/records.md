# Records

`@aoxborrow/dns/records` holds the typed records, the protocol tables, record decoding and
formatting, and the record validators. It runs anywhere: browsers and Cloudflare Workers
included. The root entry re-exports all of it.

Every record type has its own interface, with fields named as the RFCs name them, in
camelCase. A value inside a record stays as it was on the wire: names keep their case,
binary data is hex or base64, TTLs and RRSIG times are numbers of seconds.

Text that is a character-string on the wire (TXT strings, the CAA tag and value, HINFO, the
URI target, and NAPTR's flags, services and regexp) keeps every byte, the way names do:
valid UTF-8 as it is, a backslash as `\\`, and any other byte as `\DDD`. So the TXT bytes
`"`, `\` and 0xFF read `"\\\255`, as `dig` writes them, and a NAPTR regexp's `\1` reads
`\\1`. The `/promises` facade undoes the escapes, as Node does.

Supported: A, AAAA, CAA, CDNSKEY, CDS, CERT, CNAME, DNAME, DNSKEY, DS, HINFO, HTTPS, KEY,
LOC, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, PTR, RP, RRSIG, SIG, SOA, SRV,
SSHFP, SVCB, TLSA, TSIG, TXT and URI. A record of any other type, or one whose data is
malformed, comes back in a generic form (`type: 'TYPE65280'`, `data` in hex); `strict: true`,
on a resolver or on `decodeRecord(s)`, makes malformed data an error.

## Formatting and helpers

```ts
import {
  flattenRecords,
  formatRecord,
  parseRecord,
  reverseIp,
  typeCode,
  typeName,
} from '@aoxborrow/dns/records';

const mx = parseRecord({ name: 'example.com', type: 'MX', ttl: 300, data: '0 .' });

formatRecord(mx); // 'example.com.\t300\tIN\tMX\t0 .', a zone-file line
flattenRecords([mx]); // [{ name: 'example.com', type: 'MX', class: 'IN', ttl: 300, data: '0 .' }]

reverseIp('8.8.8.8'); // '8.8.8.8.in-addr.arpa'
typeCode('HTTPS'); // 65
typeName(65280); // 'TYPE65280': a type with no name comes back in the RFC 3597 form
```

Also here: `formatRecordData`, `deduplicateRecords`, `sortRecords`, `decodeRecord(s)`, the
protocol tables (`RECORD_TYPES`, `RECORD_CLASSES`, `RCODES`, `OPCODES`, `EDNS_OPTIONS`,
`EXTENDED_DNS_ERRORS`), the EDNS option builders and decoders, and the DNSSEC record-data
decoders (`decodeRrsig`, `decodeDnskey`, `decodeDs`, `decodeNsec`, `decodeNsec3`,
`decodeNsec3Param`, `decodeTypeBitmap`), which throw `ParseError` for malformed data.

The rest of the entry:

| Name                                    |                                                                                                                                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `flattenRecord`                         | one record, as `flattenRecords` gives each record of a list                                                                                                                                      |
| `parseRecordData`, `hasRecordParser`    | a record's data alone, from presentation format to typed fields; and whether a type has a presentation format of its own. Any type can be written in the RFC 3597 generic form (`\# 4 c0000201`) |
| `isKnownRecordType`                     | whether a type code is one the library decodes into fields of its own                                                                                                                            |
| `classCode`, `className`                | a class's code and its mnemonic, as `typeCode` and `typeName` are for a type                                                                                                                     |
| `parseIpv4`, `parseIpv6`                | the bytes of an address written as text, or `null` when the text is not one                                                                                                                      |
| `formatSignatureTime`                   | an RRSIG time, in seconds since 1970, as a zone file writes it: `YYYYMMDDHHmmSS`                                                                                                                 |
| `serviceParamName`                      | the name of an SVCB or HTTPS parameter key: its mnemonic, or `key<n>`                                                                                                                            |
| `decodeEdnsOptions`, `decodeEdnsOption` | a message's EDNS options, or one of them, typed. An option that does not fit its layout comes back as unknown, with its bytes                                                                    |
| `HEADER_FLAGS`                          | the bits of the header's flags word                                                                                                                                                              |
| `DEFAULT_UDP_PAYLOAD_SIZE`              | 1232, the UDP payload size a query advertises unless told otherwise                                                                                                                              |

## Validating records

The same entry checks records written by a person or held by a DNS provider. These are
pure functions and touch no network. A record is given as a `FlatRecord`:
`{ name, type, class?, ttl, data }`, with the class `IN` when left out.

```ts
import { RecordSyntaxError } from '@aoxborrow/dns';
import {
  canonicalRecord,
  diffRecords,
  findCnameConflicts,
  parseRecord,
} from '@aoxborrow/dns/records';

// text to a typed record
parseRecord({ name: 'example.com', type: 'MX', ttl: 300, data: '10 mail.example.com.' });
// { name: 'example.com', type: 'MX', class: 'IN', ttl: 300, preference: 10, exchange: 'mail.example.com' }

// or a RecordSyntaxError listing every problem, each with a code and its values
try {
  parseRecord({ name: 'example.com', type: 'A', ttl: 300, data: '300.1.2.3' });
} catch (error) {
  if (error instanceof RecordSyntaxError) {
    error.problems;
    // [{ code: 'invalid-address', values: { field: 'address', text: '300.1.2.3' },
    //    detail: '"300.1.2.3" is not an IPv4 address', name: 'example.com', type: 'A' }]
  }
}

// one spelling for records that mean the same thing
canonicalRecord({ name: 'Example.COM.', type: 'txt', ttl: 300, data: 'v=spf1 -all' });
// { name: 'example.com', type: 'TXT', class: 'IN', ttl: 300, data: '"v=spf1 -all"' }

// what a zone should hold against what it does, TTLs aside unless `compareTtl` is set
diffRecords(
  [{ name: 'example.com', type: 'A', ttl: 300, data: '192.0.2.1' }],
  [{ name: 'example.com', type: 'A', ttl: 300, data: '192.0.2.2' }]
);
// { missing: [{ …, data: '192.0.2.1' }], unexpected: [{ …, data: '192.0.2.2' }] }

// a name with a CNAME and anything else
findCnameConflicts([
  { name: 'www.example.com', type: 'CNAME', ttl: 300, data: 'example.com.' },
  { name: 'www.example.com', type: 'A', ttl: 300, data: '192.0.2.1' },
]);
// [{ code: 'cname-and-other-data', values: { types: ['A'] }, name: 'www.example.com', type: 'CNAME',
//    detail: 'www.example.com has a CNAME record, so it cannot also have A records' }]
```

`detail` is English for showing to a person; a program acts on `code` and `values`. The
codes are listed in the `RecordProblemValues` type, with the values each carries. The
checks over sets of records (`findCnameConflicts`, `findRepeatedRecords`) return problems
as data; `parseRecord`, `canonicalRecord` and `diffRecords` throw one `RecordSyntaxError`
holding all of them. Pass `{ zone }` to reject a record whose name is outside the zone.

Names given to the validators are full names. `qualify()` expands names written relative
to a zone, `@` included, in the record's name and in its data; `relativize()` writes them
short again. As in a zone file (RFC 1035 §5.1), a name without a trailing dot is relative
to the zone.

```ts
import { qualify, relativize } from '@aoxborrow/dns/records';

qualify({ name: '@', type: 'MX', ttl: 300, data: '10 mail' }, 'example.com');
// { name: 'example.com', type: 'MX', ttl: 300, data: '10 mail.example.com.' }

relativize(
  { name: 'www.example.com', type: 'CNAME', ttl: 300, data: 'example.com.' },
  'example.com'
);
// { name: 'www', type: 'CNAME', ttl: 300, data: '@' }
```
