# Upgrading from dns-client 0.x

`@aoxborrow/dns` 1.0 replaces `@aoxborrow/dns-client` 0.x. It is a rewrite: nothing carries
over unchanged, and there is no compatibility layer. `@aoxborrow/dns-client` 0.2.0 stays on
npm for anyone who needs it, and receives no further work.

What you get for the change: no runtime dependencies (0.x was built on `dns-packet` and
`buffer`), DNS over TLS, proxies, a resolver that walks from the root and moves on from
servers that do not help, record validation, DNSSEC validation, a `node:dns/promises`
facade, and record types that 0.x asked for wrongly (HTTPS, SVCB, OPENPGPKEY and URI went
out as type 0 and came back empty).

## The package

| 0.x | 1.0 |
| --- | --- |
| `npm install @aoxborrow/dns-client` | `npm install @aoxborrow/dns` |
| ES modules only | ES modules only, unchanged |
| Node 18 or later | Node 22 or later |
| one entry point | the root, plus `/records`, `/wire`, `/dnssec`, `/transports`, `/transports/doh` and `/promises`. The root holds the resolvers, the errors and the types an answer is made of; the record helpers and tables are in `/records`, the codec in `/wire` |
| `dns-packet` and `buffer` as dependencies | no dependencies. Bytes are `Uint8Array`, never `Buffer` |

If all you used was a lookup by type, the [`/promises`](docs/promises.md) facade may be
the shortest way across: it has the `node:dns/promises` API.

## The client

`DnsClient` is gone. There are two resolvers, and each asks one question at a time.

```ts
// 0.x
import { DnsClient } from '@aoxborrow/dns-client';

const client = new DnsClient({ server: '1.1.1.1' });
const [a, mx] = await client.query({ query: 'example.com', types: ['A', 'MX'] });
```

```ts
// 1.0
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1'] });
const [a, mx] = await Promise.all([
  resolver.query('example.com', 'A'),
  resolver.query('example.com', 'MX'),
]);
```

| 0.x | 1.0 |
| --- | --- |
| `new DnsClient()` | `new Resolver()` |
| `new DnsClient({ authoritative: true })` | `new AuthoritativeResolver()` |
| `client.query({ query, types })` returning `DnsAnswer[]` | `resolver.query(name, type)` returning one `Answer`. For several types, call it for each |
| `client.query({ query, server })` | `resolver.query(name, type, { server })`. That query neither reads nor fills the cache |
| `client.queryAll([…])` | `Promise.all([…])` over `resolver.query()` |
| the default server `1.1.1.1` | the resolvers this machine is set up to use (on Node). Pass `servers: ['1.1.1.1']` for the old behaviour |

`Resolver` takes a list of servers, tried in order: the next is asked when one fails or
answers SERVFAIL, NOTIMP or REFUSED. Both resolvers have `close()`, which closes the
sockets they opened, and `clearCache()`.

## Options

| 0.x | 1.0 |
| --- | --- |
| `server: '1.1.1.1'` | `servers: ['1.1.1.1']` on `Resolver`. For one query only: `resolver.query(name, type, { server })` |
| `transport: 'udp' \| 'tcp' \| 'doh'` | the same, plus `'tls'`. `AuthoritativeResolver` takes `'udp'` or `'tcp'` |
| `transport: 'doh'` with `server: 'https://…'` | `servers: ['https://…']`. A URL is asked over DNS over HTTPS without naming the transport |
| `authoritative: true` | `AuthoritativeResolver` |
| `flags: ['RD']` | `recursionDesired: true` (the default on `Resolver`; `AuthoritativeResolver` never sets it) |
| `flags: ['CD']` | `checkingDisabled: true` |
| `flags: ['DO']` | `dnssecOk: true` |
| `tcpFallback` | `tcpFallback`. When the TCP retry fails, the truncated answer comes back as it came, `flags.tc` set, with the TCP error in `answer.tcpFallbackError` |
| `timeout` | `timeout`, unchanged: milliseconds per attempt |
| `retries: 0` by default | `retries: 2` by default, or 1 when there are other servers to turn to |
| `backoff` | removed. A retry is sent as soon as the attempt before it has failed |
| `signal` on the client | `signal` on each `query()`. An aborted query rejects with the signal's reason |
| `cache: true`, `cacheSize: 1000` | `cache: { max: 1000 }` (the default), `cache: false`, or a cache of your own. `AuthoritativeResolver` takes `cache: true \| false`, which caches delegations, and `nameserverCache: true \| false`, which caches the addresses of nameservers that came without glue; neither caches answers |
| `concurrency: 10` by default | `concurrency`, no limit by default. Each server also has a limit of its own, `serverConcurrency` |

Options can be set on the resolver for every query, or passed to one `query()`.

## Defaults to know about

These are new, or differ from what 0.x did.

| Setting | 1.0 default | |
| --- | --- | --- |
| `servers` (`Resolver`) | this machine's resolvers | 0.x asked 1.1.1.1 |
| `serverConcurrency` | 16 (`Resolver`), 8 (`AuthoritativeResolver`) | queries in flight to one server at once. `Infinity` for no limit |
| server order (`AuthoritativeResolver`) | random, drawn afresh each time | for root servers, nameservers and addresses. There is no option to fix it; the trace says which servers were asked |
| `addressFamily` (`AuthoritativeResolver`) | `'both'`, IPv4 first | a server's IPv6 address is tried once each of the zone's servers has been tried at its first address. `'ipv4'` for IPv4 only |
| `totalTimeout` (`AuthoritativeResolver`) | 10 seconds | the time one answer may take altogether, on top of `timeout` per server |
| `udpPayloadSize` | 1232 | the EDNS buffer size, as DNS Flag Day 2020 recommends |

## The answer

An `Answer` is plain data, with no methods: it can be cached, logged or sent as it is.

| 0.x `DnsAnswer` | 1.0 `Answer` |
| --- | --- |
| `query` | `name` |
| `type` | `type` |
| `server` | `server` |
| `serverHost` | `serverName`, absent when unknown, not `null` |
| `elapsed`, `rcode`, `rcodeName` | unchanged, and never `null` |
| `bytes`, the response's size | `bytes` is now the response itself, a `Uint8Array`; its size is `bytes.length` |
| `flags: ['RD', 'RA', 'AD']` | `flags: { rd: true, ra: true, ad: true, … }` |
| `extendedErrors` as an object keyed by name | `extendedErrors` as an array of `{ infoCode, purpose, extraText }` |
| `ednsOptions` | `message.edns.options` as bytes, or typed with `decodeEdnsOptions(answer.message.edns)` |
| `records`, `authorities`, `additionals` | `records` is now only the records that answer the question, typed by the type asked for. `answers`, `authorities` and `additionals` are the three sections in full |
| `trace` | `trace`, on answers from `AuthoritativeResolver` only. A hop is `{ server, serverName, zone, name, type, transport, rcode, rcodeName, referral, bytes, elapsed, timestamp, error }` |
| `error` | removed. Errors are thrown |

New on the answer: `class`, `message` (the decoded response), `query` (the query as sent),
`port`, `url`, `transport`, `attempts`, `timestamp`, `cached`, and `security` when
validating.

The `dig` command for an answer is a function of it:

```ts
import { Resolver, toDig } from '@aoxborrow/dns';

const answer = await new Resolver().query('example.com', 'A');
toDig(answer); // 'dig @192.0.2.53 example.com A'
```

## Errors

A failed query now throws. In 0.x it came back as an answer with `error` set; in 1.0 an
`Answer` is always a response from a server, and an error is always thrown. A name that
does not exist, or has no records of the type, is still an answer: `rcodeName: 'NXDOMAIN'`,
or `'NOERROR'` with empty `records`. See
[Reading a negative answer](README.md#reading-a-negative-answer).

```ts
// 0.x
const [answer] = await client.query({ query: 'example.com', types: ['A'] });
if (answer.error) {
  if (answer.error.shouldRetry()) retryLater();
}
```

```ts
// 1.0
import { DnsError, Resolver } from '@aoxborrow/dns';

const resolver = new Resolver();
const retryLater = () => {};

try {
  const answer = await resolver.query('example.com', 'A');
} catch (error) {
  if (error instanceof DnsError && error.retryable) retryLater();
}
```

| 0.x | 1.0 |
| --- | --- |
| `error.shouldRetry()` | `error.retryable` |
| `RetryableDnsError` | removed. Check `retryable` |
| `error.code`, `error.errno`, `error.syscall` | removed. An error is told apart by its class (and `name`); one raised from a response carries `rcode` and `rcodeName`. Node's string codes exist only in `/promises` |
| `TimeoutError`, `ConnectionError` | the same names |
| `InvalidResponseError` | the same name, no longer retryable |
| `ParsingError` | `ParseError` |
| `TruncatedResponseError` | `TruncatedError`, when a TCP, TLS or HTTPS answer comes back truncated. A truncated UDP answer with `tcpFallback` off, or one whose TCP retry failed, is returned as it came |
| `ServerNotFoundError` | `NoServerError` |
| `ConfigurationError` (an invalid record type) | `InvalidQueryError` |
| `AbortError` | the signal's reason, as `fetch` does |
| `toDnsError(error)` | removed |
| | new: `ProxyError`, `EmptyResponseError`, `RecordSyntaxError` |

Every error also carries `server`, `query`, `type` and `transport` where known, and
`failures` when a resolver asked more than one server. Error classes are one set across all
entries, so `instanceof` works whichever entry threw.

## Records

Fields are named as the RFCs name them, in camelCase. Every record has `name`, `type`,
`class` and `ttl`, as before. Names have no trailing dot and keep the case the server sent.

| Record | 0.x | 1.0 |
| --- | --- | --- |
| NS, CNAME, PTR, DNAME | `value` | `target` |
| TXT | `value`, the strings joined | `strings`, an array of the character-strings as sent |
| MX | `priority` | `preference` |
| SOA | `nsname`, `hostmaster` | `mname`, `rname` |
| DS, CDS | `key_tag`, `digest_type` | `keyTag`, `digestType` |
| DNSKEY, CDNSKEY, KEY | `public_key` | `publicKey` |
| RRSIG, SIG | `type_covered`, `original_ttl`, `signature_expiration`, `signature_inception`, `key_tag`, `signer_name` | `typeCovered`, `originalTtl`, `signatureExpiration`, `signatureInception`, `keyTag`, `signerName` |
| NSEC, NSEC3 | `next_domain`, `rr_types` | `nextDomain`, `types` |
| TLSA | `mtype`, `cert` | `matchingType`, `certificate` |
| SSHFP | `fp_type` | `fingerprintType` |
| NAPTR | `service` | `services` |
| HTTPS, SVCB | `svc_priority`, `target_name`, `svc_params` | `priority`, `target`, `params` |
| CERT | `certificate_type`, a string; `key_tag` | `certificateType`, a number; `keyTag` |
| TSIG | `time_signed`, `original_id`, `other_data`, `mac_size`, `other_len` | `timeSigned`, `originalId`, `otherData`. The two lengths are gone: `mac` and `otherData` are base64 of exactly those bytes |
| CAA | `tag`, a `CaaTag` or a string | `tag`, a string. `CaaTag` is removed |
| LOC | `size`, `horiz_pre`, `vert_pre`, as text | `size`, `horizontalPrecision`, `verticalPrecision`, as numbers in metres |

Two values are corrected, not only renamed. A type in an NSEC or NSEC3 type list that 0.x
had no name for was `UNKNOWN_65` and is now its name (`HTTPS`), or `TYPE65280` where it has
none. A zero byte in an NSEC next name was dropped and is now written `\000`.

A record whose type the library does not know, or whose data is malformed, comes back in a
generic form (`type: 'TYPE65280'`, `data` in hex). Pass `strict: true` to make malformed
data an error.

## Helpers and constants

These are in `/records` unless the row names another entry.

| 0.x | 1.0 |
| --- | --- |
| `getRecords(answers)` | `answers.flatMap(answer => answer.records)` |
| `deduplicateRecords(records)` | `deduplicateRecords(records)`, unchanged |
| `flattenRecord(record)` | `flattenRecord(record)`, the same name, returning the new shape below |
| `flattenRecords(records)` returning `{ name, type, ttl, content }` | `flattenRecords(records)` returning `{ name, type, class, ttl, data }` |
| `reverseIp(ip)` | `reverseIp(ip)`, unchanged |
| `sortRecordsCanonical` | `sortRecords` |
| `compareHostnamesCanonical` | `compareNames` (`/wire`) |
| `countDomainLevels` | `countLabels` (`/wire`) |
| `isValidIpv4`, `isValidIpv6`, `isValidIp` | `parseIpv4`, `parseIpv6`, which return the bytes or `null` |
| `toBase32Hex` | `toBase32Hex` (`/wire`) |
| `parseEdnsOptions`, `parseEdnsOption` | `decodeEdnsOptions`, `decodeEdnsOption` |
| `parseExtendedDnsErrors` | `extendedErrors` |
| `parsePacketOptions` | `answer.message.edns`: the OPT record is read into `edns`, never returned as a record |
| `parseDnssecAlgorithm` | removed. `parseRecordData` reads an algorithm, by number or mnemonic, with the rest of the record's data, and `algorithmName` (`/dnssec`) gives the mnemonic for a number |
| `createGenericRecord` | removed. `decodeRecord` returns a record it has no fields for in the generic form |
| `parseRaw…Record`, `parsePacketAnswer` | `decodeRecord`, `decodeRecords`. The DNSSEC record-data decoders (`decodeRrsig`, `decodeDnskey`, `decodeDs`, `decodeNsec`, `decodeNsec3`, `decodeNsec3Param`) are in `/records` and throw `ParseError` for malformed data |
| `createDnsPacket`, `DnsPacket` (from `dns-packet`) | `encodeQuery`, `decodeMessage` and `Message` (`/wire`) |
| `A_RECORD`, `MX_RECORD` and the other `*_RECORD` constants | the strings themselves (`'A'`, `'MX'`), typed |
| `DNS_RECORD_TYPES`, `DNS_RECORD_CODES_IANA` | `RECORD_TYPES`, `typeCode`, `typeName` |
| `DNS_RECORD_CLASSES` | `RECORD_CLASSES` |
| `DNS_RESPONSE_CODES` | `RCODES`, `rcodeName` |
| `DNS_FLAGS`, `FLAG_*` | `HEADER_FLAGS`, and flags as an object of booleans |
| `DNS_QUERY_FLAGS`, `DNS_TEXT_RECORD_TYPES` | removed |
| `EDNS_OPTIONS`, `EXTENDED_DNS_ERRORS` | the same names |
| `DEFAULT_OPTIONS`, `DEFAULT_PUBLIC_DNS_SERVER`, `DEFAULT_PUBLIC_DOH_SERVER`, `DNS_TRANSPORT_*` | removed |
| `naturalSort`, `naturalCompare`, `stripTrailingDot`, `normalizeHost`, `stripProtocol`, `sanitizeString`, `sortObjectKeys`, `isEmpty`, `getRandomRootServer`, `detectDohServer`, `getQueryFlagsBitmask` | removed |

## Types

The record interfaces keep their names (`DnsRecord`, `ARecord`, `MxRecord` and the rest), with
the fields above. `RecordOf<'MX'>` is `MxRecord`.

| 0.x | 1.0 |
| --- | --- |
| `DnsAnswer` | `Answer` |
| `DnsOptions` | `ResolverOptions`, `AuthoritativeResolverOptions` |
| `DnsResolutionHop` | `TraceHop` |
| `DnsRecordType`, `RecordType` | `KnownRecordType` for the types the library decodes, `RecordTypeName` for every mnemonic in the registry |
| `DnsRecordClass` | `RecordClassName` |
| `DnsResponseType` | `RcodeName` |
| `DnsRecordCode`, `DnsResponseCode` | `number` |
| `DnsTransportType` | `TransportName` |
| `DnsQuery`, `DnsQuestion`, `DnsTransportQuery` | removed: a question is `query(name, type, options)`. `Query` (`/wire`) is what `encodeQuery` takes |
| `DnsFlag`, `DnsQueryFlag`, `QueryFlag` | removed: flags are booleans, in `HeaderFlags` and the query settings |
| `DnsExtendedErrorCode`, `DnsExtendedErrors` | `ExtendedErrorOption` |
| `FlatDnsRecord` | `FlatRecord` (`/records`) |
| `EdnsOption`, and `EdnsNsid`, `EdnsClientSubnet`, `EdnsCookie`, `EdnsTcpKeepAlive`, `EdnsPadding`, `EdnsDnssecCapability`, `EdnsKeyTag` | `TypedEdnsOption`, and `NsidOption`, `ClientSubnetOption`, `CookieOption`, `TcpKeepaliveOption`, `PaddingOption`, `AlgorithmsOption`, `KeyTagOption` (`/records`) |
| `RawEdnsOption`, `EdnsBaseOption`, `EdnsOptionType`, `EdnsOptionCode`, `EdnsOptionCodeByType` | `EdnsOption`, an option's code and bytes, a different type from 0.x's of that name; `EDNS_OPTIONS` for the codes |
| `OptRecord` | `Edns`, as `message.edns` |
| `PacketAnswer`, `PacketQuestion`, `DnsPacket` | `ResourceRecord`, `Question`, `Message` |

## New in 1.0

- Record validation: `parseRecord`, `canonicalRecord`, `diffRecords`,
  `findCnameConflicts`, `findRepeatedRecords`, `qualify` and `relativize`, with every
  problem as a code and its values. See [Validating records](docs/records.md#validating-records).
- DNSSEC validation with `validate: true` on either resolver, the judging core and its
  primitives. See [DNSSEC](docs/dnssec.md).
- The `node:dns/promises` facade, with `connectLookup` for `net.connect` and undici. See
  [`/promises`](docs/promises.md).
- DNS over TLS, DNS over HTTPS over HTTP/2 on Node, SOCKS5 and HTTP CONNECT proxies, and
  `onEvent` for logging and metrics.
