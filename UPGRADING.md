# Upgrading from 0.x to 1.0

1.0 is a rewrite. Nothing in 0.x carries over unchanged, and there is no compatibility
layer: 0.2.0 stays on npm for anyone who needs it, and receives no further work.

What you get for the change: no runtime dependencies (0.x was built on `dns-packet`),
DNS over TLS, proxies, a resolver that walks from the root and moves on from servers that
do not help, record validation, DNSSEC primitives that verify signatures themselves, and
record types that 0.x asked for wrongly (HTTPS, SVCB, OPENPGPKEY and URI went out as type
0 and came back empty).

## The client

`DnsClient` is gone. There are two resolvers, and each asks one question at a time.

| 0.x | 1.0 |
| --- | --- |
| `new DnsClient()` | `new Resolver()` |
| `new DnsClient({ authoritative: true })` | `new AuthoritativeResolver()` |
| `client.query({ query, types: ['A', 'MX'] })` returning `DnsAnswer[]` | `resolver.query(name, 'A')` returning one `Answer`. For several types, call it for each: `Promise.all(types.map(type => resolver.query(name, type)))` |
| `client.queryAll([…])` | `Promise.all([…])` over `resolver.query()` |
| the default server `1.1.1.1` | the resolvers this machine is set up to use (on Node). Pass `servers: ['1.1.1.1']` for the old behaviour |

A failed query now throws. In 0.x it came back as an answer with `error` set; in 1.0 an
`Answer` is always a response from a server, and an error is always thrown. A name that
does not exist is still an answer (`rcodeName: 'NXDOMAIN'`).

## Options

| 0.x | 1.0 |
| --- | --- |
| `server: '1.1.1.1'` | `servers: ['1.1.1.1']` on `Resolver`, tried in order. For one query only: `resolver.query(name, type, { server })` |
| `transport: 'udp' \| 'tcp' \| 'doh'` | the same, plus `'tls'` |
| `transport: 'doh'` with `server: 'https://…'` | `servers: ['https://…']`. A URL is asked over DNS over HTTPS without naming the transport |
| `authoritative: true` | `AuthoritativeResolver` |
| `flags: ['RD']` | `recursionDesired: true` (the default) |
| `flags: ['CD']` | `checkingDisabled: true` |
| `flags: ['DO']` | `dnssecOk: true` |
| `tcpFallback` | `tcpFallback`, unchanged |
| `timeout` | `timeout`, unchanged. `AuthoritativeResolver` also has `totalTimeout` |
| `retries: 0` by default | `retries: 2` by default, or 1 when there are other servers to turn to |
| `backoff` | removed. A retry is sent as soon as the attempt before it has failed |
| `signal` on the client | `signal` on each `query()` |
| `cache: true`, `cacheSize: 1000` | `cache: { max: 1000 }`, `cache: false`, or a cache of your own. `AuthoritativeResolver` takes `cache: true \| false` |
| `concurrency: 10` by default | `concurrency`, no limit by default |

## The answer

| 0.x `DnsAnswer` | 1.0 `Answer` |
| --- | --- |
| `query` | `name` |
| `type` | `type` |
| `server` | `server` |
| `serverHost` | `serverName`, absent when unknown, not `null` |
| `elapsed`, `bytes`, `rcode`, `rcodeName` | `elapsed` and `rcode`, `rcodeName` unchanged. `bytes` is now the response itself, a `Uint8Array`; its size is `bytes.length` |
| `flags: ['RD', 'RA', 'AD']` | `flags: { rd: true, ra: true, ad: true, … }` |
| `extendedErrors` as an object keyed by name | `extendedErrors` as an array of `{ infoCode, purpose, extraText }` |
| `ednsOptions` | `message.edns.options` |
| `records`, `authorities`, `additionals` | `records` is now only the records that answer the question, typed by the type asked for. `answers`, `authorities` and `additionals` are the three sections in full |
| `trace` | `trace`, on answers from `AuthoritativeResolver` only. A hop is `{ server, serverName, zone, name, type, rcode, rcodeName, bytes, elapsed, timestamp, referral, error }` |
| `error` | removed. Errors are thrown, as `DnsError` subclasses with `retryable`, `server`, `query`, `type` and `transport` |

New on the answer: `message` (the decoded response), `port`, `transport`, `attempts`,
`timestamp`, `cached`, and `toDig()`.

## Records

Fields are named as the RFCs name them, in camelCase. Every record has `name`, `type`,
`class` and `ttl`, as before.

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
| CERT | `certificate_type` | `certificateType` |
| LOC | `horiz_pre`, `vert_pre` | `horizontalPrecision`, `verticalPrecision`, as numbers in metres |

Two values are corrected, not only renamed. A type in an NSEC or NSEC3 type list that 0.x
had no name for was `UNKNOWN_65` and is now its name (`HTTPS`), or `TYPE65280` where it has
none. A zero byte in an NSEC next name was dropped and is now written `\000`.

A record whose type the library does not know, or whose data is malformed, comes back in a
generic form (`type: 'TYPE65280'`, `data` in hex). Pass `strict: true` to make malformed
data an error.

## Helpers

| 0.x | 1.0 |
| --- | --- |
| `getRecords(answers)` | `answers.flatMap(answer => answer.records)` |
| `deduplicateRecords(records)` | `deduplicateRecords(records)`, unchanged |
| `flattenRecords(records)` returning `{ name, type, ttl, content }` | `flattenRecords(records)` returning `{ name, type, ttl, data }` |
| `reverseIp(ip)` | `reverseIp(ip)`, unchanged |

## DNSSEC analysis

This one breaks code written against the 1.0.0-dev builds, not 0.x. Those builds also
carried a chain-of-trust analysis, which has moved out of the library into DNS.Tools.
`@aoxborrow/dns-client/dnssec` now holds only the primitives a validator is built from.

| 1.0.0-dev | 1.0 |
| --- | --- |
| `analyze(name, options)`, `DnssecEngine` | removed. Walking a chain of trust and reaching a verdict is left to the caller, built from the primitives |
| `AnalyzeOptions`, `DnssecReport`, `EngineOptions`, `EngineOutput` | removed with them |
| `@aoxborrow/dns-client/dnssec/types`: the report types, the finding catalog and the status vocabularies | removed. The primitives' own types (`DenialProof`, `ProofStep`, `TrustAnchor`, `Nsec3Params`, `VerificationResult` and the like) come from `@aoxborrow/dns-client/dnssec` |
| `KSK_2024_SIGNING_DATE`, `KSK_2017_REVOCATION_DATE` | removed. `ROOT_TRUST_ANCHORS` and `isAnchorCurrent` remain |

## Requirements

Node 20 or later (0.x allowed 18). The package now ships CommonJS as well as ES modules.
