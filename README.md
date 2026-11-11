# dns-client

A DNS client for TypeScript with nothing underneath it: its own wire codec, typed records,
resolvers that ask a recursive resolver or walk from the root, record validation, and a
DNSSEC analysis that verifies every signature itself. No runtime dependencies.

```bash
npm install @aoxborrow/dns-client
```

**Status:** 1.0 is a rewrite and is in pre-release. It is not compatible with 0.x; see
[UPGRADING.md](UPGRADING.md) for what changed and what replaces what.

## Asking a question

```ts
import { Resolver } from '@aoxborrow/dns-client';

// an ordinary recursive query, like dig or node:dns, to the resolvers this machine uses
const resolver = new Resolver();
const answer = await resolver.query('example.com', 'MX');

answer.rcodeName; // 'NOERROR'
answer.records; // MxRecord[]: [{ name, type: 'MX', class: 'IN', ttl: 300, preference: 0, exchange: '.' }]
answer.server; // '192.0.2.53', whichever resolver answered
answer.toDig(); // 'dig @192.0.2.53 example.com MX'
```

Name the resolvers to use, or ask one particular server for one query:

```ts
const resolver = new Resolver({ servers: ['1.1.1.1', '8.8.8.8'] });

// this server and no other, over TCP, outside the cache
const txt = await resolver.query('example.com', 'TXT', { server: '9.9.9.9', transport: 'tcp' });
txt.records.map(record => record.strings); // [['v=spf1 -all'], …]
```

A server is an address, a name, `host:port`, or an `https://` URL, which is asked over DNS
over HTTPS (`https://cloudflare-dns.com/dns-query`). For DNS over TLS, name the server and
set `transport: 'tls'`.

`Resolver` caches by TTL, shares one query between callers asking the same thing at the
same moment, and moves to the next server when one fails or answers SERVFAIL, NOTIMP or
REFUSED.

### From the root

```ts
import { AuthoritativeResolver } from '@aoxborrow/dns-client';

const resolver = new AuthoritativeResolver();
const answer = await resolver.query('example.com', 'A');

answer.flags.aa; // true: this is what the zone's own server says
answer.trace; // every server asked on the way
// [ { zone: '.',           serverName: 'a.root-servers.net',        referral: 'com' },
//   { zone: 'com',         serverName: 'a.gtld-servers.net',        referral: 'example.com' },
//   { zone: 'example.com', serverName: 'elliott.ns.cloudflare.com', rcodeName: 'NOERROR' } ]
```

It asks no resolver. It starts at the root servers and follows referrals to the zone's own
nameservers, remembers delegations for as long as their TTLs allow, looks up nameservers
that come without an address, and moves on from a server that refuses, fails or stays
silent. It stops at an alias into another zone unless `followCnames` is set.

### The answer

Both resolvers have one method, `query(name, type, options?)`, and return the same thing:

| Field | |
| --- | --- |
| `rcode`, `rcodeName`, `flags` | what the server said about the question |
| `records` | the records that answer it, typed by the type you asked for |
| `answers`, `authorities`, `additionals` | every record in each section, typed |
| `extendedErrors` | extended DNS errors (RFC 8914), when the server sent any |
| `message`, `bytes` | the response decoded from the wire, and exactly as it arrived |
| `server`, `serverName`, `port`, `transport` | who answered, and how |
| `elapsed`, `attempts`, `timestamp`, `cached` | how long it took, how many tries, when, and whether it came from the cache |
| `trace` | `AuthoritativeResolver` only: every hop from the root |
| `toDig()` | the `dig` command that asks the same question |

A name that does not exist is an answer (`rcodeName: 'NXDOMAIN'`, no records), not an
error.

### Options

These can be set on a resolver for every query, or passed to one `query()`:

| Option | Default | |
| --- | --- | --- |
| `transport` | `'udp'` | `'udp'`, `'tcp'`, `'tls'` or `'doh'`. TCP where there is no UDP; DoH for a server given as a URL |
| `timeout` | `5000` | milliseconds of patience with one server |
| `retries` | `2` | further attempts at a server that fails in a way worth retrying. One, when there are other servers to turn to |
| `tcpFallback` | `true` | ask again over TCP when a UDP answer is truncated |
| `recursionDesired` | `true` | the RD flag. `AuthoritativeResolver` never sets it |
| `dnssecOk` | `false` | the DO bit: ask for signatures with the answer |
| `checkingDisabled` | `false` | the CD flag: ask a validating resolver not to hold an answer back |
| `authenticData` | `false` | the AD flag in the query: ask to be told whether the answer validated |
| `udpPayloadSize` | `1232` | the largest UDP answer this client will accept |
| `ednsOptions` | none | EDNS options to send: `nsidOption()`, `clientSubnetOption()`, `cookieOption()`, `paddingOption()` |
| `edns` | on | `false` sends a plain RFC 1035 query |
| `signal` | none | an `AbortSignal`, per query |

`Resolver` also takes `servers`, `cache` (false, your own, or settings for the built-in
one), `maxTtl`, `concurrency` and `strict`. `AuthoritativeResolver` also takes
`rootServers`, `addressFamily` (`'ipv4'` by default), `followCnames`, `hosts`,
`nameserverOrder`, `addressOrder`, `resolveNameserver`, `cache`, `serverDelay`,
`concurrency`, `maxHops`, and `totalTimeout`: the time one answer may take altogether (30
seconds by default), since a zone whose servers all stay silent would otherwise cost a
timeout for each of them.

Both take `onEvent`, which is told about every query sent, every retry, every fallback to
TCP and every proxy connection. That is where logging and metrics attach; the library
itself prints nothing.

### Errors

An error means no usable response arrived. Every one is a `DnsError` subclass:

```ts
import { DnsError } from '@aoxborrow/dns-client';

try {
  await resolver.query('example.com', 'A');
} catch (error) {
  if (error instanceof DnsError) {
    error.name; // 'TimeoutError'
    error.retryable; // true: asking again could work
    error.server; // '192.0.2.1'
    error.message; // 'No answer from 192.0.2.1 within 5000 ms'
  }
}
```

| Error | Retryable | |
| --- | --- | --- |
| `TimeoutError` | yes | the server said nothing in time |
| `ConnectionError` | yes | the server could not be reached |
| `ProxyError` | yes | the proxy refused or failed |
| `EmptyResponseError` | yes | a connection closed without an answer |
| `TruncatedError` | no | a truncated answer, with `tcpFallback` off |
| `InvalidResponseError` | no | an answer that does not match the question, or a walk that leads nowhere |
| `ParseError`, `RecordSyntaxError` | no | bytes or text that are not valid DNS |
| `InvalidQueryError` | no | a question that cannot be asked |
| `NoServerError` | no | no resolver to ask |

An error from `AuthoritativeResolver` carries `trace`, the servers asked before it failed.

## Records

Every record type has its own interface, with fields named as the RFCs name them. A value
inside a record stays as it was on the wire: names keep their case, binary data is hex or
base64, times are numbers.

```ts
import { formatRecord, flattenRecords, reverseIp, typeCode, typeName } from '@aoxborrow/dns-client/records';

formatRecord(answer.records[0]); // 'example.com.\t300\tIN\tMX\t0 .', a zone-file line
flattenRecords(answer.records); // [{ name: 'example.com', type: 'MX', ttl: 300, data: '0 .' }]

reverseIp('8.8.8.8'); // '8.8.8.8.in-addr.arpa'
typeCode('HTTPS'); // 65
typeName(65280); // 'TYPE65280': a type with no name comes back in the RFC 3597 form
```

Supported: A, AAAA, CAA, CDNSKEY, CDS, CERT, CNAME, DNAME, DNSKEY, DS, HINFO, HTTPS, KEY,
LOC, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, PTR, RP, RRSIG, SIG, SOA, SRV,
SSHFP, SVCB, TLSA, TSIG, TXT and URI. A record of any other type, or one whose data is
malformed, comes back in a generic form with its data in hex; `strict: true` makes
malformed data an error.

### Checking records before saving them

The same package checks records written by a person or held by a DNS provider. These are
pure functions and touch no network:

```ts
import { canonicalRecord, diffRecords, findCnameConflicts, parseRecord } from '@aoxborrow/dns-client/records';

// text to a typed record, or a RecordSyntaxError saying what is wrong
parseRecord({ name: 'example.com', type: 'MX', ttl: 300, data: '10 mail.example.com.' });
// { name: 'example.com', type: 'MX', class: 'IN', ttl: 300, preference: 10, exchange: 'mail.example.com' }

parseRecord({ name: 'example.com', type: 'A', ttl: 300, data: '300.1.2.3' });
// RecordSyntaxError: "300.1.2.3" is not an IPv4 address

// one spelling for records that mean the same thing
canonicalRecord({ name: 'Example.COM.', type: 'txt', ttl: 300, data: 'v=spf1 -all' });
// { name: 'example.com', type: 'TXT', ttl: 300, data: '"v=spf1 -all"' }

// what a zone should hold against what it does
diffRecords(intended, actual); // { missing: […], unexpected: […] }

// a name with a CNAME and anything else
findCnameConflicts(records); // [{ name: 'www.example.com', type: 'CNAME', detail: '…' }]
```

Names are full names. `qualify()` and `relativize()` convert to and from names written
relative to a zone, `@` included.

## DNSSEC

```ts
import { analyze } from '@aoxborrow/dns-client/dnssec';

const report = await analyze('example.com');

report.overallStatus; // 'secure' | 'insecure' | 'bogus' | 'indeterminate'
report.chain; // every zone from the root down: keys, delegation, signatures, denial proofs
report.findings; // what is wrong or worth knowing, each with a stable slug
```

It asks the zones' own servers directly, with checking disabled, and verifies every
signature itself: RSA, ECDSA and EdDSA through WebCrypto, DS digests and NSEC3 hashes with
its own SHA-1, SHA-256 and SHA-384. An algorithm the runtime cannot verify is reported as
not checked, never as a pass. The `now` option judges signatures against a time other than
the present.

This is an analysis, a full report on a zone. The resolvers do not validate answers yet:
`dnssecOk` asks for signatures and `flags.ad` reports what a validating resolver decided.

## The wire format

```ts
import { decodeMessage, encodeQuery } from '@aoxborrow/dns-client/wire';

const bytes = encodeQuery({ id: 1234, name: 'example.com', type: 'A', recursionDesired: true });
const message = decodeMessage(response); // header, flags, question, three record sections, EDNS
```

`Uint8Array` in and out, no `Buffer`. Names are accepted in Unicode or punycode and
returned in ASCII.

## Where it runs

| Entry | Contents | Runs on |
| --- | --- | --- |
| `@aoxborrow/dns-client` | everything below | Node |
| `@aoxborrow/dns-client/records` | typed records, protocol tables, parsing, formatting, validation | anywhere |
| `@aoxborrow/dns-client/wire` | encoding queries and decoding messages | anywhere |
| `@aoxborrow/dns-client/transports/udp` | DNS over UDP on shared sockets | Node |
| `@aoxborrow/dns-client/transports/tcp` | DNS over TCP | Node, Cloudflare Workers |
| `@aoxborrow/dns-client/transports/tls` | DNS over TLS | Node, Cloudflare Workers |
| `@aoxborrow/dns-client/transports/doh` | DNS over HTTPS | anywhere with `fetch` |
| `@aoxborrow/dns-client/dnssec` | `analyze()` and its primitives | Node |
| `@aoxborrow/dns-client/dnssec/types` | report types, status constants, the finding catalog | anywhere |

Node 20 or later. The package ships ES modules and CommonJS, with type declarations for
both. Node built-ins are imported only by the transports, and only when a query needs
them, so the entries marked "anywhere" bundle for a browser with none.

On Cloudflare Workers there is no UDP, and Ed448 signatures cannot be verified. The codec,
the records, both resolvers and the DNSSEC primitives pass their tests inside the Workers
runtime, and the TCP, TLS and HTTPS transports have been run on a deployed Worker. A whole
lookup, resolver and transport together, has not yet been run on a deployed Worker.

## Proxies

Every transport can go through a SOCKS5 or HTTP CONNECT proxy. With `proxy` set nothing
goes around it: a query that cannot go through the proxy fails.

```ts
const resolver = new Resolver({ servers: ['1.1.1.1'], proxy: 'socks5://user:pass@proxy.example:1080' });
```

| Transport | Through the proxy |
| --- | --- |
| TCP, DNS over TLS | a tunnel to the server; TLS starts inside it |
| UDP | a SOCKS5 UDP association where the proxy offers one, otherwise TCP through the tunnel. The answer's `transport` says which |
| DNS over HTTPS | not by itself: pass a `fetch` that uses the proxy. Without one the query fails |

`proxy` can be a function that picks a proxy per server, or returns nothing to leave a
server unproxied. An explicit `connect` wins over `proxy` for TCP and TLS. Credentials
never appear in an error or an event.

On a deployed Cloudflare Worker TLS cannot start inside a tunnel, so the built-in tunnel
carries plain TCP there and nothing else. For DNS over HTTPS through a proxy on Workers,
pass a `fetch` that does its own TLS, such as
[`tunnelfetch`](https://github.com/latentharbor/tunnelfetch); that combination has not
been run with this library.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
