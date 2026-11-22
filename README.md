# @aoxborrow/dns

DNS for TypeScript, with no dependencies. Ask the resolvers you're configured with, or walk
from the root to each zone's own servers; validate answers with DNSSEC; read and write every
common record type as typed data. UDP, TCP, DNS over TLS and DNS over HTTPS, directly or
through a SOCKS5 or HTTP CONNECT proxy.

- **Two resolvers, one answer shape.** `Resolver` asks recursive resolvers, as `dig` does;
  `AuthoritativeResolver` walks from the root and returns the trace of every server asked.
- **DNSSEC validation** with `validate: true`: secure, insecure, bogus or indeterminate,
  with the reason as a code and the extended DNS error a validator would send.
- **33 typed record types**, parsing and validation of records in zone-file syntax, and a
  wire codec on `Uint8Array`.
- **A `node:dns/promises`-compatible API** in `@aoxborrow/dns/promises`, with a cache.
- **Runs in more places than Node:** the records, wire and DNSSEC entries run in browsers and
  Cloudflare Workers; DNS over HTTPS works anywhere with `fetch`.

**Status:** `1.0.0-beta.1`, on npm's `beta` tag. It replaces `@aoxborrow/dns-client` 0.x and
is not compatible with it; see [UPGRADING.md](UPGRADING.md).

- [Install](#install)
- [Quick start](#quick-start)
- [Which API do I want?](#which-api-do-i-want)
- [The answer](#the-answer)
- [Errors](#errors)
- [Scope](#scope)
- [Entry points](#entry-points)
- [Where it runs](#where-it-runs)
- [Documentation](#documentation)
- [Benchmarks](#benchmarks)

## Install

```bash
npm install @aoxborrow/dns@beta
```

ES modules with type declarations. Node 22 or later; `require()` from CommonJS works on Node
22.12 and later.

## Quick start

```ts network
import { Resolver, toDig } from '@aoxborrow/dns';

// the resolvers this machine is set up to use, as `dig` and `node:dns` would
const resolver = new Resolver();
const answer = await resolver.query('example.com', 'MX');

answer.rcodeName; // 'NOERROR'
answer.records; // MxRecord[]: [{ name: 'example.com', type: 'MX', class: 'IN', ttl: 300, preference: 0, exchange: '.' }]
answer.server; // '192.0.2.53', whichever resolver answered
toDig(answer); // 'dig @192.0.2.53 example.com MX'
```

Ask particular resolvers, over any transport, or one server for one query:

```ts network
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['https://cloudflare-dns.com/dns-query', '8.8.8.8'] });
const txt = await resolver.query('example.com', 'TXT');
txt.records.map(record => record.strings); // [['v=spf1 -all'], …]

// this server and no other, over TCP, outside the cache
await resolver.query('example.com', 'TXT', { server: '9.9.9.9', transport: 'tcp' });
```

Or ask each zone's own servers, starting at the root, and check the answer's signatures:

```ts network
import { AuthoritativeResolver } from '@aoxborrow/dns';

const resolver = new AuthoritativeResolver({ validate: true });
const answer = await resolver.query('example.com', 'A');

answer.flags.aa; // true: the zone's own server answered
answer.security?.status; // 'secure'
answer.trace?.map(hop => hop.serverName);
// ['e.root-servers.net', 'b.gtld-servers.net', 'hera.ns.cloudflare.com']: one of each zone's
// servers, picked at random each time
```

## Which API do I want?

| You want to…                                                           | Use                                                                                                         |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| swap out `node:dns/promises` and keep your code                        | [`@aoxborrow/dns/promises`](docs/promises.md)                                                               |
| look names up through recursive resolvers (the system's, 1.1.1.1, DoH) | [`Resolver`](docs/resolvers.md#resolver)                                                                    |
| see what a zone's own servers say, and which servers were asked        | [`AuthoritativeResolver`](docs/resolvers.md#authoritativeresolver)                                          |
| know whether an answer is DNSSEC-signed and valid                      | [`validate: true`](docs/dnssec.md) on either resolver; `@aoxborrow/dns/dnssec` for the parts               |
| parse, format, compare or validate records written as text             | [`@aoxborrow/dns/records`](docs/records.md)                                                                 |
| build and read raw DNS messages, or send them yourself                 | [`@aoxborrow/dns/wire`](docs/wire-and-transports.md) and [`/transports`](docs/wire-and-transports.md#transports) |

## The answer

An `Answer` is plain data: no methods, so it can be copied, cached, logged or sent as it
is. Functions that read it stand alone, such as `toDig(answer)`.

| Field                                              |                                                                                                                                                                                                                               |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`, `type`, `class`                            | the question, with the name as you wrote it, minus a trailing dot                                                                                                                                                             |
| `rcode`, `rcodeName`, `flags`                      | what the server said: `0`, `'NOERROR'`, `{ aa: true, rd: true, … }`                                                                                                                                                           |
| `records`                                          | the records that answer the question, typed by the type asked for, at the name or at the end of its alias chain                                                                                                               |
| `answers`, `authorities`, `additionals`            | every record in each section, typed                                                                                                                                                                                           |
| `extendedErrors`                                   | extended DNS errors (RFC 8914): `{ infoCode, purpose, extraText }[]`                                                                                                                                                          |
| `message`, `bytes`                                 | the response decoded from the wire, and exactly as it arrived                                                                                                                                                                 |
| `query`                                            | the query as it was sent: name, type, class, flags, EDNS                                                                                                                                                                      |
| `server`, `serverName`, `port`, `url`, `transport` | who answered, and how                                                                                                                                                                                                         |
| `elapsed`, `attempts`, `timestamp`, `cached`       | milliseconds taken, queries sent, when it arrived, whether it came from the cache                                                                                                                                             |
| `tcpFallbackError`                                 | the answer is a truncated UDP one (`flags.tc`), with whatever records it carried, because asking again over TCP failed: why, as plain error data. A hop in `trace` carries it too, for a truncated referral the walk followed |
| `trace`                                            | `AuthoritativeResolver` only: every server asked, from the root                                                                                                                                                               |
| `security`                                         | with `validate: true` only: what DNSSEC validation made of it                                                                                                                                                                 |

### Reading a negative answer

A name that does not exist, or has no records of the type asked for, is an answer, not an
error. Neither is thrown.

- **NXDOMAIN**: the name does not exist. `rcodeName` is `'NXDOMAIN'` and `records` is
  empty.
- **NODATA**: the name exists, with nothing of that type. `rcodeName` is `'NOERROR'` and
  `records` is empty.

Both carry the zone's SOA record in `authorities`; how long the negative answer may be
cached is the smaller of the SOA's TTL and its `minimum` field (RFC 2308). In a signed zone,
asked with `dnssecOk: true`, `authorities` also holds the NSEC or NSEC3 records that prove
the denial.

An error means no usable response arrived at all.

```ts network
import { DnsError, Resolver } from '@aoxborrow/dns';
import type { SoaRecord } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1'] });

try {
  const answer = await resolver.query('www.example.com', 'MX');
  const soa = answer.authorities.find((record): record is SoaRecord => record.type === 'SOA');

  if (answer.rcodeName === 'NXDOMAIN') {
    // the name does not exist
  } else if (answer.rcodeName === 'NOERROR' && answer.records.length === 0) {
    // the name exists, with no MX records
  } else if (answer.rcodeName === 'NOERROR') {
    // records
  } else {
    // SERVFAIL, REFUSED and the like: every server gave up on the question
  }
  // how long this negative answer may be kept, in seconds
  const negativeTtl = soa ? Math.min(soa.ttl, soa.minimum) : 0;
} catch (error) {
  if (error instanceof DnsError) {
    // no usable response: a timeout, a connection refused, a malformed reply
  }
}
```

The [`/promises`](docs/promises.md) facade turns both into errors, as `node:dns` does:
NXDOMAIN is `ENOTFOUND`, NODATA is `ENODATA`.

## Errors

An error means no usable response arrived. Every error the library throws is a `DnsError`,
told apart by its class (and `name`), never by a string code. Classes are one set across
every entry, so `instanceof` holds whichever entry threw.

| Class                  | `retryable` | Thrown when                                                                                                |
| ---------------------- | ----------- | ---------------------------------------------------------------------------------------------------------- |
| `DnsError`             |             | the base class of all below                                                                                |
| `TimeoutError`         | yes         | no answer arrived in time                                                                                  |
| `ConnectionError`      | yes         | the server could not be reached, or the connection failed; also a failure of your own `fetch` or `connect` |
| `ProxyError`           | yes         | the proxy could not be reached, refused, or rejected the credentials                                       |
| `EmptyResponseError`   | yes         | the server accepted the query and closed without an answer                                                 |
| `TruncatedError`       | no          | a truncated answer and no larger transport left to ask over                                                |
| `InvalidResponseError` | no          | an answer that does not decode or does not match the question, or a walk from the root that leads nowhere  |
| `ParseError`           | no          | bytes or text that are not valid DNS: a message, a record, a name                                          |
| `RecordSyntaxError`    | no          | record text that is not valid for its type; `problems` lists what, with codes                              |
| `InvalidQueryError`    | no          | a question that cannot be asked: an unknown type, a name that cannot be encoded                            |
| `NoServerError`        | no          | no server to ask: none given and none configured, or its name does not resolve                             |

Every `DnsError` carries `retryable`, and what is known of the exchange: `server`, `query`,
`type`, `transport`, and `rcode` with `rcodeName` when a response caused it. When a resolver
asked more than one server, `failures` lists what went wrong at each. An aborted query
rejects with the signal's reason, not a `DnsError`.

A mistake in what the program passed is a `TypeError`, not a `DnsError`, so it never lands
in code that handles DNS failures or retries them: a server, proxy or DoH URL that cannot
be read, and options that contradict each other (a set of `transports` beside transport
options, `edns: false` beside `dnssecOk`, `udpPayloadSize`, `ednsOptions` or `validate`).
The options are refused when the resolver is made, or the query is, before anything is sent.
A resolver's `servers` are read when it is made, so one that cannot be read never stops
the failover to the others.

Examples, and the details of `failures`, `trace` and `errorData`, are in
[Resolvers](docs/resolvers.md#errors).

## Scope

A DNS library that asks questions and reads answers. It is not a server, and it answers
nobody's queries.

- For a `node:dns/promises`-compatible API, use the [`/promises`](docs/promises.md) entry; that
  page lists where it differs from Node.
- No zone transfers (AXFR, IXFR), no dynamic UPDATE, no TSIG signing.
- No zone-file parsing yet. Records are read and written one at a time, in presentation
  format.

## Entry points

| Entry                           | What it holds                                                                                           | Runs on                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `@aoxborrow/dns`                | the resolvers, answers, errors, `toDig`, caching, events, `createTransports`, and the record types      | Node; Cloudflare Workers, without UDP |
| `@aoxborrow/dns/records`        | typed records, protocol tables, record decoding, formatting, parsing and validation                     | anywhere                              |
| `@aoxborrow/dns/wire`           | encoding queries, decoding messages, names, byte helpers                                                | anywhere                              |
| `@aoxborrow/dns/dnssec`         | the judging core, signature verification, DS digests, NSEC/NSEC3 proofs, trust anchors                  | anywhere                              |
| `@aoxborrow/dns/transports`     | the four transports (UDP, TCP, TLS, HTTPS) and `createTransports`, the set of them that resolvers share | Node; Cloudflare Workers, without UDP |
| `@aoxborrow/dns/transports/doh` | DNS over HTTPS alone: HTTP/2 on Node, `fetch` elsewhere                                                 | anywhere with `fetch`                 |
| `@aoxborrow/dns/promises`       | a `node:dns/promises`-compatible facade, with `connectLookup`                                           | Node                                  |

Error classes are one set across every entry: a `ParseError` thrown by `/wire` is
`instanceof` the root's `ParseError`. `/records` and `/wire` also export the classes they
throw (`DnsError`, `ParseError`, `InvalidQueryError`, and `RecordSyntaxError` from
`/records`), so code that imports only those entries can tell them apart.

## Where it runs

Node 22 or later. Node built-ins are imported only by the transports, and only when a query
needs them, so `/records`, `/wire` and `/dnssec` bundle for a browser with none, and the
root and transport entries load no Node module at import. esbuild bundles the root and
transport entries for a browser with no configuration, leaving those imports for the
runtime. If another bundler stops at a `node:` import, mark `node:*` external there.
`check:browser` checks all of this.

On Cloudflare Workers there is no UDP, and Ed448 signatures cannot be verified. TCP and
TLS go through the runtime's `connect()`, found on its own. The codec, the records, both
resolvers and the DNSSEC primitives pass their tests inside the Workers runtime, and the
TCP, TLS and HTTPS transports have been run on a deployed Worker. A whole lookup, resolver
and transport together, has not yet been run on a deployed Worker.

## Documentation

| Page | What it covers |
| --- | --- |
| [Resolvers](docs/resolvers.md) | `Resolver` and `AuthoritativeResolver` in depth: server order, every option, caching and memory, events, errors |
| [Records](docs/records.md) | the typed records, protocol tables, decoding, formatting, and the record validators |
| [Wire format and transports](docs/wire-and-transports.md) | `/wire` and `/transports`: encoding and decoding messages, the four transports, shared sockets, DNS over HTTPS, proxies |
| [DNSSEC](docs/dnssec.md) | `validate: true`, the judging core, the primitives, the codes and registries |
| [The `node:dns/promises` facade](docs/promises.md) | what it has, where it differs from Node, its error codes |
| [CONVENTIONS.md](CONVENTIONS.md) | the shapes every entry hands back: names, flags, times, bytes, codes |
| [UPGRADING.md](UPGRADING.md) | moving from `@aoxborrow/dns-client` 0.x |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each release |

## Benchmarks

Against the other ways to resolve names from Node, on an Apple M2 Max (12 cores), macOS
14.8.5, Node 24.14.1, on 2026-11-16. To reproduce, from this package:

```bash
yarn bench --network
```

The full output, with every scenario, the real-network runs and the method, is in
[`bench/RESULTS.md`](bench/RESULTS.md); how it is run is in
[`bench/README.md`](bench/README.md).

**On a local fixture server**, which answers every question with one A record in the same
process, so nothing but the client is measured. Every query asks a new name, except in the
cache column.

| Client                               |     Transport | warm p50, µs | 1,000 sequential, ms | queries/s, 100 in flight | queries/s, 1,000 in flight | cached answers/s |
| :----------------------------------- | ------------: | -----------: | -------------------: | -----------------------: | -------------------------: | ---------------: |
| `@aoxborrow/dns` `Resolver`          |           UDP |          131 |                  141 |                    6,939 |                     10,179 |          209,841 |
| `@aoxborrow/dns` `Resolver`          | TCP pipelined |           49 |                   57 |                   35,594 |                     31,671 |          207,846 |
| `@aoxborrow/dns` `Resolver`          |           DoH |          115 |                  129 |                   11,398 |                        n/a |          227,129 |
| `@aoxborrow/dns/promises` `resolve4` |           UDP |          175 |                  182 |                   11,300 |                     10,158 |          176,548 |
| `node:dns` `Resolver` (c-ares)       |           UDP |           65 |                   67 |                   34,119 |                     32,008 |         no cache |
| dns2 3.1.1                           |           UDP |          116 |                  120 |                    7,116 |                     13,064 |         no cache |
| tangerine 2.1.3                      |           DoH |           84 |                   94 |                   19,517 |                        n/a |        1,335,076 |
| `fetch` + dns-packet                 |           DoH |          145 |                  165 |                   10,744 |                        n/a |         no cache |

DoH stops at 100 in flight: past that the local test server's accept queue drops
connections, which measures the server.

**UDP throughput is about a third of c-ares's**, and that is a choice. The library gives
every UDP query a socket and source port of its own, so a forged answer has to guess the
port as well as the 16-bit ID (RFC 5452); c-ares sends every query from one socket. The
extra system calls cost throughput when many queries are in flight. Pipelined TCP, which
reuses a connection, keeps up with c-ares.

**Iterative resolution from the root**, the 100 names in `bench/top-100.ts`, one at a time
over IPv4 UDP:

| Resolver                                   | total, s | per name p50, ms | per name p95, ms | queries per name |
| :----------------------------------------- | -------: | ---------------: | ---------------: | ---------------: |
| `AuthoritativeResolver`, one for the list  |     14.8 |               95 |              541 |              2.8 |
| `AuthoritativeResolver`, new for each name |     19.6 |              134 |              582 |              4.3 |
| `dig +trace`, a process per name           |     43.2 |              244 |            1,655 |              4.0 |

Against public resolvers (Cloudflare, Google, Quad9) every client is mostly round-trip time
and the differences are within the network's own variance; those tables are in
`bench/RESULTS.md`. `Bun.dns`, `Deno.resolveDns` and `dnsperf` were not installed on the
machine, and `dns-socket` is unmaintained since 2021, so none of them is measured.

### Features

|                                                         | @aoxborrow/dns                                                                            | node:dns Resolver        | node:dns lookup    | dns2              | tangerine                            | Bun.dns                   | Deno.resolveDns            | dig                               |
| :------------------------------------------------------ | :---------------------------------------------------------------------------------------- | :----------------------- | :----------------- | :---------------- | :----------------------------------- | :------------------------ | :------------------------- | :-------------------------------- |
| UDP                                                     | yes                                                                                       | yes                      | system resolver    | yes               | no                                   | system resolver           | yes                        | yes                               |
| TCP                                                     | yes, pipelined on request                                                                 | on truncation only       | system resolver    | yes               | no                                   | system resolver           | on truncation only         | yes (`+tcp`)                      |
| DNS over TLS                                            | yes                                                                                       | no                       | no                 | no                | no                                   | no                        | no                         | BIND 9.18+ (`+tls`)               |
| DNS over HTTPS                                          | yes                                                                                       | no                       | no                 | yes               | yes, only                            | no                        | no                         | BIND 9.18+ (`+https`)             |
| Iterative resolution from the root                      | yes (`AuthoritativeResolver`)                                                             | no                       | no                 | no                | no                                   | no                        | no                         | `+trace`                          |
| DNSSEC                                                  | validation (`validate: true`), and the primitives it is built from                        | no                       | no                 | record types only | DO bit, reads the resolver's AD flag | no                        | no                         | DO bit (`+dnssec`), no validation |
| Cache                                                   | yes, by TTL, shared between callers                                                       | no (Node turns c-ares's cache off) | the system's       | no                | yes, pluggable (Map, Redis)          | yes                       | no                         | no                                |
| One query on the wire for callers asking the same thing | yes                                                                                       | no                       | no                 | no                | no                                   | not documented            | no                         | n/a                               |
| SOCKS5 and HTTP CONNECT proxies                         | yes                                                                                       | no                       | no                 | no                | through its `request` function       | no                        | no                         | no                                |
| Browsers and Workers                                    | records, wire and DNSSEC entries anywhere; DoH through `fetch`; TCP on Cloudflare Workers | no                       | no                 | no                | no                                   | Bun only                  | Deno only                  | n/a                               |
| Typed records                                           | 33 types, every field typed; unknown types as raw data                                    | 12 types in fixed shapes | addresses only     | about 20 types    | Node's shapes                        | addresses only            | 12 types                   | text                              |
| TypeScript                                              | written in it                                                                             | `@types/node`            | `@types/node`      | bundled types     | bundled types                        | built in                  | built in                   | n/a                               |
| Runtime dependencies                                    | none                                                                                      | built in                 | built in           | none              | 15                                   | built in                  | built in                   | n/a                               |
| A `node:dns/promises` drop-in                           | yes (`@aoxborrow/dns/promises`)                                                           | it is the original       | it is the original | no                | yes, over DoH                        | Bun implements `node:dns` | Deno implements `node:dns` | n/a                               |

"System resolver" means the client asks the operating system (getaddrinfo), which picks
the transport and the servers.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

MIT
