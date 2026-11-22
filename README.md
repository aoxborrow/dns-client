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
- [Options](#options)
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

## Options

Both resolvers take their options in the constructor, and any query setting can be given to
one `query()` as well, for that query alone. Everything is optional.

```ts
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({
  servers: ['1.1.1.1', '8.8.8.8'], // tried in order: the next when one fails, or answers SERVFAIL, NOTIMP or REFUSED
  transport: 'tls', // 'udp' (default), 'tcp', 'tls' or 'doh'
  timeout: 2000, // milliseconds per attempt at one server (default 5000)
  retries: 1, // further attempts at a server (default 2, or 1 with several servers)
  totalTimeout: 6000, // milliseconds for the whole answer (default 10000)
  cache: { max: 5000 }, // the built-in cache, by TTL (default 1000 entries); false for none
  serverConcurrency: 32, // queries in flight to one server (default 16)
  dnssecOk: true, // ask for signatures with the answer (default false)
  onEvent: event => console.log(event), // told of every query, retry and fallback
});
```

```ts network
import { Resolver } from '@aoxborrow/dns';
import { nsidOption } from '@aoxborrow/dns/records';

const resolver = new Resolver({ servers: ['1.1.1.1'] });

// for this query alone
const answer = await resolver.query('example.com', 'A', {
  server: '8.8.8.8', // this server and no other, outside the cache
  transport: 'tcp',
  ednsOptions: [nsidOption()], // ask the server to name itself
  signal: AbortSignal.timeout(3000),
});
```

```ts
import { AuthoritativeResolver } from '@aoxborrow/dns';

const resolver = new AuthoritativeResolver({
  addressFamily: 'ipv4', // ask nameservers at their IPv4 addresses only (default 'both')
  followCnames: true, // resolve an alias into another zone too (default false)
  maxHops: 20, // servers asked on the way to one answer (default 40)
  serverDelay: 50, // least milliseconds between two queries to one server (default 0)
  validate: true, // check the DNSSEC chain, into answer.security (default false)
});
```

Transport options can go on a resolver, or on a set of sockets that several resolvers share:

```ts
import { AuthoritativeResolver, createTransports, Resolver } from '@aoxborrow/dns';

const transports = createTransports({
  proxy: 'socks5://user:pass@proxy.example:1080', // every query goes through it
  pipeline: true, // several queries down one TCP connection (default false; true for TLS)
  idleTimeout: 10_000, // how long an unused connection stays open (default 5000)
});
const resolver = new Resolver({ servers: ['9.9.9.9'], transport: 'tcp', transports });
const authoritative = new AuthoritativeResolver({ transports });

// a resolver leaves a set it was given open, so close it when they are done
transports.close();
```

The option types, with each default. [Resolvers](docs/resolvers.md#options) explains the
ones that need more than a line.

```ts
import type {
  Cache,
  CachedResponse,
  Connect,
  EdnsOption,
  FetchLike,
  NameserverHint,
  OnEvent,
  ProxyInput,
  Server,
  TlsOptions,
  Transports,
  TrustAnchor,
} from '@aoxborrow/dns';

// what both resolvers take, for every query or for one. AuthoritativeResolver takes all but
// recursionDesired, only 'udp' or 'tcp' as transport, and defaults retries to 0 (1 at a zone's
// last server)
interface QuerySettings {
  transport?: 'udp' | 'tcp' | 'tls' | 'doh'; // default 'udp'; 'doh' for a server given as a URL
  port?: number; // default 53, 853 for TLS, 443 for DoH
  timeout?: number; // milliseconds per attempt at one server (default 5000)
  retries?: number; // further attempts at a server (default 2, or 1 with several servers)
  tcpFallback?: boolean; // ask again over TCP when a UDP answer is truncated (default true)
  recursionDesired?: boolean; // the RD flag (default true)
  checkingDisabled?: boolean; // the CD flag (default false)
  authenticData?: boolean; // the AD flag, to be told whether the answer validated (default false)
  dnssecOk?: boolean; // the DO bit, to get signatures with the answer (default false)
  udpPayloadSize?: number; // the largest UDP answer to accept (default 1232)
  ednsOptions?: readonly EdnsOption[]; // to send: nsidOption(), clientSubnetOption(), cookieOption(), paddingOption()
  edns?: boolean; // false sends a plain RFC 1035 query, with no EDNS record (default true)
}

// how the transports connect
interface TransportOptions {
  proxy?: ProxyInput; // 'socks5://…' or 'http://…', or a function picking one per server (default none)
  fetch?: FetchLike; // how DoH requests are made (default HTTP/2 on Node, fetch elsewhere)
  connect?: Connect; // how TCP connections are opened (default node:net on Node)
  tls?: TlsOptions; // { ca, rejectUnauthorized } for TLS and DoH on Node (default the runtime's trust store)
  idleTimeout?: number; // milliseconds an unused connection stays open (default 5000)
  pipeline?: boolean; // several queries down one TCP connection (default false; true for TLS)
  dohMethod?: 'GET' | 'POST'; // default 'GET'
}

interface ResolverOptions extends QuerySettings, TransportOptions {
  servers?: readonly (string | Server)[]; // addresses, names, host:port or URLs (default this machine's resolvers)
  cache?: false | Cache<CachedResponse> | { max?: number }; // default the built-in cache, 1000 entries
  concurrency?: number; // queries in flight at once, to all servers (default no limit)
  serverConcurrency?: number; // queries in flight to one server (default 16)
  totalTimeout?: number; // milliseconds for the whole answer (default 10000)
  strict?: boolean; // malformed record data is an error, not a generic record (default false)
  onEvent?: OnEvent; // told of every query, retry, TCP fallback and proxy connection
  transports?: Transports; // sockets shared with other resolvers (default the process-wide set)
  validate?: boolean; // check the DNSSEC chain, into answer.security (default false)
  trustAnchors?: readonly TrustAnchor[]; // where validation starts (default IANA's root anchors)
}

// what one Resolver query() takes besides the query settings
interface ResolverQueryOptions extends QuerySettings {
  server?: string | Server; // this server and no other, outside the cache
  totalTimeout?: number; // in place of the resolver's
  signal?: AbortSignal; // abandons the query; it rejects with the signal's reason
}

interface AuthoritativeResolverOptions
  extends Omit<QuerySettings, 'recursionDesired' | 'transport'>, TransportOptions {
  transport?: 'udp' | 'tcp'; // default 'udp'
  rootServers?: readonly NameserverHint[]; // where walks start (default the 13 root servers)
  addressFamily?: 'ipv4' | 'ipv6' | 'both'; // nameserver addresses to use (default 'both', IPv4 first)
  followCnames?: boolean; // resolve an alias into another zone too (default false)
  maxAliases?: number; // how long an alias chain may be (default 8)
  maxHops?: number; // servers asked on the way to one answer (default 40)
  totalTimeout?: number; // milliseconds for the whole answer (default 10000)
  hosts?: Readonly<Record<string, string | readonly string[]>>; // nameserver addresses by name (default none)
  serverConcurrency?: number; // queries in flight to one server address (default 8)
  cache?: boolean; // remember delegations between queries (default true)
  nameserverCache?: boolean; // remember glueless nameservers' addresses (default true)
  serverDelay?: number; // least milliseconds between two queries to one server (default 0)
  concurrency?: number; // queries in flight at once, to all servers (default no limit)
  strict?: boolean; // as for Resolver
  onEvent?: OnEvent;
  transports?: Transports;
  validate?: boolean;
  trustAnchors?: readonly TrustAnchor[];
}

// what one AuthoritativeResolver query() takes besides the query settings
interface AuthoritativeQueryOptions extends Omit<QuerySettings, 'recursionDesired' | 'transport'> {
  transport?: 'udp' | 'tcp';
  totalTimeout?: number; // in place of the resolver's
  signal?: AbortSignal;
  onEvent?: OnEvent; // told of this query's own exchanges, nameserver lookups included
  startAt?: readonly NameserverHint[]; // start the walk at these servers instead of the root
  fromRoot?: boolean; // walk from the root whatever the resolver remembers (default false)
}
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

Against the other ways to resolve names from Node, on a cloud machine with 2 AMD EPYC
cores, Linux 6.1, Node 24.22.3, on 2026-11-22. To reproduce, from this package:

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
| `@aoxborrow/dns` `Resolver`          |           UDP |          150 |                  187 |                    6,413 |                      7,796 |          113,467 |
| `@aoxborrow/dns` `Resolver`          | TCP pipelined |           85 |                  100 |                   11,389 |                     10,612 |           84,168 |
| `@aoxborrow/dns` `Resolver`          |           DoH |          273 |                  348 |                    4,330 |                        n/a |          146,063 |
| `@aoxborrow/dns/promises` `resolve4` |           UDP |          148 |                  170 |                    6,072 |                      6,282 |           90,589 |
| `node:dns` `Resolver` (c-ares)       |           UDP |           65 |                   86 |                   29,118 |                      1,836 |         no cache |
| dns2 3.1.1                           |           UDP |           68 |                   79 |                   19,250 |                        390 |         no cache |
| tangerine 2.1.3                      |           DoH |          176 |                  207 |                   10,056 |                        n/a |          787,024 |
| `fetch` + dns-packet                 |           DoH |          263 |                  316 |                    5,228 |                        n/a |         no cache |

DoH stops at 100 in flight: past that the local test server's accept queue drops
connections, which measures the server.

**UDP throughput at 100 in flight is under a quarter of c-ares's**, and that is a choice.
The library gives every UDP query a socket and source port of its own, so a forged answer
has to guess the port as well as the 16-bit ID (RFC 5452); c-ares sends every query from
one socket. The extra system calls cost throughput. At 1,000 in flight c-ares and dns2,
each on one socket, fall to 1,836 and 390 queries a second, while the library keeps its
rate. Pipelined TCP, which reuses a connection, is the library's fastest transport here.

**Iterative resolution from the root**, the 100 names in `bench/top-100.ts`, one at a time
over IPv4 UDP:

| Resolver                                   | total, s | per name p50, ms | per name p95, ms | queries per name |
| :----------------------------------------- | -------: | ---------------: | ---------------: | ---------------: |
| `AuthoritativeResolver`, one for the list  |     13.1 |               48 |              289 |              3.2 |
| `AuthoritativeResolver`, new for each name |     17.6 |              104 |              331 |              4.9 |
| `dig +trace`, a process per name           |     36.8 |              197 |            1,333 |              4.0 |

Against public resolvers (Cloudflare, Google, Quad9) every client is mostly round-trip time
and the differences are within the network's own variance; those tables are in
`bench/RESULTS.md`. `Bun.dns` is not driven by the harness yet, `Deno.resolveDns` and
`dnsperf` were not installed on the machine, and `dns-socket` is unmaintained since 2021, so
none of them is measured.

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
