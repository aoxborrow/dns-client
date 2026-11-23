# @aoxborrow/dns

[![npm version](https://img.shields.io/npm/v/@aoxborrow/dns/beta.svg)](https://www.npmjs.com/package/@aoxborrow/dns)
[![Test](https://github.com/aoxborrow/dns/actions/workflows/test.yml/badge.svg)](https://github.com/aoxborrow/dns/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-blue.svg)](https://www.typescriptlang.org)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](package.json)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/aoxborrow)

> A fully typed DNS library for TypeScript: resolvers, DNSSEC validation and every common record type, with no dependencies.

- **Two resolvers** - ask recursive resolvers with failover and a TTL cache, or walk from the root servers with a hop-by-hop trace, like `dig +trace`
- **DNSSEC validation** - every answer judged secure, insecure, bogus or indeterminate, with the reason and the extended DNS error
- **Every transport** - UDP, TCP, DNS over TLS and DNS over HTTPS, directly or through a SOCKS5 or HTTP CONNECT proxy
- **33 typed record types** - decoded into typed fields, and parsed, formatted and validated in zone-file syntax
- **A `node:dns/promises`-compatible facade** - most of the same API, with a cache, in `@aoxborrow/dns/promises`; [where it differs](docs/promises.md)
- **Runs beyond Node** - the records, wire and DNSSEC entries run in browsers and Cloudflare Workers; DNS over HTTPS works anywhere with `fetch`

This library is extracted from [dns.tools](https://dns.tools). Check out our [DNS API](https://dns.tools/docs#dns) if you need a hosted version of it.

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
- [Performance](#performance)

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
  retries?: number; // further attempts at a server (default 2, or 1 with several servers; see above for AuthoritativeResolver)
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
  tls?: TlsOptions; // { ca, rejectUnauthorized } for TLS and DoH over HTTP/2 on Node (default the runtime's trust store)
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
is. Functions that read it stand alone, such as `toDig(answer)`. The values in the comments
are from the quick start's `new AuthoritativeResolver({ validate: true }).query('example.com', 'A')`.

```ts
import type {
  AnswerStatus,
  DnsRecord,
  LinkKind,
  Message,
  RcodeName,
  ReasonCode,
  SecurityStatus,
  TransportName,
} from '@aoxborrow/dns';

interface Answer<Rec extends DnsRecord = DnsRecord> {
  name: string; // 'example.com': the question as asked, with no trailing dot
  type: string; // 'A'
  class: string; // 'IN'
  rcode: number; // 0
  rcodeName: RcodeName | `RCODE${number}`; // 'NOERROR'; 'NXDOMAIN' when the name does not exist
  flags: HeaderFlags; // { qr: true, aa: true, tc: false, rd: false, ra: false, ad: false, cd: false }
  status: AnswerStatus; // 'ok'; or 'nxdomain', 'nodata', 'referral', 'alias', 'failed': see below
  negativeTtl?: number; // 300, for 'nxdomain' and 'nodata' only: seconds the negative answer may be kept
  records: Rec[]; // [{ name: 'example.com', type: 'A', class: 'IN', ttl: 300, address: '172.66.147.243' }, …]
  answers: DnsRecord[]; // the whole answer section: the A records, and with validate their RRSIG
  authorities: DnsRecord[]; // the authority section: the SOA of a negative answer, for one
  additionals: DnsRecord[]; // the additional section
  extendedErrors: ExtendedErrorOption[]; // [], or why a server answered as it did (RFC 8914)
  message: Message; // the response decoded from the wire, record data as bytes
  bytes: Uint8Array; // the response exactly as it arrived
  query: SentQuery; // the query as it was sent
  server: string; // '173.245.58.162'
  serverName?: string; // 'hera.ns.cloudflare.com', where the resolver knows it
  port: number; // 53
  url?: string; // 'https://cloudflare-dns.com/dns-query', for DoH
  transport: TransportName; // 'udp'
  elapsed: number; // milliseconds, every server and attempt included
  attempts: number; // 1
  timestamp: Date; // when the response arrived
  cached: boolean; // false; true from the cache, with the TTLs counted down
  tcpFallbackError?: ErrorData; // a truncated UDP answer whose TCP retry failed: why
  trace?: TraceHop[]; // AuthoritativeResolver only: every server asked, from the root
  security?: Security; // with validate: true only
}

interface HeaderFlags {
  qr: boolean; // true: a response
  aa: boolean; // the zone's own server answered
  tc: boolean; // truncated
  rd: boolean; // recursion desired
  ra: boolean; // recursion available
  ad: boolean; // a validating resolver says the answer is authentic
  cd: boolean; // checking disabled
}

interface SentQuery {
  name: string; // 'example.com'
  type: string; // 'A'
  class: string; // 'IN'
  flags: QueryFlags; // { rd: false, cd: false, ad: false }
  edns: false | { udpPayloadSize: number; dnssecOk: boolean }; // { udpPayloadSize: 1232, dnssecOk: true }
}

interface QueryFlags {
  rd: boolean;
  cd: boolean;
  ad: boolean;
}

interface ExtendedErrorOption {
  name: 'EDE';
  code: 15;
  infoCode: number; // 18
  purpose: string | null; // 'Prohibited'
  extraText: string; // '', or whatever the server added
}

interface ErrorData {
  name: string; // 'TimeoutError'
  message: string; // 'No answer from 192.0.2.2 within 5000 ms'
  retryable: boolean; // true
  rcode?: number;
  rcodeName?: RcodeName | `RCODE${number}`;
  extendedErrors?: ExtendedErrorOption[];
}

// one server asked by AuthoritativeResolver
interface TraceHop {
  server: string; // '173.245.58.162'
  serverName?: string; // 'hera.ns.cloudflare.com'
  zone: string; // 'example.com': the zone it was asked as an authority for
  name: string; // 'example.com'
  type: string; // 'A'
  transport?: TransportName; // 'udp'
  rcode?: number; // 0
  rcodeName?: RcodeName | `RCODE${number}`; // 'NOERROR'
  referral?: string; // 'com' on the root's hop: the zone it referred the question on to
  bytes?: number; // 179: the response's size
  elapsed: number; // 3.3
  timestamp: Date;
  error?: ErrorData; // why this server gave nothing usable, when it did not
  tcpFallbackError?: ErrorData;
}

// what DNSSEC validation made of the answer
interface Security {
  status: SecurityStatus; // 'secure', 'insecure', 'bogus' or 'indeterminate'
  reason: SecurityReason; // { code: 'verified', zone: 'example.com', name: 'example.com', type: 'A' }
  chain: ChainLink[]; // each zone's key set from the trust anchor down, then the data
  failure?: ChainLink; // the first link that is bogus or indeterminate
}

interface SecurityReason {
  code: ReasonCode; // 'verified'
  zone: string; // 'example.com'
  name?: string; // 'example.com'
  type?: string; // 'A'
  keyTag?: number; // 38696, on the root key set's link
  algorithm?: number;
  digestType?: number;
  ede?: number; // the extended DNS error a validator would send for it
}

interface ChainLink {
  kind: LinkKind; // 'keys', 'rrset' or 'denial'
  zone: string; // '.'
  name?: string;
  type?: string;
  status: SecurityStatus; // 'secure'
  reason: SecurityReason;
}
```

### Reading a negative answer

A name that does not exist, or has no records of the type asked for, is an answer, not an
error: `status` says what it amounts to. An error means no usable response arrived at all.

```ts network
import { DnsError, Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1'] });

try {
  const answer = await resolver.query('www.example.com', 'MX');
  switch (answer.status) {
    case 'ok': // the MX records are in answer.records
      break;
    case 'nxdomain': // the name does not exist
    case 'nodata': // the name exists, with no MX records
      console.log(`no MX records, for the next ${answer.negativeTtl} seconds`);
      break;
    case 'referral': // the server sent the question on to another zone's servers
    case 'alias': // an alias whose target was not followed
    case 'failed': // SERVFAIL, REFUSED and the like, an empty truncated answer, or lame servers
      break;
  }
} catch (error) {
  if (error instanceof DnsError) {
    // no usable response: a timeout, a connection refused, a malformed reply
  }
}
```

`negativeTtl` is the smaller of the SOA's TTL and its `minimum` field (RFC 2308 §5), and 0
when no SOA for the name came with the answer. It is what the zone says; the resolver's own
cache keeps a negative answer an hour at most. The SOA is in `authorities`, with the NSEC or
NSEC3 records that prove the denial in a signed zone asked with `dnssecOk: true`.

The [`/promises`](docs/promises.md) facade turns `nxdomain` and `nodata` into errors, as `node:dns` does:
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

## Performance

Maximum throughput is not the goal of this library. For raw volume, keep using `node:dns`:
its resolver (c-ares) answers a busy UDP workload faster, in part because this library gives
every UDP query a socket and source port of its own (RFC 5452). This library is for the
rest: DNSSEC validation, resolving from the root, DNS over TLS and HTTPS, proxies, typed
records, and runtimes beyond Node. The numbers, against `node:dns` and other clients, are in
[`bench/RESULTS.md`](bench/RESULTS.md).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

MIT
