# @aoxborrow/dns

A DNS client for TypeScript with nothing underneath it: its own wire codec, typed records,
a resolver that asks recursive resolvers, a resolver that walks from the root, record
validation, and DNSSEC validation with the primitives it is built from. It speaks UDP, TCP,
DNS over TLS and DNS over HTTPS, directly or through a SOCKS5 or HTTP CONNECT proxy. No
runtime dependencies.

**Status:** 1.0 is in pre-release. It replaces `@aoxborrow/dns-client` 0.x and is not
compatible with it; see [UPGRADING.md](UPGRADING.md).

- [Install](#install)
- [Quick start](#quick-start)
- [Scope](#scope)
- [Entry points](#entry-points)
- [The root entry: resolvers](#the-root-entry-resolvers)
- [`/records`](#records)
- [`/wire`](#wire)
- [`/dnssec`](#dnssec)
- [`/transports`](#transports)
- [`/promises`](#promises)
- [Where it runs](#where-it-runs)
- [Benchmarks](#benchmarks)
- [Conventions](#conventions)

## Install

```bash
npm install @aoxborrow/dns
```

ES modules only, with type declarations. Node 22 or later. The `/records`, `/wire` and
`/dnssec` entries run anywhere, browsers and Cloudflare Workers included; see
[Where it runs](#where-it-runs).

## Quick start

```ts
import { Resolver, toDig } from '@aoxborrow/dns';

// the resolvers this machine is set up to use, as `dig` and `node:dns` would
const resolver = new Resolver();
const answer = await resolver.query('example.com', 'MX');

answer.rcodeName; // 'NOERROR'
answer.records; // MxRecord[]: [{ name: 'example.com', type: 'MX', class: 'IN', ttl: 300, preference: 0, exchange: '.' }]
answer.server; // '192.0.2.53', whichever resolver answered
toDig(answer); // 'dig @192.0.2.53 example.com MX'
```

Ask particular resolvers, or one server for one query:

```ts
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1', '8.8.8.8'] });

// this server and no other, over TCP, outside the cache
const txt = await resolver.query('example.com', 'TXT', { server: '9.9.9.9', transport: 'tcp' });
txt.records.map(record => record.strings); // [['v=spf1 -all'], …]
```

Or skip the resolvers and ask each zone's own servers, starting at the root:

```ts
import { AuthoritativeResolver } from '@aoxborrow/dns';

const resolver = new AuthoritativeResolver();
const answer = await resolver.query('example.com', 'A');

answer.flags.aa; // true: this is what the zone's own server says
answer.trace; // every server asked on the way
// [ { zone: '.',           serverName: 'a.root-servers.net',        referral: 'com' },
//   { zone: 'com',         serverName: 'a.gtld-servers.net',        referral: 'example.com' },
//   { zone: 'example.com', serverName: 'elliott.ns.cloudflare.com', rcodeName: 'NOERROR' } ]
```

## Scope

This is a DNS client. It asks questions and reads answers.

- For a `node:dns/promises`-compatible API, use the [`/promises`](#promises) entry; that
  section lists where it differs from Node.
- It is not a server: it answers nobody's queries.
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

## The root entry: resolvers

Questions are asked through one of two resolvers. Both have one method,
`query(name, type, options?)`, and return the same `Answer`.

### `Resolver`

Asks recursive resolvers, the way `dig` and `node:dns` do. Without `servers` it uses the
ones this machine is set up to use (on Node). A server is an address, a name,
`host:port`, or an `https://` URL, which is asked over DNS over HTTPS
(`https://cloudflare-dns.com/dns-query`). For DNS over TLS, name the server and set
`transport: 'tls'`.

It tries `servers` in the order given, and moves to the next when one fails or answers
SERVFAIL, NOTIMP or REFUSED. A server that fails is asked again only after every other
server has had its turn, and all of it fits in `totalTimeout`. If every server answers that way, the last response is the
answer. It caches by TTL, and callers asking the same question at the same moment share
one query on the wire.

### `AuthoritativeResolver`

Asks no resolver. It starts at the root servers and follows referrals to the zone's own
nameservers, and the answer carries `trace`, every server asked on the way. It remembers
delegations for as long as their TTLs allow (at most a day), looks up nameservers that come without an
address, and moves on from a server that refuses, fails or stays silent, and from a lame
one: an answer with neither authority nor the zone's SOA, or FORMERR. Two of a zone's
servers refusing the same way is the zone's answer. It stops at an alias into another
zone unless `followCnames` is set.

A zone's server is trusted only for its own zone (RFC 2181 §5.4.1). Records it sends about
another zone, after an alias out of it, are left out of `records` and never used to find a
nameserver: with `followCnames` the alias target is asked of its own zone's servers. The
raw sections (`answers`, `authorities`, `additionals`, `message`) keep everything the
server sent, unvetted.

Root servers, nameservers and addresses are tried in a random order, drawn afresh each
time, so the load falls on all of a zone's servers and one slow server is not always
first. With `addressFamily: 'both'` (the default) IPv4 addresses come first. The trace
says which servers were asked.

A query can start somewhere other than the root: `startAt` names the servers to ask first,
and the walk follows their referrals from there. Nameservers that come without an address
are still looked up from the root servers, and what such a walk is told is not kept for
other queries. The walk cannot tell which zone the starting servers serve, so it takes their
own answers whole: a zone's server is trusted only for its own zone from their first
referral on.

A query that has to show the whole path sets `fromRoot`: it walks from the root servers and
asks every server on the way whatever the resolver remembers, so its trace starts at the
root. What it learns is still remembered for the other queries.

```ts
import { AuthoritativeResolver } from '@aoxborrow/dns';

const resolver = new AuthoritativeResolver();
// start at one of org's servers
await resolver.query('mozilla.org', 'NS', {
  startAt: [{ name: 'v0n0.pir-ns.org', ipv4: '199.19.56.1' }],
});
```

### The answer

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

```ts
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

The [`/promises`](#promises) facade turns both into errors, as `node:dns` does:
NXDOMAIN is `ENOTFOUND`, NODATA is `ENODATA`.

### Options

These can be set on a resolver for every query, or passed to one `query()`:

| Option             | Default |                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `transport`        | `'udp'` | `'udp'`, `'tcp'`, `'tls'` or `'doh'`. DoH for a server given as a URL, TCP where there is no UDP. `AuthoritativeResolver` takes `'udp'` or `'tcp'`                                                                                                                                                                                                                                                                                                                       |
| `timeout`          | `5000`  | milliseconds of patience with one server                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `retries`          | `2`     | further attempts at a server that fails in a way worth retrying. With several `servers`, one: each server is asked once before any is asked again. `AuthoritativeResolver` asks a zone's next server instead (`0`), and only the last one a zone has left a second time (`1`)                                                                                                                                                                                            |
| `totalTimeout`     | `10000` | milliseconds one answer may take altogether: every server, retry and TCP fallback, time spent waiting under `concurrency` and `serverConcurrency`, and the queries `validate` makes for the chain. Where `timeout` or `retries` is set, the default is at least what one server's attempts take, `timeout × (retries + 1)`, so it never cuts them short. `AuthoritativeResolver` gives the last server a zone has left the rest of it, and counts nameserver lookups too |
| `tcpFallback`      | `true`  | ask again over TCP when a UDP answer is truncated. When TCP fails (refused, timed out, no time left for it), the truncated answer comes back as it came, `flags.tc` set, with the TCP error in `tcpFallbackError`                                                                                                                                                                                                                                                        |
| `recursionDesired` | `true`  | the RD flag. `AuthoritativeResolver` never sets it                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `dnssecOk`         | `false` | the DO bit: ask for signatures with the answer                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `checkingDisabled` | `false` | the CD flag: ask a validating resolver not to hold an answer back                                                                                                                                                                                                                                                                                                                                                                                                        |
| `authenticData`    | `false` | the AD flag in the query: ask to be told whether the answer validated                                                                                                                                                                                                                                                                                                                                                                                                    |
| `udpPayloadSize`   | `1232`  | the largest UDP answer this client will accept                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `ednsOptions`      | none    | EDNS options to send: `nsidOption()`, `clientSubnetOption()`, `cookieOption()`, `paddingOption()`                                                                                                                                                                                                                                                                                                                                                                        |
| `edns`             | on      | `false` sends a plain RFC 1035 query, with no EDNS record. `dnssecOk`, `udpPayloadSize` and `ednsOptions` travel in that record, so setting one of them together with `edns: false` is a `TypeError`. One exception: `edns: false` passed to a single `query()` sends that query plain, dropping any of the three that were set on the resolver                                                                                                                           |
| `signal`           | none    | an `AbortSignal`, per query. An aborted query rejects with the signal's reason, including one still waiting for its turn under a concurrency limit                                                                                                                                                                                                                                                                                                                       |

`Resolver` also takes:

| Option                     | Default          |                                                                              |
| -------------------------- | ---------------- | ---------------------------------------------------------------------------- |
| `servers`                  | this machine's   | addresses, names, `host:port`, URLs, or `{ address, port, serverName, url }` |
| `cache`                    | 1000 entries     | `false`, `{ max }` for the built-in cache, or a cache of your own            |
| `concurrency`              | no limit         | queries in flight at once, to all servers together                           |
| `serverConcurrency`        | `16`             | queries in flight to one server at once; `Infinity` for no limit             |
| `strict`                   | `false`          | malformed record data is an error, not a record in the generic form          |
| `validate`, `trustAnchors` | off, IANA's root | DNSSEC validation; see [`/dnssec`](#dnssec)                                  |

`AuthoritativeResolver` also takes:

| Option                               | Default             |                                                                                                                                                      |
| ------------------------------------ | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rootServers`                        | the 13 root servers | where to start: `{ name, ipv4, ipv6 }[]`                                                                                                             |
| `addressFamily`                      | `'both'`            | `'ipv4'`, `'ipv6'` or `'both'`. With both, a server's IPv6 address is tried only once each of the zone's servers has been tried at its first address |
| `followCnames`, `maxAliases`         | off, `8`            | resolve an alias into another zone, and how long a chain may be                                                                                      |
| `maxHops`                            | `40`                | servers asked on the way to one answer, nameserver lookups included                                                                                  |
| `serverConcurrency`                  | `8`                 | queries in flight to one server address at once; `Infinity` for no limit                                                                             |
| `serverDelay`                        | `0`                 | the least milliseconds between two queries to the same server                                                                                        |
| `concurrency`                        | no limit            | queries in flight at once, to all servers together                                                                                                   |
| `hosts`                              | none                | addresses for nameservers by name, used before asking for them                                                                                       |
| `cache`                              | `true`              | remember delegations between queries, and share the referrals of queries running at the same time. With `false` every query walks from the root      |
| `nameserverCache`                    | `true`              | remember the addresses of nameservers that came without glue between queries, even with `cache: false`                                               |
| `strict`, `validate`, `trustAnchors` |                     | as for `Resolver`                                                                                                                                    |

The default `rootServers` is `ROOT_HINTS`, taken from IANA's root hints file
(`ROOT_HINTS_SOURCE`). `ROOT_HINTS_DATA_VERSION` is the version of that file the list was
taken from, and `ROOT_HINTS_REFRESHED` the date the list was last compared with it.

One `query()` also takes, for that query alone:

| Option                    | On                      |                                                                                                                                                                                                                                        |
| ------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `server`                  | `Resolver`              | ask this server and no other: an address, a name, `host:port`, a URL, or `{ address, port, serverName, url }`. The answer is not taken from the cache or put in it                                                                     |
| `startAt`                 | `AuthoritativeResolver` | where the walk starts, in place of the root servers: `{ name, ipv4, ipv6 }[]`. Nameservers that come without an address are still looked up from the root servers, and the delegations found on the way are not kept for other queries |
| `fromRoot`                | `AuthoritativeResolver` | `true` walks from the root servers whatever delegations the resolver remembers, so that `trace` is the whole path. What the walk learns is kept for other queries. Default `false`                                                     |
| `totalTimeout`, `onEvent` | `AuthoritativeResolver` | as on the resolver, for this query. This `onEvent` is told only of the queries this one sends, nameserver lookups included, and the resolver's own is told as well                                                                     |

Both take the transport options (`proxy`, `fetch`, `connect`, `tls`, `pipeline`,
`idleTimeout`, `dohMethod`; see [`/transports`](#transports)), `onEvent`, and
`transports`, a set of sockets to share with other resolvers. The set is made with
`createTransports(options)` and takes its transport options there: a resolver given both
`transports` and a transport option throws a `DnsError`.

### Caching

`Resolver` keeps each response for its TTL (the smallest in the answer section; for a
negative answer, the SOA's, as above), and for no more than a day, or an hour for a negative
answer (RFC 2308 §5); a cache of your own may keep things longer. A cached answer comes
back with `cached: true` and its TTLs reduced by the time it has spent in the cache. A query
with a `server` of its own neither reads nor fills the cache.

```ts
import { createLruCache, Resolver } from '@aoxborrow/dns';
import type { CachedResponse } from '@aoxborrow/dns';

const small = new Resolver({ cache: { max: 100 } });
const none = new Resolver({ cache: false });
// or anything with get, set(key, value, ttlMilliseconds), delete and clear
const shared = new Resolver({ cache: createLruCache<CachedResponse>({ max: 10_000 }) });

shared.clearCache();
shared.close(); // closes the sockets this resolver opened, and empties its cache
```

`AuthoritativeResolver` caches delegations and nameserver addresses, not answers, for as
long as their TTLs allow and never longer than the resolver lives. A query starts at the
deepest zone it knows, and its trace starts there too. Queries running at the same time
share referrals: one that needs a delegation another query is asking for right now waits
for that answer instead of asking the same servers, no longer than its own time allows,
and asks for itself if the other query gets nothing. A query with `fromRoot: true` walks from
the root anyway, asking every server on the way, and the others learn from it. With
`cache: false` every query starts again from the root, so its trace is the whole path, but
a nameserver that came without glue and was looked up by an earlier query is asked
straight away; `nameserverCache: false` looks it up again every time. Queries running at
the same time that meet the same nameserver share one lookup, which has a query's whole
time of its own and lasts while any of them still waits on it. Both resolvers have
`clearCache()` and `close()`.

Neither resolver's memory grows with the number of names asked about. `Resolver` keeps at
most `cache.max` answers (1000 by default). `AuthoritativeResolver` keeps at most 10,000
delegations (the least recently used forgotten first), 10,000 nameserver addresses looked
up for nameservers without glue, 10,000 nameserver names for the trace, and what it has
seen of how 10,000 zones answer (the least recently learned forgotten first). What has
expired is dropped when it is next looked at, and at most once a minute, when something
new is learned, everything the resolver knows is swept of it. The root servers, and the
`hosts` it was given, are never forgotten. A validating resolver of either kind also keeps
what at most 1000 zones' key sets came to.

```ts
import { AuthoritativeResolver } from '@aoxborrow/dns';

// every answer walked from the root, nameserver addresses reused
const walker = new AuthoritativeResolver({ cache: false });
await walker.query('example.com', 'A');
await walker.query('example.com', 'MX');

// the name's own answer with its whole path, and names under it straight from its zone
const shared = new AuthoritativeResolver();
await shared.query('example.com', 'A', { fromRoot: true });
await Promise.all(['www', 'mail'].map(label => shared.query(`${label}.example.com`, 'A')));
```

### Events

The library prints nothing. `onEvent` is told about every query sent, every retry, every
fallback to TCP and every proxy connection; that is where logging and metrics attach.

```ts
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({
  onEvent: event => {
    if (event.event === 'query') {
      console.log(
        event.server,
        event.query,
        event.type,
        event.rcodeName ?? event.error?.name,
        event.elapsed
      );
    }
  },
});
```

| `event`                 | When                                                                                                     |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| `'query'`               | one per network exchange, with its server, transport, attempt, elapsed time, bytes, and rcode or error   |
| `'retry'`               | an attempt failed and another is about to be made                                                        |
| `'tcp-fallback'`        | a UDP query goes over TCP: the answer was truncated, or the proxy cannot carry UDP                       |
| `'tcp-fallback-failed'` | asking a truncated answer again over TCP failed, with the error: the truncated answer is what comes back |
| `'proxy'`               | a proxy was asked for a tunnel or a UDP association. Credentials never appear                            |

`AuthoritativeResolver.query()` also takes an `onEvent` of its own, told only of the
queries that one call sends, nameserver lookups included: how the queries of one answer
are told apart from those of others the same resolver is working on.

### Errors

An error means no usable response arrived. Every error the library throws is a
`DnsError`, told apart by its class (and `name`). There are no string codes.

```ts
import { DnsError, Resolver, TimeoutError } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['192.0.2.1', '192.0.2.2'] });

try {
  await resolver.query('example.com', 'A');
} catch (error) {
  if (error instanceof TimeoutError) {
    error.retryable; // true: asking again could work
    error.server; // '192.0.2.2'
    error.message; // 'No answer from 192.0.2.2 within 5000 ms'
    error.failures; // [{ server: '192.0.2.1', error: TimeoutError }, { server: '192.0.2.2', error: TimeoutError }]
  } else if (error instanceof DnsError) {
    error.name; // 'ConnectionError', 'InvalidResponseError', …
  }
}
```

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
`type`, `transport`. One raised from a server's response also carries `rcode`, `rcodeName`
and `extendedErrors`. When a resolver asked more than one server, `failures` lists each
server and what went wrong there, in the order asked, the thrown error among them; an
error from `AuthoritativeResolver` also carries `trace`. `toJSON()` gives the same as plain
data, and `errorData(error)` gives any error as the plain data events and results carry:
`name`, `message`, `retryable`, and what a `DnsError` knows of the response code. An
aborted query rejects with the signal's reason, not a `DnsError`.

A mistake in what the program passed is a `TypeError`, not a `DnsError`, so it never lands
in code that handles DNS failures or retries them: a server, proxy or DoH URL that cannot
be read, and options that contradict each other (a set of `transports` beside transport
options, `edns: false` beside `dnssecOk`, `udpPayloadSize`, `ednsOptions` or `validate`).
The options are refused when the resolver is made, or the query is, before anything is sent.
A resolver's `servers` are read when it is made, so one that cannot be read never stops
the failover to the others.

Classes are one set across entries, so `instanceof` holds whichever entry threw:

```ts
import { ParseError } from '@aoxborrow/dns';
import { decodeMessage } from '@aoxborrow/dns/wire';

try {
  decodeMessage(new Uint8Array([0, 1, 2]));
} catch (error) {
  error instanceof ParseError; // true
}
```

## `/records`

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

### Formatting and helpers

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

### Validating records

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
// [{ code: 'cname-and-other-data', values: { types: ['A'] }, name: 'www.example.com', type: 'CNAME', detail: '…' }]
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
  { name: 'www.example.com', type: 'CNAME', ttl: 300, data: 'example.com' },
  'example.com'
);
// { name: 'www', type: 'CNAME', ttl: 300, data: '@' }
```

## `/wire`

```ts
import { createUdpTransport } from '@aoxborrow/dns/transports';
import { decodeMessage, encodeQuery } from '@aoxborrow/dns/wire';

const query = encodeQuery({ id: 1234, name: 'example.com', type: 'A', recursionDesired: true });

const udp = createUdpTransport();
const response = await udp.send({ endpoint: { host: '1.1.1.1', port: 53 }, query });
udp.close();

const message = decodeMessage(response.bytes);
message.rcode; // 0
message.answers; // [{ name: 'example.com', type: 1, class: 1, ttl: 300, rdata: Uint8Array, section: 'answer' }]
```

`Uint8Array` in and out, no `Buffer`. Record data stays as bytes; `decodeRecords` in
`/records` types it. Names are accepted in Unicode or punycode and returned in ASCII.
Also here: `encodeMessage`, and the name helpers `canonicalName`, `compareNames`,
`isSubdomain`, `parentName`, `countLabels`, `encodeName` and `toAsciiName`. `splitName`
gives a name's labels as text, `nameToLabels` gives them as bytes and `labelsToName` turns
those back into a name, and `readName` reads a name out of a message, following
compression pointers. The byte helpers are `toHex`, `fromHex`, `toBase64`, `fromBase64`,
`toBase32Hex`, `concatBytes`, `compareBytes`, `readU16`/`writeU16` and
`readU32`/`writeU32`.

## `/dnssec`

### Validating answers

```ts
import { AuthoritativeResolver, Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1'], validate: true });
const answer = await resolver.query('example.com', 'A');

answer.security?.status; // 'secure', 'insecure', 'bogus' or 'indeterminate'
answer.security?.reason; // { code: 'verified', zone: 'example.com', keyTag: 370 }

const iterative = new AuthoritativeResolver({ validate: true });
const broken = await iterative.query('dnssec-failed.org', 'A');
broken.security?.status; // 'bogus'
broken.security?.reason; // { code: 'no-matching-dnskey', zone: 'dnssec-failed.org', keyTag: …, ede: 9 }
broken.security?.failure; // the first link that broke: { kind: 'keys', zone: 'dnssec-failed.org', … }
```

With `validate: true`, both resolvers check every answer's chain of trust and say what came
of it in `answer.security`. The data is asked for with DO set (and CD, for `Resolver`, so a
validating resolver upstream hands over broken records instead of a SERVFAIL); then each
zone between the root and the data has its DS and DNSKEY records fetched the same way, and
the judging core decides. The answer itself is unchanged apart from carrying its
signatures in `answers`; nothing is withheld, whatever the verdict. Without `validate`,
nothing changes. Validation needs EDNS, which carries the DO bit: `edns: false` on a
validating resolver, or on one of its queries, is a `DnsError`.

| Status          | Meaning                                                                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secure`        | a chain of valid signatures runs from a trust anchor to the data                                                                                                                      |
| `insecure`      | the data is proven to sit below a delegation with no DS (or an opt-out range, or a DS set naming only algorithms this runtime cannot verify, RFC 6840 §5.2), so nothing could sign it |
| `bogus`         | a chain should be there and is broken: an expired or invalid signature, a DS that matches no key, a missing proof                                                                     |
| `indeterminate` | it could not be told: a response missing or truncated, or every signature in an algorithm this runtime cannot check                                                                   |

`reason` is a code and the values it is about (zone, name, type, key tag, algorithm), never
English, with `ede` set to the extended DNS error (RFC 8914) a validating resolver would send
for it, where one fits: 7 for an expired signature, 9 for a missing DNSKEY, 10 for missing
RRSIGs, 12 for a missing NSEC proof, 1 for an unsupported algorithm, 27 for an NSEC3
iteration count past 50. `chain` lists every link judged, each zone's key set from the root
down and then each RRset and denial proof of the data, each with its own status and reason;
`failure` is the first bogus or indeterminate one. CNAME and DNAME chains are judged link by
link (a CNAME synthesized from a signed DNAME needs no signature of its own), answers from a
wildcard need the proof that the name itself does not exist, and NXDOMAIN and NODATA need
their NSEC or NSEC3 proofs, a NODATA from a wildcard or at an empty non-terminal included.
An opt-out range makes an answer insecure only where the NSEC3 covering the next closer name
sets it (RFC 5155 §9.2).

One answer may cost at most 128 signature verifications, 4 keys tried per signature and 8
signatures per RRset; past that it is `bogus` with the code `validation-limit`, as
validators have done since KeyTrap (CVE-2023-50387). `judgeChain` takes other `limits`.
NSEC3 names are hashed once per parameter set, and not at all past 50 iterations.

What each zone's key set came to is kept for as long as the TTLs and signatures it rests on
allow (with `cache: false`, not at all), and `clearCache()` forgets it. Validation starts
from `trustAnchors`, IANA's root anchors by default (`ROOT_TRUST_ANCHORS`, with
`ROOT_TRUST_ANCHORS_DATA_VERSION` and `ROOT_TRUST_ANCHORS_REFRESHED`). A key published with
the RFC 5011 revoke bit anchors nothing and signs nothing.

### The judging core

The resolvers fetch, and `judgeChain` judges. Given the root's DNSKEY response, each name's
DS response (and DNSKEY response, where it is a zone of its own), the responses holding the
data, the trust anchors and a time, it returns the status and reason of every link. It
fetches nothing and keeps nothing, so the same records and time always give the same
judgement.

```ts
import { Resolver } from '@aoxborrow/dns';
import { typeCode } from '@aoxborrow/dns/records';
import { judgeChain } from '@aoxborrow/dns/dnssec';
import type { DnssecResponse } from '@aoxborrow/dns/dnssec';

const resolver = new Resolver({ servers: ['1.1.1.1'], dnssecOk: true, checkingDisabled: true });

// one response as the core reads it: the question as sent, and the records with their
// signatures
async function ask(name: string, type: string): Promise<DnssecResponse> {
  const answer = await resolver.query(name, type);
  const { answers, authorities } = answer.message;
  return {
    name: answer.query.name,
    type: typeCode(type),
    rcode: answer.rcode,
    answers,
    authorities,
  };
}

const judgement = await judgeChain(
  {
    anchored: await ask('.', 'DNSKEY'),
    names: [
      { name: 'com', ds: await ask('com', 'DS'), dnskey: await ask('com', 'DNSKEY') },
      {
        name: 'example.com',
        ds: await ask('example.com', 'DS'),
        dnskey: await ask('example.com', 'DNSKEY'),
      },
    ],
    responses: [await ask('example.com', 'A')],
  },
  { mode: 'all', now: new Date() }
);
judgement.status; // 'secure'
judgement.links; // every link, with a status and a reason
```

A response marked `truncated: true` (it came with TC set) is not the whole answer: in a
signed zone its data is `indeterminate`, whatever signatures it carries.

`mode: 'first'` (what the resolvers use) stops at the first link that settles the outcome;
`mode: 'all'` judges every link and every signature. `requireEveryAlgorithm` asks for each
RRset to be signed with every algorithm in its zone's key set (RFC 4035 §2.2), which
validators do not require (RFC 6840 §5.11). Three of the checks it is made of are
exported, each returning codes: `checkAnchors` for the trust anchors against a key set,
`checkRrset` for one RRset's signatures, and `judgeKeys` for a zone's key set as a whole.

### The primitives

```ts
import { Resolver } from '@aoxborrow/dns';
import {
  buildSignedData,
  computeKeyTag,
  groupRrsets,
  verifySignature,
} from '@aoxborrow/dns/dnssec';
import { decodeDnskey, decodeRrsig, RECORD_TYPES } from '@aoxborrow/dns/records';

// a zone's keys and the signatures over them, from a resolver asked not to validate
const resolver = new Resolver({ servers: ['1.1.1.1'] });
const answer = await resolver.query('example.com', 'DNSKEY', {
  dnssecOk: true,
  checkingDisabled: true,
});
const { answers } = answer.message;
const [keys] = groupRrsets(answers);

for (const record of answers.filter(rr => rr.type === RECORD_TYPES.RRSIG)) {
  const rrsig = decodeRrsig(record.rdata); // throws ParseError for malformed data
  const key = keys.records.find(rr => computeKeyTag(rr.rdata) === rrsig.keyTag);
  const signed = buildSignedData(rrsig, keys);
  if (!key || !signed) continue;

  const { publicKey } = decodeDnskey(key.rdata);
  const outcome = await verifySignature(rrsig.algorithm, publicKey, signed.data, rrsig.signature);
  outcome.verified; // true, false, or undefined when this runtime cannot check the algorithm
}
```

These are the pieces the judging core is built from, each checking one thing.
`verifySignature` checks RSA, ECDSA and EdDSA signatures through WebCrypto; an algorithm
the runtime cannot verify comes back not checked, never as a pass, and
`isAlgorithmSupported` says beforehand whether it can (a WebCrypto may lack Ed25519 or
Ed448). `computeDsDigest` and `computeKeyTag` match a DS record to the key it names.
`verifyNoDsProof`, `verifyNxdomainProof`, `verifyNodataProof` and `verifyWildcardProof`
check NSEC and NSEC3 denial proofs and return the reasoning step by step;
`verifyWildcardProof` takes the wildcard an answer was synthesised from, which
`wildcardOwner` rebuilds from the RRSIG's labels field. Digests and NSEC3 hashes use the
library's own SHA-1, SHA-256 and SHA-384. They all take records as the library decodes them,
the `ResourceRecord`s of `answer.message`; `buildSignedData` puts their data in the canonical
form signatures are computed over (RFC 4034 §6.2).
The record-data decoders (`decodeRrsig`, `decodeDnskey` and the rest) are in `/records`.

### Codes, registries and helpers

What the judgements and the checks return is spelled out as constants:

| Name                                                          |                                                                                                                                                                              |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECURITY_STATUSES`                                           | the four statuses: `secure`, `insecure`, `bogus`, `indeterminate`                                                                                                            |
| `REASON_CODES`                                                | every reason code a link can carry. A reason with an extended DNS error (RFC 8914) carries its code in `ede`                                                                 |
| `DS_CODES`, `KEY_SET_CODES`, `RRSET_CODES`, `SIGNATURE_CODES` | the codes the checks give a DS set, a key set, an RRset and one signature                                                                                                    |
| `CHECK_LIMITS`, `checkBudget()`                               | the default limits on signature checking (128 verifications in all, 4 keys tried per signature, 8 signatures per RRset), and a budget made from them to pass to `checkRrset` |
| `VERIFICATION_RESULTS`                                        | what a signature or digest check came to: `verified`, `failed` or `unchecked`                                                                                                |
| `PROOF_TYPES`, `PROOF_PURPOSES`, `PROOF_STATUSES`             | a denial proof's kind (NSEC or NSEC3), what it was asked to show, and how it came out                                                                                        |

The registries the checks read:

| Name                                                                       |                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DNSSEC_ALGORITHMS`, `ALGORITHM_STANDINGS`, `ALGORITHM_REGISTRY_REFRESHED` | each signing algorithm's name, whether the library verifies it, and its standing in IANA's registry (RFC 9904); the standings themselves, which are `recommended`, `supported`, `deprecated`, `prohibited` and `regional`; and the date they were last checked against IANA |
| `DS_DIGEST_TYPES`                                                          | each DS digest type's name, standing and strength. Strength picks among several digests published for one key (RFC 4509 §3)                                                                                                                                                 |
| `NSEC3_HASH_ALGORITHMS`                                                    | the NSEC3 hash algorithms, which is SHA-1 alone                                                                                                                                                                                                                             |
| `DNSKEY_FLAGS`, `DNSKEY_PROTOCOL`, `NSEC3_FLAGS`                           | the flag bits of a DNSKEY, the one protocol value it may carry (3), and the flag bits of an NSEC3                                                                                                                                                                           |
| `ROOT_TRUST_ANCHOR_SOURCE`                                                 | the URL of the IANA file `ROOT_TRUST_ANCHORS` is taken from                                                                                                                                                                                                                 |

And the smaller functions:

| Name                                                          |                                                                                                                                                                             |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `algorithmName()`, `isAlgorithmVerifiable()`, `keySizeBits()` | an algorithm's mnemonic; whether the library has code to verify it, which `isAlgorithmSupported` goes on to check against the runtime; and the size of a public key in bits |
| `isDigestDeprecated()`                                        | whether a DS digest type is deprecated (SHA-1)                                                                                                                              |
| `readKeys()`                                                  | the DNSKEYs among some records, decoded, leaving out any that do not decode                                                                                                 |
| `canonicalRdata()`                                            | record data in canonical form (RFC 4034 §6.2)                                                                                                                               |
| `nsec3Hash()`, `assessNsec3Params()`                          | a name's NSEC3 hash, and a zone's NSEC3 parameters held against RFC 9276                                                                                                    |

## `/transports`

The resolvers make the transports they need. Use one directly to send a message you
encoded yourself, as in the [`/wire`](#wire) example.

| Function               | Notes                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `createUdpTransport()` | a fresh socket and source port for every query, kept for its retransmissions (RFC 5452)                                   |
| `createTcpTransport()` | a connection per query by default; `pipeline: true` keeps connections open and sends several queries down each (RFC 7766) |
| `createTlsTransport()` | DNS over TLS, pipelined by default                                                                                        |
| `createDohTransport()` | DNS over HTTPS, GET by default (`dohMethod: 'POST'`)                                                                      |

`/transports/doh` holds `createDohTransport()` alone, with the types its `send()` takes and
returns, for a program that sends DNS over HTTPS and nothing else: it leaves out the UDP
and TCP transports.

To share sockets and connections between resolvers, make one set with `createTransports`,
which the root entry has too, and pass it to each. A resolver does not close a set it was
given.

```ts
import { AuthoritativeResolver, createTransports, Resolver } from '@aoxborrow/dns';

const transports = createTransports({ pipeline: true, idleTimeout: 10_000 });
const recursive = new Resolver({ servers: ['1.1.1.1'], transport: 'tcp', transports });
const iterative = new AuthoritativeResolver({ transports });

// …
transports.close();
```

Resolvers given no transport options share one set for the whole process.
`closeDefaultTransports()` closes it, for code that wants its sockets gone at a known point.
Those sockets never keep a process alive. `DEFAULT_PORTS` has each transport's port: 53 for
UDP and TCP, 853 for TLS, 443 for HTTPS.

The `connect` option is the function that opens a TCP connection. Left out, the library
uses `createNodeConnect()` on Node and `createCloudflareConnect()` on Cloudflare Workers,
and either can be called to make one to pass in. `createCloudflareConnect()` takes the
runtime's own `connect`, imported from `cloudflare:sockets`; without it, it loads that
module itself the first time a connection is opened.

### DNS over HTTPS

On Node, DNS over HTTPS to an `https://` URL goes over HTTP/2 with `node:http2`,
one session per server shared by every query to it (RFC 8484 recommends HTTP/2 at least,
and some servers refuse HTTP/1.1). A session idle for `idleTimeout` milliseconds (5000 by
default) is closed, and `tls` (`ca`, `rejectUnauthorized`) applies to it as to DNS over
TLS. A server that does not offer HTTP/2, an `http://` URL, Deno, browsers and Workers go
through `fetch`; pass your own `fetch` to use it everywhere.

### Proxies

Every transport can go through a SOCKS5 or HTTP CONNECT proxy. With `proxy` set nothing
goes around it: a query that cannot go through the proxy fails.

```ts
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({
  servers: ['1.1.1.1'],
  proxy: 'socks5://user:pass@proxy.example:1080',
});
```

| Transport         | Through the proxy                                                                                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP, DNS over TLS | a tunnel to the server; TLS starts inside it                                                                                                                          |
| UDP               | a SOCKS5 UDP association where the proxy offers one, otherwise TCP through the tunnel. The answer's `transport` says which                                            |
| DNS over HTTPS    | on Node, HTTP/2 through a tunnel to the server; a server that does not offer HTTP/2 fails. Elsewhere, pass a `fetch` that uses the proxy. Without one the query fails |

`proxy` can be a function that picks a proxy per server, or returns nothing to leave a
server unproxied. An explicit `connect` wins over `proxy` for TCP and TLS. Credentials
never appear in an error or an event.

On a deployed Cloudflare Worker TLS cannot start inside a tunnel, so the built-in tunnel
carries plain TCP there and nothing else. For DNS over HTTPS through a proxy on Workers,
pass a `fetch` that does its own TLS, such as
[`tunnelfetch`](https://github.com/latentharbor/tunnelfetch); that combination has not
been run with this library.

## `/promises`

The `node:dns/promises` API over the library's `Resolver`: the same functions, a
`Resolver` class, the same return shapes, and errors shaped like Node's. Code written for
`node:dns/promises` changes only its import.

```ts
import net from 'node:net';
import { connectLookup, lookup, resolveMx, Resolver } from '@aoxborrow/dns/promises';

await resolveMx('gmail.com'); // [{ exchange: 'gmail-smtp-in.l.google.com', priority: 5, type: 'MX' }, …]
await lookup('example.com'); // { address: '…', family: 4 }

const resolver = new Resolver({ timeout: 2000, tries: 2 });
resolver.setServers(['1.1.1.1', '[2606:4700:4700::1111]:53']);
await resolver.resolve4('example.com', { ttl: true }); // [{ address: '…', ttl: 300 }]

// the callback form `net.connect`, `tls.connect`, `http.Agent` and undici's `connect` take
net.connect({ host: 'example.com', port: 80, lookup: connectLookup });
```

There: `resolve` and every `resolve*` Node has (`resolve4`, `resolve6`, `resolveAny`,
`resolveCaa`, `resolveCname`, `resolveMx`, `resolveNaptr`, `resolveNs`, `resolvePtr`,
`resolveSoa`, `resolveSrv`, `resolveTlsa`, `resolveTxt`), `reverse`, `lookup` with its hints
(`ADDRCONFIG`, `ALL`, `V4MAPPED`), `getServers`, `setServers`, `getDefaultResultOrder`,
`setDefaultResultOrder`, `Resolver` with `cancel()`, and every error-code constant Node has
(`NODATA`, `FORMERR`, `SERVFAIL`, `NOTFOUND`, `NOTIMP`, `REFUSED`, `BADQUERY`, `BADNAME`,
`BADFAMILY`, `BADRESP`, `CONNREFUSED`, `TIMEOUT`, `EOF`, `FILE`, `NOMEM`, `DESTRUCTION`,
`BADSTR`, `BADFLAGS`, `NONAME`, `BADHINTS`, `NOTINITIALIZED`, `LOADIPHLPAPI`,
`ADDRGETNETWORKPARAMS`, `CANCELLED`), the ones the facade never gives included. The
`default` export is all of it as one object, so `import dns from '@aoxborrow/dns/promises'`
works as it does with `node:dns/promises`. Added: `connectLookup`, and `close()` on a
`Resolver`. Not there: `lookupService`, `setLocalAddress`, the `maxTimeout` option.

Where it differs from Node:

- It caches by TTL, as the library's `Resolver` does; Node does not. Pass `cache: false`
  for Node's behaviour.
- Node's `timeout` (milliseconds per attempt) and `tries` (attempts per server) work as in
  Node; `tries: 4` is the library's `retries: 3`. `maxTimeout` is not supported. Every other
  option of the library's `Resolver` is accepted too.
- `lookup` does not call getaddrinfo. It returns an IP address as it is, then reads the
  hosts file, answers `localhost` and names under it with the loopback addresses
  (RFC 6761), and otherwise asks the DNS servers for A and AAAA at once. `ADDRCONFIG` is
  accepted and has no effect.
- `reverse` only asks the DNS servers. Node's reads the hosts file first, so an address
  named there gets the hosts file's name from Node and the PTR record's from this.
- `cancel()` rejects every call in progress with `ECANCELLED`; what was already sent is
  still answered, into the cache.

Errors are plain `Error`s with `code`, `syscall` and `hostname`, as Node's are:

| Code                                           | When                                                                       |
| ---------------------------------------------- | -------------------------------------------------------------------------- |
| `ENOTFOUND`                                    | NXDOMAIN; from `lookup`, also a name with no addresses                     |
| `ENODATA`                                      | NOERROR with an empty answer section                                       |
| `ESERVFAIL`, `EREFUSED`, `EFORMERR`, `ENOTIMP` | the server answered with that rcode                                        |
| `EBADRESP`                                     | any other rcode, or `InvalidResponseError`, `ParseError`, `TruncatedError` |
| `ETIMEOUT`                                     | `TimeoutError`                                                             |
| `ECONNREFUSED`                                 | `ConnectionError`, `ProxyError`, `EmptyResponseError`, `NoServerError`     |
| `EBADNAME`                                     | `InvalidQueryError`                                                        |
| `ECANCELLED`                                   | `cancel()`                                                                 |
| `EAI_AGAIN`                                    | from `lookup`: no server could say whether the name exists                 |

The library error behind a code, when there is one, is its `cause`. These codes exist only
in this entry; the rest of the library has none.

As in Node, a truncated answer whose TCP retry fails is not returned: the call rejects the
way the TCP query failed, `ETIMEOUT` or `ECONNREFUSED`.

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
| Cache                                                   | yes, by TTL, shared between callers                                                       | c-ares query cache       | the system's       | no                | yes, pluggable (Map, Redis)          | yes                       | no                         | no                                |
| One query on the wire for callers asking the same thing | yes                                                                                       | no                       | no                 | no                | no                                   | not documented            | no                         | n/a                               |
| SOCKS5 and HTTP CONNECT proxies                         | yes                                                                                       | no                       | no                 | no                | through its `request` function       | no                        | no                         | no                                |
| Browsers and Workers                                    | records, wire and DNSSEC entries anywhere; DoH through `fetch`; TCP on Cloudflare Workers | no                       | no                 | no                | no                                   | Bun only                  | Deno only                  | n/a                               |
| Typed records                                           | 33 types, every field typed; unknown types as raw data                                    | 12 types in fixed shapes | addresses only     | about 20 types    | Node's shapes                        | addresses only            | 12 types                   | text                              |
| TypeScript                                              | written in it                                                                             | `@types/node`            | `@types/node`      | bundled types     | bundled types                        | built in                  | built in                   | n/a                               |
| Runtime dependencies                                    | none                                                                                      | built in                 | built in           | none              | 15                                   | built in                  | built in                   | n/a                               |
| A `node:dns/promises` drop-in                           | yes (`@aoxborrow/dns/promises`)                                                           | it is the original       | it is the original | no                | yes, over DoH                        | Bun implements `node:dns` | Deno implements `node:dns` | n/a                               |

"System resolver" means the client asks the operating system (getaddrinfo), which picks
the transport and the servers.

## Conventions

The shapes every entry hands back follow one set of rules: names without a trailing dot in
the case they were written, header flags as an object of booleans, `rcode` with
`rcodeName`, points in time as `Date`, durations in milliseconds, record fields as the wire
defines them, answers as plain data, problems as codes. They are written down in
[CONVENTIONS.md](CONVENTIONS.md).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
