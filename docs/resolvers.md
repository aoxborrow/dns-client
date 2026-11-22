# Resolvers

The root entry, `@aoxborrow/dns`, asks questions through one of two resolvers. This page is
the reference for both: how each one picks its servers, every option, the cache, events and
errors. The [README](../README.md) has the quick start, the shape of an answer and how to read
a negative one.

Both resolvers have one method, `query(name, type, options?)`, and return the same `Answer`.

## `Resolver`

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

## `AuthoritativeResolver`

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

```ts network
import { AuthoritativeResolver } from '@aoxborrow/dns';

const resolver = new AuthoritativeResolver();
// start at one of org's servers
await resolver.query('mozilla.org', 'NS', {
  startAt: [{ name: 'v0n0.pir-ns.org', ipv4: '199.19.56.1' }],
});
```

## Options

Every option, with its default, is in the README's [Options](../README.md#options). The
query settings (`transport`, `port`, `timeout`, `retries`, `tcpFallback`, the flags and the
EDNS settings) can be set on a resolver for every query, or passed to one `query()`. These
need more than a line:

- **`retries`**: further attempts at a server that fails in a way worth retrying. The
  default is `2`, or `1` with several `servers`, so each server is asked once before any is
  asked again. `AuthoritativeResolver` asks a zone's next server instead (`0`), and asks only
  the last one a zone has left a second time (`1`).
- **`totalTimeout`**: the milliseconds one answer may take altogether. That covers every
  server, retry and TCP fallback, time spent waiting under `concurrency` and
  `serverConcurrency`, and the queries `validate` makes for the chain. Where `timeout` or
  `retries` is set, the default is at least what one server's attempts take,
  `timeout × (retries + 1)`, so it never cuts them short. `AuthoritativeResolver` gives the
  last server a zone has left the rest of it, and counts nameserver lookups too.
- **`tcpFallback`**: when TCP fails too (refused, timed out, or no time left for it), the
  truncated answer comes back as it came, `flags.tc` set, with the TCP error in
  `tcpFallbackError`.
- **`edns: false`**: sends a plain RFC 1035 query, with no EDNS record. `dnssecOk`,
  `udpPayloadSize` and `ednsOptions` travel in that record, so setting one of them together
  with `edns: false` is a `TypeError`. One exception: `edns: false` passed to a single
  `query()` sends that query plain, dropping any of the three that were set on the resolver.
- **`signal`**, per query: an aborted query rejects with the signal's reason, including one
  still waiting for its turn under a concurrency limit.
- **`server`**, on one `Resolver.query()`: an address, a name, `host:port`, a URL, or
  `{ address, port, serverName, url }`. The answer is neither taken from the cache nor put in
  it.
- **`addressFamily`**: with `'both'`, a server's IPv6 address is tried only once each of the
  zone's servers has been tried at its first address, so a host with no IPv6 route does not
  wait out a timeout per server.
- **`cache`** on `AuthoritativeResolver`: remembers delegations between queries, and shares
  the referrals of queries running at the same time. With `false`, every query walks from
  the root.
- **`startAt`**, on one `AuthoritativeResolver.query()`: nameservers that come without an
  address are still looked up from the root servers, and the delegations found on the way
  are not kept for other queries.
- **`fromRoot`**, on one `AuthoritativeResolver.query()`: what the walk learns is kept for
  other queries.
- **`onEvent`**, on one `AuthoritativeResolver.query()`: told only of the queries this one
  sends, nameserver lookups included. The resolver's own `onEvent` is told as well.

The default `rootServers` is `ROOT_HINTS`, taken from IANA's root hints file.
`ROOT_HINTS_INFO` says where: `source` is the file's URL, `version` the root zone version
the list was taken from, and `refreshed` the day the list was last compared with the file.
Every dataset the library bundles has an info object like it, named after the dataset.

Both resolvers take the transport options (`proxy`, `fetch`, `connect`, `tls`, `pipeline`,
`idleTimeout`, `dohMethod`; see [Wire format and transports](wire-and-transports.md#transports)),
`onEvent`, and `transports`, a set of sockets to share with other resolvers. The set is made
with `createTransports(options)` and takes its transport options there: a resolver given
both `transports` and a transport option throws a `TypeError`.

## Caching

`Resolver` keeps each response for its TTL (the smallest in the answer section; for a
negative answer, its `negativeTtl`), and for no more than a day, or an hour for a negative
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

```ts network
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

## Events

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

## Errors

An error means no usable response arrived. Every error the library throws is a
`DnsError`, told apart by its class (and `name`). There are no string codes.

```ts network
import { DnsError, Resolver, TimeoutError } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['192.0.2.1', '192.0.2.2'] });

try {
  await resolver.query('example.com', 'A');
} catch (error) {
  if (error instanceof TimeoutError) {
    error.retryable; // true: asking again could work
    error.server; // '192.0.2.2'
    error.message; // 'No answer from 192.0.2.2 within 4994 ms': what was left of `totalTimeout`
    error.failures; // [{ server: '192.0.2.1', error: TimeoutError }, { server: '192.0.2.2', error: TimeoutError }]
  } else if (error instanceof DnsError) {
    error.name; // 'ConnectionError', 'InvalidResponseError', …
  }
}
```

The classes, and when each is thrown, are tabled in the [README](../README.md#errors).

Every `DnsError` carries `retryable`, and what is known of the exchange: `server`, `query`,
`type`, `transport`. One raised from a server's response also carries `rcode`, `rcodeName`
and `extendedErrors`. When a resolver asked more than one server, `failures` lists each
server and what went wrong there, in the order asked, the thrown error among them; an
error from `AuthoritativeResolver` also carries `trace`. `toJSON()` gives the same as plain
data, and `errorData(error)` gives any error as the plain data events and results carry:
`name`, `message`, `retryable`, and what a `DnsError` knows of the response code. An
aborted query rejects with the signal's reason, not a `DnsError`.

A mistake in what the program passed (an address that cannot be read, options that
contradict each other) is a `TypeError`, not a `DnsError`; the [README](../README.md#errors)
lists them.

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
