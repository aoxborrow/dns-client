# dns-client

A fully-typed DNS client for TypeScript: wire codec, typed records, record validation,
resolvers and DNSSEC.

**Status:** 1.0 is under development and is a rewrite. Nothing here is released yet, and it is
not compatible with the 0.x versions on npm.

## Layout

| Entry | Contents | Runtime |
| --- | --- | --- |
| `@aoxborrow/dns-client` | everything below, re-exported | Node, Workers |
| `@aoxborrow/dns-client/records` | typed records, protocol tables, parse/format/validate | any |
| `@aoxborrow/dns-client/wire` | query encoding and message decoding | any |
| `@aoxborrow/dns-client/transports/udp` | DNS over UDP on shared sockets | Node |
| `@aoxborrow/dns-client/transports/tcp` | DNS over TCP, pooled and pipelined | Node, Workers |
| `@aoxborrow/dns-client/transports/tls` | DNS over TLS | Node, Workers |
| `@aoxborrow/dns-client/transports/doh` | DNS over HTTPS | any |
| `@aoxborrow/dns-client/dnssec` | `analyze()`, the chain-of-trust analysis, and its primitives | Node, Workers |
| `@aoxborrow/dns-client/dnssec/types` | report types, status constants, finding catalog | any |

Entries are added as each layer lands. `test/package.test.ts` keeps the `exports` map, the
published `exports` map and the build entries in step.

## Asking questions

```ts
import { AuthoritativeResolver, Resolver } from '@aoxborrow/dns-client';

// an ordinary recursive query, like dig or node:dns, to the system's resolvers
const resolver = new Resolver();
const answer = await resolver.query('example.com', 'MX');
answer.rcodeName; // 'NOERROR'
answer.records; // MxRecord[]: [{ preference: 10, exchange: 'mail.example.com', ttl: 300, … }]
answer.toDig(); // dig @192.0.2.53 example.com MX

// named servers, tried in order
const named = new Resolver({ servers: ['1.1.1.1', '8.8.8.8'] });

// one particular server, for this call, outside the cache
await resolver.query('example.com', 'MX', { server: '1.1.1.1' });

// from the root, asking each zone's own servers
const auth = new AuthoritativeResolver();
const traced = await auth.query('example.com', 'A');
traced.trace; // every server asked: root, then com, then example.com's
```

Each resolver has one `query()`, and both return the same answer:

| Field | |
| --- | --- |
| `rcode`, `rcodeName`, `flags` | what the server said about the question |
| `records` | the records that answer it, typed by the type asked for |
| `answers`, `authorities`, `additionals` | every record in each section, typed |
| `message`, `bytes` | the response decoded from the wire, and exactly as it arrived |
| `server`, `serverName`, `transport`, `elapsed`, `attempts` | who answered, and how |
| `cached`, `timestamp` | whether it came from the cache, and when it arrived |
| `trace` | `AuthoritativeResolver` only: every hop from the root |

A name that does not exist is an answer (`rcodeName: 'NXDOMAIN'`, no records), not an
error. An error means no usable response arrived: a `DnsError` subclass with a `retryable`
flag and the `server`, `query`, `type` and `transport` it came from. An error from
`AuthoritativeResolver` also carries `trace`, the servers asked before it failed.

`timeout` is the patience with one server. `AuthoritativeResolver` also takes
`totalTimeout` (30 seconds by default), the time one answer may take altogether, since a
zone whose servers all stay silent would otherwise cost a timeout for each of them.
Retries and a TCP fallback count against it. `exchange` takes a `totalTimeout` of its own,
for all its attempts together, and has none by default.

`Resolver` caches by TTL, shares one query between callers asking the same thing at once,
and moves to the next server when one fails. `AuthoritativeResolver` remembers delegations,
looks up nameservers that come without an address, moves past servers that do not answer
for their zone, and stops at an alias into another zone unless `followCnames` is set.

## DNSSEC

```ts
import { analyze } from '@aoxborrow/dns-client/dnssec';

const report = await analyze('example.com');
report.overallStatus; // 'secure' | 'insecure' | 'bogus' | 'indeterminate'
report.chain; // every zone from the root down: keys, delegation, signatures, denial proofs
report.findings; // what was found wrong or worth knowing, each with a stable slug
```

It asks the zones' own servers directly, with checking disabled, and verifies every
signature itself: RSA, ECDSA and EdDSA through WebCrypto, DS digests and NSEC3 hashes with
its own SHA-1, SHA-256 and SHA-384. An algorithm the runtime cannot verify is reported as
not checked, never as a pass. `now` judges signatures against a time other than the
present.

## Proxies

Every transport can go through a SOCKS5 or HTTP CONNECT proxy, and with `proxy` set nothing
goes around it: a query that cannot go through the proxy fails.

| Transport | Through the proxy |
| --- | --- |
| TCP, DoT | a tunnel to the server; DoT upgrades to TLS inside it |
| DoH | not by itself: pass a `fetch` that uses the proxy. Without one the query fails |
| UDP | a SOCKS5 UDP association where the proxy offers one, otherwise TCP through the tunnel; the answer says which |

An explicit `connect` (TCP, DoT) wins over `proxy` for its protocol, and a `proxy` function
can leave a server unproxied by returning nothing for it. Credentials never appear in an
error or an event.

### Cloudflare Workers

A deployed Worker cannot start TLS inside a tunnel, so through a proxy there the built-in
tunnel carries plain TCP and nothing else. For DoH through a proxy, the `fetch` to pass is
one that does its own TLS. The [`tunnelfetch`](https://github.com/latentharbor/tunnelfetch)
package is one:

```ts
import { createCloudflareConnect } from '@aoxborrow/dns-client';
import { connect } from 'cloudflare:sockets';
import { Client } from 'tunnelfetch';

const client = new Client({ connect, proxy: env.PROXY_URL });
const options = {
  connect: createCloudflareConnect(connect), // TCP: pass the runtime's connect in
  fetch: (url, init) => client.fetch(url, init), // DoH: tunnelfetch does the TLS
};
```

That combination has not been run with this library yet. DoT through a proxy is not
available on Workers, and UDP is not available there at all.

## Rules

- No runtime dependencies.
- Relative imports only.
- `Uint8Array` and `DataView`, never `Buffer`.
- No console output from `src/`.

## Scripts

```bash
yarn test            # unit tests, no network
yarn lint            # typecheck, eslint, prettier
yarn build           # ESM + CommonJS + type declarations into dist/
yarn check:browser   # the browser-safe entries bundle with no Node built-ins
yarn check:pack      # the packed tarball installs and imports as ESM and CommonJS
yarn bench           # local benchmark against node:dns, no network
```

## License

MIT
