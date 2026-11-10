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
| `@aoxborrow/dns-client/transports/doh` | DNS over HTTPS, and the tunnelling `fetch` | any |

Entries are added as each layer lands. `test/package.test.ts` keeps the `exports` map, the
published `exports` map and the build entries in step.

## One question, one server

`exchange` puts one question to one server and returns its answer, decoded and raw. It
follows nothing, caches nothing and passes no judgement: NXDOMAIN and SERVFAIL are answers.

By default it is an ordinary recursive query, what `dig` or `node:dns` would send:

```ts
import { exchange } from '@aoxborrow/dns-client';

const res = await exchange({ name: 'example.com', type: 'MX' }, '1.1.1.1');
res.toDig(); // dig @1.1.1.1 example.com MX
```

Asking an authoritative server directly is a setting:

```ts
import { decodeRecords, exchange } from '@aoxborrow/dns-client';

const res = await exchange({ name: 'example.com', type: 'DNSKEY' }, '199.43.135.53', {
  transport: 'tcp', // 'udp' (default) | 'tcp' | 'tls' | 'doh'
  recursionDesired: false, // the question as an authoritative server is asked it
  checkingDisabled: true,
  dnssecOk: true,
});
res.message.rcode; // 0
res.message.answers[0].rdata; // Uint8Array, as signed
decodeRecords(res.message.answers); // typed records
res.transport; // the transport that carried the answer
res.toDig(); // dig +dnssec +cd +norecurse +tcp @199.43.135.53 example.com DNSKEY
```

A UDP answer that comes back truncated is asked again over TCP. A query that times out is
sent again (`timeout` 5000 ms per attempt, `retries` 2). Errors are `DnsError` subclasses
with a `retryable` flag and the `server`, `query`, `type` and `transport` they came from.

Every query can go through a proxy, and with `proxy` set nothing goes around it:

```ts
await exchange({ name: 'example.com', type: 'A' }, 'https://dns.google/dns-query', {
  proxy: 'socks5://user:pass@proxy.example:1080', // or http:// for an HTTP CONNECT proxy
});
```

UDP uses a SOCKS5 UDP association where the proxy offers one and TCP through the tunnel
where it does not; the result's `transport` says which. An explicit `fetch` (DoH) or
`connect` (TCP, DoT) wins over `proxy` for its protocol. Credentials never appear in an
error or an event.

`onEvent` reports every network exchange, failures included, plus retries, TCP fallbacks
and proxy handshakes. Calls share sockets and connections: pass
`transports: createTransports({ proxy })` to reuse them across calls that set transport
options.

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
