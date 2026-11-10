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

Entries are added as each layer lands. `test/package.test.ts` keeps the `exports` map, the
published `exports` map and the build entries in step.

## Asking questions

Not built yet. The resolvers arrive in the next milestone, and this is the shape they will
have:

```ts
import { AuthoritativeResolver, Resolver } from '@aoxborrow/dns-client';

// an ordinary recursive query, like dig or node:dns, to the system's resolvers
const resolver = new Resolver();
const answer = await resolver.query('example.com', 'MX');
answer.rcodeName; // 'NOERROR'
answer.records; // MxRecord[]
answer.toDig(); // dig @192.0.2.53 example.com MX

// one particular server, for this call
await resolver.query('example.com', 'MX', { server: '1.1.1.1' });

// from the root, asking each zone's own servers
const auth = new AuthoritativeResolver();
await auth.query('example.com', 'MX');
```

Each resolver has one `query()`, and both return the same answer: the response code, typed
records, the decoded message and the raw bytes. NXDOMAIN is an answer, not an error.

What is built is everything underneath: the wire codec, the typed records, the four
transports with their proxy support, and the function that puts one question to one server
and checks the response is the answer to it.

## Proxies

Every transport can go through a SOCKS5 or HTTP CONNECT proxy, and with `proxy` set nothing
goes around it: a query that cannot go through the proxy fails.

| Transport | Through the proxy |
| --- | --- |
| TCP, DoT | a tunnel to the server; DoT upgrades to TLS inside it |
| DoH | HTTP over the tunnel, upgraded to TLS by the runtime |
| UDP | a SOCKS5 UDP association where the proxy offers one, otherwise TCP through the tunnel; the answer says which |

An explicit `fetch` (DoH) or `connect` (TCP, DoT) wins over `proxy` for its protocol.
Credentials never appear in an error or an event.

### Cloudflare Workers

A deployed Worker cannot start TLS inside a tunnel, so the built-in path covers plain TCP
through a proxy and nothing that needs TLS. For DoH through a proxy, pass a `fetch` that
does its own TLS. The [`tunnelfetch`](https://github.com/latentharbor/tunnelfetch) package
is one:

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
