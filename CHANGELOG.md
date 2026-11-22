# Changelog

Every release of `@aoxborrow/dns`. Releases before 1.0 were published as
`@aoxborrow/dns-client`; [UPGRADING.md](UPGRADING.md) covers the move from 0.x.

## 1.0.0-beta.1

The first release under the new name, on npm's `beta` tag. A rewrite of
`@aoxborrow/dns-client` 0.x with no runtime dependencies.

- `Resolver`, which asks recursive resolvers with failover, retries, a cache that honours
  TTLs and a total timeout, and `AuthoritativeResolver`, which walks from the root servers
  and records every server it asked.
- UDP, TCP, DNS over TLS and DNS over HTTPS, through SOCKS5 and HTTP CONNECT proxies if
  asked, with sockets shared between resolvers.
- Typed records for 33 types, presentation-format parsing and formatting, and record
  validation with problems given as codes and values.
- DNSSEC validation (`validate: true`) on both resolvers, and the judging core and
  primitives it is built from in `/dnssec`.
- A `node:dns/promises` facade in `/promises`.
- The records, wire and DNSSEC entries run in browsers and Workers; DoH runs anywhere
  `fetch` does, and TCP on Cloudflare Workers.
