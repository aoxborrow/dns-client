# Contributing

## Setup

```bash
yarn install
yarn test            # unit tests, no network
yarn lint            # typecheck, eslint, prettier
yarn build           # ES modules, CommonJS and type declarations into dist/
yarn check:browser   # the browser-safe entries bundle with no Node built-ins
yarn check:pack      # the packed tarball installs and imports as ES modules and CommonJS
yarn bench           # a local benchmark against node:dns, no network
```

Node 20 or later.

## How the code is laid out

Each layer uses only the ones above it in this list.

| Directory | What it holds |
| --- | --- |
| `src/protocol` | the tables: record types, classes, response codes, EDNS option codes |
| `src/wire` | names, messages and queries, to and from bytes |
| `src/records` | typed records: decoding, formatting, parsing and validation |
| `src/transports` | UDP, TCP, TLS and HTTPS, the proxy handshakes, and the connectors for Node and Cloudflare Workers |
| `src/exchange.ts` | one question to one server: retries, the fallback to TCP, events. Internal, not exported |
| `src/resolvers` | `Resolver` and `AuthoritativeResolver`, the cache, the root hints |
| `src/dnssec` | the chain-of-trust analysis, signature verification, NSEC and NSEC3 proofs, trust anchors |

## Rules

- No runtime dependencies. `test/package.test.ts` fails if one is added.
- Relative imports only.
- `Uint8Array` and `DataView`, never `Buffer`.
- Node built-ins only under `src/transports/`, and imported when first needed, so the
  other entries bundle for a browser.
- No console output from `src/`. What a caller might want to log goes through `onEvent`.
- Comments are `//`, start in lower case unless they open with a proper noun, and say why
  the code is the way it is.

## Tests

Unit tests use no network. Three things make that possible, all under `test/support`:

- a DNS server on UDP and TCP that answers from a function or from recorded exchanges, and
  can misbehave on demand
- a simulated network of root, TLD and zone servers for the resolvers
- SOCKS5 and HTTP CONNECT proxy mocks that really tunnel, and can refuse

A change to how the library reads a response should come with a recorded response that
shows it. A change to what it sends should assert the bytes.

## Adding a record type

1. Its number and name in `src/protocol/types.ts`.
2. Its interface in `src/records/types.ts`.
3. Decoding in `src/records/decode.ts`, formatting in `src/records/format.ts`, and parsing
   from text in `src/records/parse.ts`.
4. A wire fixture and a round trip through all three in `test/records`.

## Adding an entry point

An entry point is listed in four places, and `test/package.test.ts` fails if they
disagree: `exports` and `publishConfig.exports` in `package.json`, and `entries` in
`tsup.config.ts`. If it must run in a browser, add it to `scripts/browser-check.mjs`.
