# Contributing

## Setup

```bash
yarn install
yarn test            # unit tests, no network
yarn lint            # typecheck, eslint, prettier
yarn build           # ES modules and type declarations into dist/
yarn check:browser   # the browser-safe entries bundle with no Node built-ins
yarn check:pack      # the packed tarball installs and imports, with one set of error classes
yarn bench           # against other DNS clients on a local server; --network adds public resolvers
```

Node 22 or later.

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
| `src/dnssec` | the judging core and the validator, signature verification, NSEC and NSEC3 proofs, trust anchors, canonical form and digests |
| `src/promises` | the `node:dns/promises` facade over `Resolver` |

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

The tests follow the entry points, one directory each:

| Directory | What it tests |
| --- | --- |
| `test/root` | the root entry: `Resolver`, `AuthoritativeResolver`, the exchange underneath them, the errors |
| `test/wire` | `/wire`: names, messages, the byte helpers |
| `test/records` | `/records`: the tables, decoding, formatting, parsing, validation, EDNS options |
| `test/dnssec` | `/dnssec` |
| `test/transports` | `/transports/*`: UDP, TCP, TLS, HTTPS, the proxies, the connectors |
| `test/promises` | `/promises` |
| `test/support` | the servers, mocks and fixture loaders the others share, and their own tests |
| `test/fixtures` | recorded messages and the IANA root files |

`test/package.test.ts` checks the manifest and the entry points themselves, and
`test/readme.test.ts` typechecks every TypeScript example in the README, so each must
stand alone with its own imports.

Unit tests use no network. Three things make that possible, all under `test/support`:

- a DNS server on UDP and TCP that answers from a function or from recorded exchanges, and
  can misbehave on demand
- a simulated network of root, TLD and zone servers for the resolvers
- SOCKS5 and HTTP CONNECT proxy mocks that really tunnel, and can refuse

A change to how the library reads a response should come with a recorded response that
shows it. A change to what it sends should assert the bytes.

### The message corpus

`test/fixtures/messages.json` holds a few hundred real responses that the codec and record
tests decode, format, parse and fuzz, each checked against `dns-packet` where it can read
the type. Every response answers a question about a public zone: the root, top-level
domains, the example domains, the IANA, ISC, IETF and CZ.NIC zones, and test zones kept
broken on purpose. Record types no public zone serves are built in code as synthetic
messages. The corpus holds a record of every type the library decodes, and a test fails
if one goes missing.

The questions are listed in `test/fixtures/questions.json`, in groups. A group asks every
combination of its names, types and servers:

```json
{
  "note": "what the group is for (optional)",
  "server": ["198.41.0.4", "193.0.14.129"],
  "transport": "tcp",
  "flags": ["do", "nsid"],
  "name": "example.com",
  "type": ["A", "DS"]
}
```

- `server`: an IP address, or a list of them
- `transport`: `tcp` (the default) or `udp`
- `flags`: any of `rd` (recursion desired), `cd` (checking disabled), `do` (DNSSEC OK),
  `nsid` (ask for the server's identifier) and `noedns` (send no OPT record)
- `name` and `type`: one, or a list

To add a response, add its question and capture it; to refresh some, name them:

```bash
yarn capture                    # ask every question again and rewrite the corpus
yarn capture 'cloudflare.com'   # ask again only the questions whose label contains the text
```

A label reads `<transport> <server> <name> <type> +<flag>...`. Every response is kept,
whatever its response code, and a truncated UDP response is kept as it came. Capturing
needs the network, TCP and UDP on port 53; the tests never do.

## Cloudflare Workers

The parts of the suite that need no listening socket (the codec, the records, the
resolvers over the simulated network, the DNSSEC primitives) also run inside the Workers
runtime, with [`@cloudflare/vitest-plugin`](https://developers.cloudflare.com/workers/testing/vitest-integration/):

```ts
// vitest.workers.config.ts
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: { compatibilityDate: '2026-11-01', compatibilityFlags: ['nodejs_compat'] },
    }),
  ],
  test: {
    name: 'dns-workers',
    globals: true,
    include: [
      'test/records/**/*.test.ts',
      'test/wire/**/*.test.ts',
      'test/dnssec/**/*.test.ts',
      'test/root/resolvers.test.ts',
    ],
  },
});
```

```bash
vitest run --config vitest.workers.config.ts
```

A test that only makes sense on Node says so with `it.skipIf(!isNode())`, and Ed448 is
skipped where the runtime cannot make a key for it. The tests of the transports start
real servers and stay on Node. This runs a local `workerd`, which is more permissive than
a deployed Worker: it lets TLS start inside a proxy tunnel, which a deployed Worker does
not.

## Adding a record type

1. Its number and name in `src/protocol/types.ts`.
2. Its interface in `src/records/types.ts`.
3. Decoding in `src/records/decode.ts`, formatting in `src/records/format.ts`, and parsing
   from text in `src/records/parse.ts`.
4. A wire fixture and a round trip through all three in `test/records`.

## Adding an entry point

An entry point is listed in three places, and `test/package.test.ts` fails if they
disagree: `exports` and `publishConfig.exports` in `package.json`, and `entries` in
`tsup.config.ts`. If it must run in a browser, add it to `scripts/browser-check.mjs`.
