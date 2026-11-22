# Contributing

## Setup

```bash
yarn install
yarn test            # unit tests, no network
yarn test:live       # the live suite, over the real network
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
- Comments start in lower case unless they open with a proper noun, and say why the code
  is the way it is. They are `//`, with one exception: a declaration an entry point exports,
  and each public member of one, gets a `/** */` comment saying what it is and does, so
  editors and the published `.d.ts` show it. `test/tsdoc.test.ts` fails on a public
  declaration with a `//` comment, and on a `/** */` anywhere else.

## Tests

The tests follow the entry points, one directory each:

| Directory | What it tests |
| --- | --- |
| `test/root` | the root entry: `Resolver`, `AuthoritativeResolver`, the exchange underneath them, the errors |
| `test/wire` | `/wire`: names, messages, the byte helpers |
| `test/records` | `/records`: the tables, decoding, formatting, parsing, validation, EDNS options |
| `test/dnssec` | `/dnssec` |
| `test/transports` | `/transports` and `/transports/doh`: UDP, TCP, TLS, HTTPS, the proxies, the connectors |
| `test/promises` | `/promises` |
| `test/support` | the servers, mocks and fixture loaders the others share, and their own tests |
| `test/fixtures` | recorded messages and the IANA root files |

`test/package.test.ts` checks the manifest and the entry points themselves.

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

The live suite, `test/live`, is the exception, and is never part of `yarn test`. It asks
1.1.1.1, 8.8.8.8 and 9.9.9.9 over every transport, walks from the root, and validates a
table of names whose DNSSEC verdict is known (signed, unsigned, broken on purpose, missing,
wildcards, aliases), checking each verdict against what 1.1.1.1 and 8.8.8.8 say. A query
that fails on the network is retried once; a wrong verdict fails the run. It prints the
table of verdicts at the end. CI runs it weekly.

## Documentation

`README.md` is the overview; the reference for each entry point is under `docs/`. The
pages the tests read are listed in `test/support/docs.ts`, so a new page goes on that list.
`test/readme.test.ts` holds them to the code:

- every `` ```ts `` example typechecks against the package as a user imports it, so each
  must stand alone with its own imports
- an example that needs no network runs, and a statement written `expression; // value`,
  or followed by a comment holding only the value, must give that value
- every value an entry point exports is named somewhere in the pages

An example that needs the network is fenced `` ```ts network ``. It is still typechecked,
and runs in the live suite (`test/live/docs.live.test.ts`) instead.

## Cloudflare Workers

The parts of the suite that need no listening socket (the codec, the records, the
resolvers over the simulated network, the DNSSEC primitives) also run inside the Workers
runtime, with [`@cloudflare/vitest-plugin`](https://developers.cloudflare.com/workers/testing/vitest-integration/).
The standalone repository has it as a devDependency; this monorepo leaves it out, because it
brings `workerd` into every install. Its config is `vitest.workers.config.ts` at the
standalone repository's root (here, `extract/standalone/vitest.workers.config.ts`):

```bash
yarn test:workers
```

A test that only makes sense on Node says so with `it.skipIf(!isNode())`, and Ed448 is
skipped where the runtime cannot make a key for it. The tests of the transports start
real servers and stay on Node. This runs a local `workerd`, which is more permissive than
a deployed Worker: it lets TLS start inside a proxy tunnel, which a deployed Worker does
not.

## Trust anchors

The IANA root trust anchors (`src/dnssec/anchors.ts`) and the root hints
(`src/resolvers/root-hints.ts`) are data compiled into the library, and they expire on
IANA's schedule. CI compares them with IANA's files every week, and the check fails when
they differ:

```bash
yarn refresh-anchors --check   # report, and fail on a difference
yarn refresh-anchors           # rewrite the bundled data
```

The script fetches over TLS alone. Before committing a changed anchor, verify the anchor
file's detached signature against ICANN's CA, and check that the digests in the diff are
the ones in the verified file:

```bash
curl -sO https://data.iana.org/root-anchors/root-anchors.xml
curl -sO https://data.iana.org/root-anchors/root-anchors.p7s
curl -sO https://data.iana.org/root-anchors/icannbundle.pem
openssl smime -verify -CAfile icannbundle.pem -inform der \
  -in root-anchors.p7s -content root-anchors.xml
```

Then save the verified `root-anchors.xml` and a fresh
[`named.root`](https://www.internic.net/domain/named.root) over the copies in
`test/fixtures/iana/`, so the offline test compares the bundle with what it was refreshed
from, and run `yarn test`: `test/dnssec/canonical.test.ts` recomputes each anchor's digest
from the published key.

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

## Releasing

A release runs on a pushed tag `v<version>`, which must equal `version` in `package.json`.
The workflow (`.github/workflows/release.yml`) lints, tests, runs the browser and pack checks,
builds, and publishes with npm's trusted publishing, with provenance. A version with a hyphen
(`1.0.0-beta.2`) goes to the `beta` dist-tag, any other to `latest`.

1. Add the version's section to `CHANGELOG.md`, and bump `version` in `package.json`.
2. Commit, then `git tag v<version> && git push origin v<version>`.
3. A GitHub release can follow: `gh release create v<version> --generate-notes`, with
   `--prerelease` for a beta.

A broken release is deprecated, not unpublished:
`npm deprecate @aoxborrow/dns@<version> "<why, and which version to use>"`.
