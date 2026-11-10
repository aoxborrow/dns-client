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

Entries are added as each layer lands. `test/package.test.ts` keeps the `exports` map, the
published `exports` map and the build entries in step.

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
```

## License

MIT
