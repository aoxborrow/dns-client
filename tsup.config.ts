import { defineConfig } from 'tsup';

// one build entry per public entry point; test/package.test.ts keeps this list, the
// `exports` map and `publishConfig.exports` in step
export const entries = [
  'src/index.ts',
  'src/records/index.ts',
  'src/wire/index.ts',
  'src/transports/udp.ts',
  'src/transports/tcp.ts',
  'src/transports/tls.ts',
  'src/transports/doh.ts',
  'src/dnssec/index.ts',
  'src/promises/index.ts',
];

export default defineConfig({
  entry: entries,
  // ESM only: Node 22 and up loads it from `require` as well as `import`. Shared code is
  // split into chunks, so each class (DnsError and the rest) exists once, whichever entry
  // it is reached through
  format: ['esm'],
  splitting: true,
  target: 'es2022',
  // never resolve a Node built-in on the library's behalf: a core module reaching the
  // bundle is a bug in the source, not something to polyfill
  platform: 'neutral',
  // the transports import Node's modules, and only when a connection is first opened.
  // Those imports stay as they are for the runtime to resolve
  external: [/^node:/],
  // `incremental` from the base tsconfig conflicts with declaration emit, and tsup's
  // declaration build sets `baseUrl`, which TypeScript 6 rejects unless told otherwise
  dts: { compilerOptions: { incremental: false, ignoreDeprecations: '6.0' } },
  sourcemap: true,
  clean: true,
  treeshake: true,
});
