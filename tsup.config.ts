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
  'src/dnssec/types.ts',
];

export default defineConfig({
  entry: entries,
  // ESM for modern consumers, CommonJS for the rest
  format: ['esm', 'cjs'],
  outExtension({ format }) {
    return { js: format === 'esm' ? '.js' : '.cjs' };
  },
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
