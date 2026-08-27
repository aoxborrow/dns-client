import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'es2022',
  platform: 'node',
  outDir: 'dist',
  // `incremental` from the base tsconfig conflicts with tsup's dts
  // emit, so turn it off just for declaration generation.
  dts: { compilerOptions: { incremental: false } },
  sourcemap: true,
  clean: true,
  // Keep code-splitting on so the lazily `import()`-ed transports
  // (udp/tcp/doh) stay separate chunks and aren't pulled in until used
  // — important for DoH-only / Cloudflare Worker consumers that can't
  // load node:net/dgram.
  splitting: true,
  // Bundle our own source into a single module; leave runtime
  // dependencies (buffer, dns-packet) and node builtins as bare
  // external imports.
  bundle: true,
});
