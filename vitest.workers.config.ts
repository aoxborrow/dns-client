import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

// the parts of the suite that need no listening socket (the codec, the records, the
// resolvers over the simulated network, the DNSSEC primitives), inside the Workers runtime.
// The transports' tests start real servers and stay on Node. Run with `yarn test:workers`
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
    // compare the bundled anchors and algorithm tables with IANA's files on disk, which a
    // Worker cannot read
    exclude: ['test/dnssec/anchors.test.ts', 'test/dnssec/registry.test.ts'],
  },
});
