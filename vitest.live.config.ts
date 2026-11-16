import { defineConfig } from 'vitest/config';

// the live suite: real resolvers and the real root, over the network. Never part of
// `yarn test`; run with `yarn workspace @aoxborrow/dns test:live`, and on a schedule in CI
// (.github/workflows/dns-live.yml)
export default defineConfig({
  test: {
    name: 'dns-live',
    environment: 'node',
    globals: true,
    include: ['test/live/**/*.live.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 60_000,
    // one file at a time, so the public resolvers see a steady trickle, not a burst
    fileParallelism: false,
  },
});
