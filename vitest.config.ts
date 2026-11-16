import { defineConfig } from 'vitest/config';

// unit tests only: no network, no database
export default defineConfig({
  test: {
    name: 'dns',
    environment: 'node',
    globals: true,
    include: ['test/**/*.test.ts', 'src/**/*.test.ts'],
    // the live suite (test/live) has its own config, vitest.live.config.ts
    exclude: ['**/node_modules/**', '**/*.itest.ts', 'test/live/**'],
  },
});
