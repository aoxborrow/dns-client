import { defineConfig } from 'vitest/config';

// unit tests only: no network, no database
export default defineConfig({
  test: {
    name: 'dns-client',
    environment: 'node',
    globals: true,
    include: ['test/**/*.test.ts', 'src/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/*.itest.ts'],
  },
});
