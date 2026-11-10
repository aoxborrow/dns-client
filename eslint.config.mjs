import path from 'path';
import { fileURLToPath } from 'url';
import { createEslintConfig } from '../../eslint.config.base.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default [
  ...createEslintConfig({
    dirname: __dirname,
  }),
  // the library never writes to the console; callers observe it through events
  {
    files: ['src/**/*.ts'],
    rules: { 'no-console': 'error' },
  },
];
