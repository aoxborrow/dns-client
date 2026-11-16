import path from 'path';
import { fileURLToPath } from 'url';
import tseslint from 'typescript-eslint';
import { createEslintConfig } from '../../eslint.config.base.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default [
  ...createEslintConfig({
    dirname: __dirname,
    // the standalone repo's own configs, linted there with its own dependencies
    ignores: ['extract/standalone/**'],
  }),
  // the extraction scripts are plain JavaScript that no tsconfig covers
  { ...tseslint.configs.disableTypeChecked, files: ['extract/**'] },
  // the library never writes to the console; callers observe it through events
  {
    files: ['src/**/*.ts'],
    rules: { 'no-console': 'error' },
  },
];
