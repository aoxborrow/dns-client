import path from 'path';
import { fileURLToPath } from 'url';
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import typescriptEslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import importPlugin from 'eslint-plugin-import';
import globals from 'globals';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default tseslint.config(
  {
    ignores: ['node_modules/**', 'out/**', 'build/**', 'dist/**', 'coverage/**'],
  },
  {
    files: ['**/*.{ts,mjs,cjs}'],
    extends: [eslint.configs.recommended, tseslint.configs.recommendedTypeChecked],
    plugins: {
      '@typescript-eslint': typescriptEslint,
      import: importPlugin,
    },
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        moduleResolution: 'bundler',
        tsconfigRootDir: __dirname,
        project: ['./tsconfig.json'],
        EXPERIMENTAL_useProjectService: true,
      },
      globals: {
        ...globals.node,
        ...globals.es2021,
      },
    },
    settings: {
      'import/parsers': {
        '@typescript-eslint/parser': ['.ts'],
      },
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
          project: './tsconfig.json',
        },
        node: true,
      },
    },
    rules: {
      // enforce .js extension for ESM imports
      'import/extensions': [
        'error',
        'ignorePackages',
        {
          js: 'always',
          ts: 'never',
        },
      ],
    },
  }
);
