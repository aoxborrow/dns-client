// browser-safety check for the entries that ship to browsers, and runtime-neutrality check
// for the root entry.
//
// the boundary lint keeps Node core modules out of this package's own source, but it
// cannot see what an import chain pulls in. Bundling each browser-safe entry with
// esbuild's browser target closes that gap: a `node:*` specifier anywhere in the chain
// fails to resolve and fails the build.
//
// the root entry carries the transports, which use Node's modules where they exist. It may
// load them only when a query needs them, with `import()`, never at import: so the root is
// bundled the same way, with a `node:*` module allowed only as a dynamic import
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// add an entry here when it is meant to run in a browser
const browserSafeEntries = ['src/records/index.ts', 'src/wire/index.ts', 'src/dnssec/index.ts'];

// entries that may load Node's modules, but only lazily
const runtimeNeutralEntries = ['src/index.ts'];

const common = {
  bundle: true,
  write: false,
  // required by esbuild for multi-entry builds even though write:false emits nothing
  outdir: 'browser-check-out',
  platform: 'browser',
  format: 'esm',
  logLevel: 'warning',
};

// a `node:*` module loaded with `import()` is left for the runtime to find when the code
// runs; one imported at the top of a module fails the build
const lazyNodeModules = {
  name: 'lazy-node-modules',
  setup(build) {
    build.onResolve({ filter: /^node:/ }, args => {
      if (args.kind === 'dynamic-import') return { path: args.path, external: true };
      return {
        errors: [
          {
            text: `${args.path} is imported at load time by ${args.importer}; load it with import() where it is needed`,
          },
        ],
      };
    });
  },
};

let failed = false;

try {
  await build({ ...common, entryPoints: browserSafeEntries.map(entry => resolve(root, entry)) });
  console.log(`✓ dns: ${browserSafeEntries.length} browser-safe entries bundled clean.`);
} catch {
  // esbuild already printed the resolution failures
  console.error('✗ dns: a browser-safe entry is NOT browser-safe (see errors above).');
  failed = true;
}

try {
  await build({
    ...common,
    entryPoints: runtimeNeutralEntries.map(entry => resolve(root, entry)),
    plugins: [lazyNodeModules],
  });
  console.log(`✓ dns: the root entry loads no Node module at import.`);
} catch {
  console.error('✗ dns: the root entry loads a Node module at import (see errors above).');
  failed = true;
}

// exit non-zero for CI
if (failed) process.exit(1);
