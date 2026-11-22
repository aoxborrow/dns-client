// browser checks for the entries, made by bundling each with esbuild's browser target.
//
// the boundary lint keeps Node core modules out of this package's own source, but it
// cannot see what an import chain pulls in. Bundling closes that gap.
//
// three entries ship to browsers, and may not name a Node module at all, not even to load
// it later: a `node:*` specifier anywhere in their import chains fails the check.
//
// the root and the transport entries carry the transports, which use Node's modules where
// they exist. They may load one only when a query needs it, with an `import()` that is
// awaited inside a `try`. esbuild leaves such an import for the runtime, and fails the
// build on one at the top of a module or outside a `try`. So these entries are bundled
// with nothing added, as a consumer's build would bundle them, and have to go through
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// add an entry here when it is meant to run in a browser
const browserSafeEntries = ['src/records/index.ts', 'src/wire/index.ts', 'src/dnssec/index.ts'];

// entries that may load Node's modules, but only lazily
const runtimeNeutralEntries = ['src/index.ts', 'src/transports/index.ts', 'src/transports/doh.ts'];

const common = {
  bundle: true,
  write: false,
  // required by esbuild for multi-entry builds even though write:false emits nothing
  outdir: 'browser-check-out',
  platform: 'browser',
  format: 'esm',
  logLevel: 'warning',
};

// any `node:*` specifier is an error, however it is imported: esbuild alone would let one
// through that is awaited inside a `try`
const noNodeModules = {
  name: 'no-node-modules',
  setup(build) {
    build.onResolve({ filter: /^node:/ }, args => ({
      errors: [
        {
          text: `${args.path} is named by ${args.importer}; this entry has to run where there is no Node`,
        },
      ],
    }));
  },
};

let failed = false;

try {
  await build({
    ...common,
    entryPoints: browserSafeEntries.map(entry => resolve(root, entry)),
    plugins: [noNodeModules],
  });
  console.log(`✓ dns: ${browserSafeEntries.length} browser-safe entries name no Node module.`);
} catch {
  // esbuild already printed the failures
  console.error('✗ dns: a browser-safe entry is NOT browser-safe (see errors above).');
  failed = true;
}

try {
  await build({ ...common, entryPoints: runtimeNeutralEntries.map(entry => resolve(root, entry)) });
  console.log(
    `✓ dns: ${runtimeNeutralEntries.length} entries that use Node's modules load them lazily, and bundle for a browser as they are.`
  );
} catch {
  console.error(
    '✗ dns: an entry imports a Node module at load, or outside an awaited `try` (see errors above).'
  );
  failed = true;
}

// exit non-zero for CI
if (failed) process.exit(1);
