// browser-safety check for the entries that ship to browsers.
//
// the boundary lint keeps Node core modules out of this package's own source, but it
// cannot see what an import chain pulls in. Bundling each browser-safe entry with
// esbuild's browser target closes that gap: a `node:*` specifier anywhere in the chain
// fails to resolve and fails the build.
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// add an entry here when it is meant to run in a browser
const browserSafeEntries = ['src/records/index.ts', 'src/wire/index.ts'];

try {
  await build({
    entryPoints: browserSafeEntries.map(entry => resolve(root, entry)),
    bundle: true,
    write: false,
    // required by esbuild for multi-entry builds even though write:false emits nothing
    outdir: 'browser-check-out',
    platform: 'browser',
    format: 'esm',
    logLevel: 'warning',
  });
  console.log(`✓ dns-client: ${browserSafeEntries.length} browser-safe entries bundled clean.`);
} catch {
  // esbuild already printed the resolution failures; exit non-zero for CI
  console.error('✗ dns-client: a browser-safe entry is NOT browser-safe (see errors above).');
  process.exit(1);
}
