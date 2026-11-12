// pack-and-import check: builds the package, packs it the way a publish would, installs
// the tarball into an empty project and imports every entry point as ESM and as CommonJS.
//
// inside the monorepo the `exports` map points at TypeScript source, so nothing here ever
// exercises the published shape. This does, on every CI run, so a broken `publishConfig`,
// a missing build entry or a stray workspace-only import is caught long before a release.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'inherit'] });
const fail = message => {
  console.error(`✗ dns-client pack check: ${message}`);
  process.exit(1);
};

const work = mkdtempSync(join(tmpdir(), 'dns-client-pack-'));
try {
  run('yarn', ['build'], root);

  const tarball = join(work, 'package.tgz');
  run('yarn', ['pack', '--out', tarball], root);

  // install by extracting: no registry, no lockfile, nothing but the tarball's contents
  const installed = join(work, 'node_modules', '@aoxborrow', 'dns-client');
  mkdirSync(installed, { recursive: true });
  run('tar', ['-xzf', tarball, '-C', installed, '--strip-components=1'], work);

  const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  const subpaths = Object.keys(manifest.exports ?? {});
  if (subpaths.length === 0) fail('the packed manifest has no exports');

  // the packed manifest must describe the build output, never the monorepo's source
  for (const [subpath, target] of Object.entries(manifest.exports)) {
    if (typeof target === 'string') fail(`${subpath} still points at source (${target})`);
    for (const condition of ['import', 'require']) {
      for (const file of [target[condition]?.types, target[condition]?.default]) {
        if (!file) fail(`${subpath} has no ${condition} target`);
        if (!existsSync(join(installed, file))) fail(`${subpath}: ${file} is not in the tarball`);
      }
    }
  }
  if (Object.keys(manifest.dependencies ?? {}).length > 0) {
    fail(`runtime dependencies in the packed manifest: ${Object.keys(manifest.dependencies)}`);
  }
  if (existsSync(join(installed, 'src'))) fail('source files are in the tarball');

  const specifiers = subpaths.map(s =>
    s === '.' ? manifest.name : `${manifest.name}/${s.slice(2)}`
  );
  writeFileSync(
    join(work, 'esm.mjs'),
    specifiers.map(s => `await import(${JSON.stringify(s)});`).join('\n')
  );
  writeFileSync(
    join(work, 'cjs.cjs'),
    specifiers.map(s => `require(${JSON.stringify(s)});`).join('\n')
  );
  run(process.execPath, ['esm.mjs'], work);
  run(process.execPath, ['cjs.cjs'], work);

  console.log(
    `✓ dns-client pack check: ${specifiers.length} entry points import as ESM and CommonJS from the tarball.`
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}
