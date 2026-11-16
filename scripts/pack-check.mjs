// pack-and-import check: builds the package, packs it the way a publish would, installs
// the tarball into an empty project and imports every entry point.
//
// inside the monorepo the `exports` map points at TypeScript source, so nothing here ever
// exercises the published shape. This does, on every CI run, so a broken `publishConfig`,
// a missing build entry or a stray workspace-only import is caught long before a release.
//
// the package is ESM only. It also checks that the error classes are one set across the
// entries: the build splits shared code into chunks, and an error thrown by code reached
// through `/wire` or `/records` must be `instanceof` the class the root exports. A class
// copied into two entry bundles would break that, and only the built package can show it
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'inherit'] });
const fail = message => {
  console.error(`✗ dns pack check: ${message}`);
  process.exit(1);
};

const work = mkdtempSync(join(tmpdir(), 'dns-pack-'));
try {
  run('yarn', ['build'], root);

  const tarball = join(work, 'package.tgz');
  run('yarn', ['pack', '--out', tarball], root);

  // install by extracting: no registry, no lockfile, nothing but the tarball's contents
  const installed = join(work, 'node_modules', '@aoxborrow', 'dns');
  mkdirSync(installed, { recursive: true });
  run('tar', ['-xzf', tarball, '-C', installed, '--strip-components=1'], work);

  const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  const subpaths = Object.keys(manifest.exports ?? {});
  if (subpaths.length === 0) fail('the packed manifest has no exports');
  if (manifest.type !== 'module') fail('the packed manifest is not "type": "module"');
  if (manifest.main) fail(`the packed manifest still has a CommonJS main (${manifest.main})`);

  // the packed manifest must describe the build output, never the monorepo's source
  for (const [subpath, target] of Object.entries(manifest.exports)) {
    if (typeof target === 'string') fail(`${subpath} still points at source (${target})`);
    if ('require' in target) fail(`${subpath} still has a require condition`);
    for (const file of [target.types, target.default]) {
      if (!file) fail(`${subpath} has no types or default target`);
      if (!/\.(d\.ts|js)$/.test(file)) fail(`${subpath}: ${file} is not an ESM build file`);
      if (!existsSync(join(installed, file))) fail(`${subpath}: ${file} is not in the tarball`);
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
  run(process.execPath, ['esm.mjs'], work);

  // one set of errors: what `/wire` and `/records` throw is the root's ParseError
  const name = JSON.stringify(manifest.name);
  writeFileSync(
    join(work, 'errors.mjs'),
    `import { DnsError, ParseError } from ${name};
import { decodeMessage } from ${JSON.stringify(`${manifest.name}/wire`)};
import { decodeRrsig } from ${JSON.stringify(`${manifest.name}/records`)};

const thrown = attempt => {
  try {
    attempt();
  } catch (error) {
    return error;
  }
  throw new Error('nothing was thrown');
};
for (const [entry, error] of [
  ['/wire', thrown(() => decodeMessage(new Uint8Array(3)))],
  ['/records', thrown(() => decodeRrsig(new Uint8Array(3)))],
]) {
  if (!(error instanceof ParseError) || !(error instanceof DnsError)) {
    throw new Error(\`\${entry} threw \${error?.name}, not the root's ParseError\`);
  }
}
`
  );
  run(process.execPath, ['errors.mjs'], work);

  console.log(
    `✓ dns pack check: ${specifiers.length} entry points import as ESM from the tarball, ` +
      'and share one set of error classes.'
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}
