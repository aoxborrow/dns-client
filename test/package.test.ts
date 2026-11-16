import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { entries } from '../tsup.config';

// the package's shape is declared in three places that have to agree: the `exports` map
// the monorepo resolves (source), `publishConfig.exports` that npm consumers resolve
// (dist), and the build entries. A new entry point added to only one of them would work
// here and break on publish, or the reverse.

interface Target {
  types: string;
  default: string;
}

interface Manifest {
  type: string;
  engines: { node: string };
  exports: Record<string, string>;
  dependencies?: Record<string, string>;
  publishConfig: {
    main?: string;
    exports: Record<string, Target>;
  };
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as Manifest;

// the build keeps the source layout: './src/records/index.ts' -> 'records/index',
// './src/transports/udp.ts' -> 'transports/udp'
const distBase = (subpath: string) =>
  manifest.exports[subpath].replace(/^\.\/src\//, '').replace(/\.ts$/, '');

describe('package manifest', () => {
  it('has no runtime dependencies', () => {
    expect(Object.keys(manifest.dependencies ?? {})).toEqual([]);
  });

  it('points every source export at a file that exists', () => {
    for (const target of Object.values(manifest.exports)) {
      expect(existsSync(path.join(root, target)), target).toBe(true);
    }
  });

  it('publishes the same entry points it exposes in the monorepo', () => {
    expect(Object.keys(manifest.publishConfig.exports).sort()).toEqual(
      Object.keys(manifest.exports).sort()
    );
  });

  it('builds exactly the exported entry points', () => {
    const exported = Object.values(manifest.exports).map(target => target.replace(/^\.\//, ''));
    expect([...entries].sort()).toEqual(exported.sort());
  });

  it('maps each published entry to the ESM build output for that entry', () => {
    for (const [subpath, target] of Object.entries(manifest.publishConfig.exports)) {
      const base = `./dist/${distBase(subpath)}`;
      expect(target).toEqual({ types: `${base}.d.ts`, default: `${base}.js` });
    }
  });

  it('is ESM only, for Node 22 and up', () => {
    expect(manifest.type).toBe('module');
    expect(manifest.engines.node).toBe('>=22');
    expect(manifest.publishConfig.main).toBeUndefined();
    const published = JSON.stringify(manifest.publishConfig);
    expect(published).not.toContain('require');
    expect(published).not.toContain('.cjs');
    expect(published).not.toContain('.d.cts');
  });
});
