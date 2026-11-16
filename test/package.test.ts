import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { entries } from '../tsup.config';

// the package's shape is declared in more than one place, and they have to agree: the build
// entries, the `exports` map npm consumers resolve (dist), and, while the library lives in
// a monorepo as a workspace, a second `exports` map at the TypeScript source for the
// workspaces that import it. There the dist map sits in `publishConfig.exports`;
// in the standalone repo it is `exports` itself and `publishConfig` holds only `access`. A
// new entry point added to only one of them would work in one place and break in another.

interface Target {
  types: string;
  default: string;
}

interface Manifest {
  type: string;
  private?: boolean;
  engines: { node: string };
  exports: Record<string, string | Target>;
  dependencies?: Record<string, string>;
  main?: string;
  publishConfig: {
    access: string;
    main?: string;
    exports?: Record<string, Target>;
  };
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as Manifest;

// in the monorepo `exports` points at source and `publishConfig.exports` at the build
const inMonorepo = manifest.publishConfig.exports !== undefined;
const published = (manifest.publishConfig.exports ?? manifest.exports) as Record<string, Target>;

// a build entry and the subpath it is published at: 'src/index.ts' -> '.',
// 'src/records/index.ts' -> './records', 'src/transports/udp.ts' -> './transports/udp'
const subpathOf = (entry: string) => {
  const base = entry
    .replace(/^src\//, '')
    .replace(/\.ts$/, '')
    .replace(/(^|\/)index$/, '');
  return base === '' ? '.' : `./${base}`;
};
// the build keeps the source layout: 'src/records/index.ts' -> './dist/records/index'
const distOf = (entry: string) => `./dist/${entry.replace(/^src\//, '').replace(/\.ts$/, '')}`;

describe('package manifest', () => {
  it('has no runtime dependencies', () => {
    expect(Object.keys(manifest.dependencies ?? {})).toEqual([]);
  });

  it('builds entries that exist', () => {
    for (const entry of entries) {
      expect(existsSync(path.join(root, entry)), entry).toBe(true);
    }
  });

  it('publishes exactly the built entry points, each at its ESM build output', () => {
    const expected = Object.fromEntries(
      entries.map(entry => [
        subpathOf(entry),
        { types: `${distOf(entry)}.d.ts`, default: `${distOf(entry)}.js` },
      ])
    );
    expect(published).toEqual(expected);
  });

  it.runIf(inMonorepo)('exposes the same entry points at source inside the monorepo', () => {
    const expected = Object.fromEntries(entries.map(entry => [subpathOf(entry), `./${entry}`]));
    expect(manifest.exports).toEqual(expected);
  });

  it.runIf(!inMonorepo)('is publishable on its own, with only access in publishConfig', () => {
    expect(manifest.private).toBeUndefined();
    expect(manifest.publishConfig).toEqual({ access: 'public' });
  });

  it('is ESM only, for Node 22 and up', () => {
    expect(manifest.type).toBe('module');
    expect(manifest.engines.node).toBe('>=22');
    expect(manifest.main).toBeUndefined();
    expect(manifest.publishConfig.main).toBeUndefined();
    const shape = JSON.stringify(published);
    expect(shape).not.toContain('require');
    expect(shape).not.toContain('.cjs');
    expect(shape).not.toContain('.d.cts');
  });
});
