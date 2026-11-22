import path from 'node:path';
import ts from 'typescript';
import { entries } from '../tsup.config';
import { DOCS, examples, readDoc, root, run } from './support/docs';

// the README and the reference pages under docs/ (the list is in ./support/docs.ts). Every
// ```ts block typechecks against the package as a user would import it, so an example
// cannot drift from the API it shows, and each must stand alone with its own imports. The
// blocks that need no network also run, and a statement written `expression; // literal`
// must give that literal. Blocks fenced ```ts network run in the live suite instead

const all = examples();

// a block that writes out one of the package's interfaces, such as the README's option
// types, must name exactly the keys the real one has, so it cannot fall behind the code
function sameKeys(code: string): string {
  return [...code.matchAll(/^interface (\w+)/gm)]
    .map(
      ([, name]) =>
        [
          `import type { ${name} as __Real${name} } from '@aoxborrow/dns';`,
          `const __keys${name}: [never, never] = null as unknown as [`,
          `  Exclude<keyof ${name}, keyof __Real${name}>,`,
          `  Exclude<keyof __Real${name}, keyof ${name}>,`,
          `];`,
        ].join('\n') + '\n'
    )
    .join('');
}

function diagnostics(): string[] {
  const config = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const compilerOptions = { ...options, noEmit: true, incremental: false };
  // beside the tests, so the package's own name resolves to its source through `exports`;
  // a module even with no import, so top-level await is allowed
  const virtual = new Map(
    all.map((example, index) => [
      path.join(root, 'test', `doc-example-${index + 1}.ts`),
      { example, code: `${example.code}${sameKeys(example.code)}export {};\n` },
    ])
  );

  const host = ts.createCompilerHost(compilerOptions);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (file, language, ...rest) => {
    const code = virtual.get(path.resolve(file))?.code;
    return code === undefined
      ? getSourceFile(file, language, ...rest)
      : ts.createSourceFile(file, code, language);
  };
  const fileExists = host.fileExists.bind(host);
  host.fileExists = file => virtual.has(path.resolve(file)) || fileExists(file);
  const readFile = host.readFile.bind(host);
  host.readFile = file => virtual.get(path.resolve(file))?.code ?? readFile(file);

  const program = ts.createProgram([...virtual.keys()], compilerOptions, host);
  return ts
    .getPreEmitDiagnostics(program)
    .filter(diagnostic => diagnostic.file && virtual.has(path.resolve(diagnostic.file.fileName)))
    .map(diagnostic => {
      const file = diagnostic.file as ts.SourceFile;
      const { example } = virtual.get(path.resolve(file.fileName)) as { example: { at: string } };
      const [doc, start] = example.at.split(':') as [string, string];
      const { line } = file.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
      const text = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
      return `${doc}:${Number(start) + line}: ${text}`;
    });
}

describe('the docs', () => {
  it('has every page, with TypeScript examples', () => {
    for (const doc of DOCS) expect(readDoc(doc).length, doc).toBeGreaterThan(500);
    expect(all.length).toBeGreaterThan(15);
    expect(all.filter(example => !example.network).length).toBeGreaterThan(5);
  });

  it('typechecks every TypeScript example', () => {
    expect(diagnostics()).toEqual([]);
  }, 60_000);

  it('runs every example that needs no network, and each gives the values it shows', async () => {
    expect(
      await run(
        all.filter(example => !example.network),
        true
      )
    ).toEqual([]);
  }, 60_000);

  // nothing is public without a word about what it is. Types are left out: the examples
  // and the option tables are where those are shown
  it('names every value the entries export', async () => {
    const text = DOCS.map(readDoc).join('\n');
    const unnamed: string[] = [];
    for (const entry of entries) {
      const exported = (await import(path.join(root, entry))) as Record<string, unknown>;
      for (const name of Object.keys(exported)) {
        // as a word of its own: `ENODATA` does not name `NODATA`
        const named = new RegExp(`(?<![A-Za-z0-9_$])${name}(?![A-Za-z0-9_$])`).test(text);
        if (!named) unnamed.push(`${entry}: ${name}`);
      }
    }
    expect(unnamed).toEqual([]);
  });
});
