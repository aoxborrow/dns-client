import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

// every ```ts block in the README typechecks against the package as a user would import
// it (`@aoxborrow/dns`, `@aoxborrow/dns/records` and so on), so an example cannot drift
// from the API it shows. Each block is a module of its own and must stand alone: its own
// imports, its own values. Nothing is run

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readme = readFileSync(path.join(root, 'README.md'), 'utf8');

interface Example {
  // the README line the block's code starts on
  line: number;
  file: string;
  code: string;
}

const examples: Example[] = [...readme.matchAll(/^```ts\n([\s\S]*?)^```$/gm)].map(
  (match, index) => ({
    line: readme.slice(0, match.index).split('\n').length + 1,
    // beside the tests, so the package's own name resolves to its source through `exports`
    file: path.join(root, 'test', `readme-example-${index + 1}.ts`),
    // a module even with no import, so top-level await is allowed
    code: `${match[1]}export {};\n`,
  })
);

function diagnostics(): string[] {
  const config = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const compilerOptions = { ...options, noEmit: true, incremental: false };
  const virtual = new Map(examples.map(example => [example.file, example.code]));

  const host = ts.createCompilerHost(compilerOptions);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (file, language, ...rest) => {
    const code = virtual.get(path.resolve(file));
    return code === undefined
      ? getSourceFile(file, language, ...rest)
      : ts.createSourceFile(file, code, language);
  };
  const fileExists = host.fileExists.bind(host);
  host.fileExists = file => virtual.has(path.resolve(file)) || fileExists(file);
  const readFile = host.readFile.bind(host);
  host.readFile = file => virtual.get(path.resolve(file)) ?? readFile(file);

  const program = ts.createProgram([...virtual.keys()], compilerOptions, host);
  return ts
    .getPreEmitDiagnostics(program)
    .filter(diagnostic => diagnostic.file && virtual.has(path.resolve(diagnostic.file.fileName)))
    .map(diagnostic => {
      const file = diagnostic.file as ts.SourceFile;
      const example = examples.find(each => each.file === path.resolve(file.fileName));
      const { line } = file.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
      const text = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
      return `README.md:${(example?.line ?? 0) + line}: ${text}`;
    });
}

describe('README', () => {
  it('has TypeScript examples', () => {
    expect(examples.length).toBeGreaterThan(10);
  });

  it('typechecks every TypeScript example', () => {
    expect(diagnostics()).toEqual([]);
  }, 60_000);
});
