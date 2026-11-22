import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { entries } from '../../tsup.config';

// the README and the reference pages it links to, read as one set of documents: their
// TypeScript examples, and what each one says. The list is written out, not globbed, so a
// page that is renamed or emptied fails the tests instead of dropping out of them
export const DOCS = [
  'README.md',
  'docs/resolvers.md',
  'docs/records.md',
  'docs/wire-and-transports.md',
  'docs/dnssec.md',
  'docs/promises.md',
];

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

// each public specifier and the source file it is built from: `.` from src/index.ts,
// `./records` from src/records/index.ts, `./transports/doh` from src/transports/doh.ts. The
// examples import the package by name, and resolve to its source through this map rather
// than through `exports`, which points at dist/ once the package is published
const NAME = (JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { name: string })
  .name;
export const sources: Record<string, string> = Object.fromEntries(
  entries.map(entry => {
    const subpath = entry.replace(/^src\//, '').replace(/(\/index)?\.ts$/, '');
    return [subpath === 'index' ? NAME : `${NAME}/${subpath}`, path.join(root, entry)];
  })
);

// the example with each import of the package by name pointed at its source file
function toSource(code: string): string {
  return code.replace(
    /(from\s+|import\s*\(\s*)(['"])([^'"]+)\2/g,
    (whole, lead, quote, specifier) =>
      specifier in sources ? `${lead}${quote}${sources[specifier]}${quote}` : whole
  );
}

export interface Example {
  // where the block's code starts, as `file:line`
  at: string;
  // a block fenced ```ts network asks real servers, so only the live suite runs it
  network: boolean;
  code: string;
}

export function readDoc(doc: string): string {
  return readFileSync(path.join(root, doc), 'utf8');
}

export function examples(): Example[] {
  return DOCS.flatMap(doc => {
    const text = readDoc(doc);
    return [...text.matchAll(/^```ts( network)?\n([\s\S]*?)^```$/gm)].map(match => ({
      at: `${doc}:${text.slice(0, match.index).split('\n').length + 1}`,
      network: Boolean(match[1]),
      code: match[2] as string,
    }));
  });
}

// a comment's leading value, when it is written as a literal and nothing else: `// 65`,
// `// 'TYPE65280': a type with no name…`, `// [{ name: 'example.com', … }]` is not one,
// for the `…`. What follows a literal is prose when it starts with `, ` or `: `
function literalIn(comment: string): { value: unknown } | undefined {
  const text = comment.replace(/^\/\/\s?/, '').trim();
  const cuts = [text.length];
  for (const match of text.matchAll(/[,:] /g)) cuts.push(match.index);
  for (const cut of cuts.sort((a, b) => b - a)) {
    const candidate = text.slice(0, cut).trim();
    if (candidate === '' || !isLiteral(candidate)) continue;
    return { value: new Function(`return (${candidate});`)() };
  }
  return undefined;
}

function isLiteral(text: string): boolean {
  const file = ts.createSourceFile('x.ts', `(${text});`, ts.ScriptTarget.Latest, true);
  const { parseDiagnostics } = file as unknown as { parseDiagnostics: ts.Diagnostic[] };
  if (parseDiagnostics.length > 0 || file.statements.length !== 1) return false;
  const statement = file.statements[0];
  if (!statement || !ts.isExpressionStatement(statement)) return false;
  const literal = (node: ts.Node): boolean => {
    if (ts.isParenthesizedExpression(node)) return literal(node.expression);
    if (
      ts.isStringLiteral(node) ||
      ts.isNumericLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      node.kind === ts.SyntaxKind.TrueKeyword ||
      node.kind === ts.SyntaxKind.FalseKeyword ||
      node.kind === ts.SyntaxKind.NullKeyword
    ) {
      return true;
    }
    if (ts.isIdentifier(node)) return node.text === 'undefined';
    if (ts.isPrefixUnaryExpression(node)) {
      return node.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(node.operand);
    }
    if (ts.isArrayLiteralExpression(node)) return node.elements.every(literal);
    if (ts.isObjectLiteralExpression(node)) {
      return node.properties.every(
        property =>
          ts.isPropertyAssignment(property) &&
          (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) &&
          literal(property.initializer)
      );
    }
    return false;
  };
  return literal(statement.expression);
}

// the comment that shows a statement's value: on the statement's own line, or else the
// lines of comment straight below it, read as one
function commentAfter(code: string, end: number): string {
  const trailing = ts.getTrailingCommentRanges(code, end)?.[0];
  if (trailing) return code.slice(trailing.pos, trailing.end);
  const below = /^[^\n]*\n((?:[ \t]*\/\/[^\n]*(?:\n|$))+)/.exec(code.slice(end));
  if (!below?.[1]) return '';
  return below[1]
    .split('\n')
    .map(line => line.trim().replace(/^\/\/\s?/, ''))
    .join(' ')
    .trim();
}

// the example as a module that checks itself: each `expression; // literal` statement
// (or a statement with the literal in the comment lines below it) becomes a call that compares the expression with the literal. Statements whose comment
// is not a literal, or is a sentence, are left as they are
export function checked(example: Example): string {
  const file = ts.createSourceFile('x.ts', example.code, ts.ScriptTarget.Latest, true);
  const edits: { start: number; end: number; text: string }[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isExpressionStatement(node)) {
      const found = literalIn(commentAfter(example.code, node.end));
      if (found) {
        const line = file.getLineAndCharacterOfPosition(node.getStart()).line;
        edits.push({
          start: node.getStart(),
          end: node.end,
          text: `__check(${node.expression.getText()}, ${JSON.stringify(found.value)}, ${line});`,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  let code = example.code;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    code = code.slice(0, edit.start) + edit.text + code.slice(edit.end);
  }
  return `const __check = (globalThis as any).__docCheck;\n${code}\nexport {};\n`;
}

// runs examples as modules beside the tests, with the package's own name pointed at its
// source, and returns what each check found wrong
type Check = (actual: unknown, expected: unknown, line: number) => void;

// what an example module finds on the global object while it runs
export interface Checked {
  __docCheck?: Check;
}

export async function run(list: Example[], check: boolean): Promise<string[]> {
  const dir = path.join(root, 'test', '.examples');
  mkdirSync(dir, { recursive: true });
  const wrong: string[] = [];
  try {
    for (const [index, example] of list.entries()) {
      const [doc, start] = example.at.split(':') as [string, string];
      const global = globalThis as unknown as Checked;
      global.__docCheck = (actual, expected, line) => {
        try {
          expect(actual).toEqual(expected);
        } catch {
          wrong.push(
            `${doc}:${Number(start) + line}: ${JSON.stringify(actual)}, not ${JSON.stringify(expected)}`
          );
        }
      };
      const file = path.join(dir, `example-${index + 1}.ts`);
      writeFileSync(file, toSource(check ? checked(example) : `${example.code}\nexport {};\n`));
      try {
        await import(file);
      } catch (error) {
        wrong.push(`${example.at}: threw ${String(error)}`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
    delete (globalThis as unknown as Checked).__docCheck;
  }
  return wrong;
}
