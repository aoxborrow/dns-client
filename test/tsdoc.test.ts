import path from 'node:path';
import ts from 'typescript';
import { entries } from '../tsup.config';

// the package's own comment rule: a declaration the entry points export, and the public
// members of one, is documented with a /** */ comment so editors and the built .d.ts show
// it. Everything else in src keeps // comments, as the rest of the repository does

const root = path.resolve(__dirname, '..');
const src = path.join(root, 'src') + path.sep;

// what each entry exports at run time: a function or constant only a type export reaches
// (`export type *`) is not public
const runtime = await Promise.all(
  entries.map(async entry => new Set(Object.keys(await import(path.join(root, entry)))))
);

function publicNodes(): { program: ts.Program; nodes: Set<ts.Node> } {
  const config = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const program = ts.createProgram(
    entries.map(entry => path.join(root, entry)),
    { ...options, noEmit: true, incremental: false }
  );
  const checker = program.getTypeChecker();
  const nodes = new Set<ts.Node>();
  for (const [index, entry] of entries.entries()) {
    const module = checker.getSymbolAtLocation(program.getSourceFile(path.join(root, entry))!)!;
    for (const exported of checker.getExportsOfModule(module)) {
      const symbol =
        exported.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(exported) : exported;
      for (const declaration of symbol.declarations ?? []) {
        const value =
          ts.isFunctionDeclaration(declaration) || ts.isVariableDeclaration(declaration);
        if (value && !runtime[index]!.has(exported.name)) continue;
        nodes.add(ts.isVariableDeclaration(declaration) ? declaration.parent.parent : declaration);
        const members =
          ts.isInterfaceDeclaration(declaration) || ts.isClassDeclaration(declaration)
            ? declaration.members
            : ts.isTypeAliasDeclaration(declaration) && ts.isTypeLiteralNode(declaration.type)
              ? declaration.type.members
              : [];
        for (const member of members) {
          const modifiers = ts.canHaveModifiers(member) ? (ts.getModifiers(member) ?? []) : [];
          const hidden = modifiers.some(
            modifier =>
              modifier.kind === ts.SyntaxKind.PrivateKeyword ||
              modifier.kind === ts.SyntaxKind.ProtectedKeyword
          );
          if (!hidden && !(member.name && ts.isPrivateIdentifier(member.name))) nodes.add(member);
        }
      }
    }
  }
  return { program, nodes };
}

const { program, nodes } = publicNodes();
const files = program.getSourceFiles().filter(file => file.fileName.startsWith(src));

// every comment in a file, found through the parsed tree: the trivia on either side of each
// token. A scanner run over the text alone cannot tell a template literal's `}` from a
// block's, so it loses its place after `${}` and stops seeing comments. JSDoc nodes are
// comments themselves, so the walk does not go into them
function commentsOf(file: ts.SourceFile): ts.CommentRange[] {
  const found = new Map<number, ts.CommentRange>();
  const visit = (node: ts.Node): void => {
    if (node.kind >= ts.SyntaxKind.FirstJSDocNode && node.kind <= ts.SyntaxKind.LastJSDocNode) {
      return;
    }
    const children = node.getChildren(file);
    if (children.length > 0) {
      children.forEach(visit);
      return;
    }
    for (const range of [
      ...(ts.getLeadingCommentRanges(file.text, node.pos) ?? []),
      ...(ts.getTrailingCommentRanges(file.text, node.pos) ?? []),
    ]) {
      found.set(range.pos, range);
    }
  };
  visit(file);
  return [...found.values()];
}

function where(file: ts.SourceFile, position: number): string {
  const { line } = file.getLineAndCharacterOfPosition(position);
  return `${path.relative(root, file.fileName)}:${line + 1}`;
}

describe('doc comments', () => {
  it('uses /** */ only on public declarations', () => {
    const attached = new Set<string>();
    for (const node of nodes) {
      const file = node.getSourceFile();
      for (const range of ts.getLeadingCommentRanges(file.text, node.getFullStart()) ?? []) {
        attached.add(where(file, range.pos));
      }
    }
    const stray: string[] = [];
    for (const file of files) {
      for (const range of commentsOf(file)) {
        if (range.kind !== ts.SyntaxKind.MultiLineCommentTrivia) continue;
        const text = file.text.slice(range.pos, range.end);
        if (text.startsWith('/**') && text !== '/**/' && !attached.has(where(file, range.pos))) {
          stray.push(where(file, range.pos));
        }
      }
    }
    expect(stray).toEqual([]);
  });

  it('gives public declarations /** */ comments, not //', () => {
    const lineComments: string[] = [];
    for (const node of nodes) {
      const file = node.getSourceFile();
      if (!file.fileName.startsWith(src)) continue;
      const last = (ts.getLeadingCommentRanges(file.text, node.getFullStart()) ?? []).at(-1);
      if (last?.kind !== ts.SyntaxKind.SingleLineCommentTrivia) continue;
      // a // comment directly above the declaration, with no blank line between
      if (!file.text.slice(last.end, node.getStart()).includes('\n\n')) {
        lineComments.push(where(file, node.getStart()));
      }
    }
    expect(lineComments).toEqual([]);
  });
});
