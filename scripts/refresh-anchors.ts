// compare the bundled root trust anchors and root hints with what IANA publishes, and
// rewrite them when they differ.
//
//   yarn refresh-anchors          rewrite the bundled data
//   yarn refresh-anchors --check  report, and fail on a difference
//
// the anchors come from https://data.iana.org/root-anchors/root-anchors.xml and the hints
// from https://www.internic.net/domain/named.root, fetched over TLS only. Before committing
// a rewrite, check the anchor file's signature as CONTRIBUTING.md says
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT_TRUST_ANCHORS, ROOT_TRUST_ANCHORS_INFO } from '../src/dnssec/anchors';
import { ROOT_HINTS, ROOT_HINTS_INFO } from '../src/resolvers/root-hints';
import {
  anchorChanges,
  anchorsLiteral,
  hintChanges,
  hintsLiteral,
  parseRootAnchors,
  parseRootHints,
} from './iana-data';

const here = dirname(fileURLToPath(import.meta.url));
const ANCHORS_FILE = resolve(here, '..', 'src', 'dnssec', 'anchors.ts');
const HINTS_FILE = resolve(here, '..', 'src', 'resolvers', 'root-hints.ts');
const check = process.argv.includes('--check');
const today = new Date().toISOString().slice(0, 10);

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.text();
}

function replace(file: string, pattern: RegExp, text: string): void {
  const source = readFileSync(file, 'utf8');
  if (!pattern.test(source)) throw new Error(`${file}: nothing matches ${pattern}`);
  writeFileSync(file, source.replace(pattern, text));
}

// one field of a dataset's info object
const setInfo = (file: string, name: string, field: 'version' | 'refreshed', value: string) =>
  replace(
    file,
    new RegExp(`(export const ${name}: DatasetInfo = \\{[^}]*?\\b${field}: )'[^']*'`),
    `$1'${value}'`
  );

async function main() {
  const [xml, named] = await Promise.all([
    fetchText(ROOT_TRUST_ANCHORS_INFO.source),
    fetchText(ROOT_HINTS_INFO.source),
  ]);
  const published = parseRootAnchors(xml);
  const { hints, version } = parseRootHints(named);
  if (hints.length < 13 || hints.some(hint => !hint.ipv4 || !hint.ipv6)) {
    throw new Error(`named.root did not read as thirteen root servers with addresses`);
  }

  const anchors = anchorChanges(ROOT_TRUST_ANCHORS, published, today);
  const roots = hintChanges(ROOT_HINTS, hints);
  for (const line of [...anchors, ...roots]) console.log(line);
  if (anchors.length + roots.length === 0) {
    console.log('The bundled root trust anchors and root hints match what IANA publishes.');
  }

  if (check) {
    if (anchors.length + roots.length > 0) {
      console.log('\nRun `yarn refresh-anchors` and follow');
      console.log('the trust anchor procedure in CONTRIBUTING.md to update the bundled data.');
      process.exitCode = 1;
    }
    return;
  }

  setInfo(ANCHORS_FILE, 'ROOT_TRUST_ANCHORS_INFO', 'refreshed', today);
  if (anchors.length) {
    // what IANA publishes, less what retired before today
    const keep = published.filter(anchor => !anchor.validUntil || anchor.validUntil >= today);
    replace(
      ANCHORS_FILE,
      /export const ROOT_TRUST_ANCHORS: TrustAnchor\[\] = \[[\s\S]*?\n\];/,
      anchorsLiteral(keep, ROOT_TRUST_ANCHORS, today)
    );
    setInfo(ANCHORS_FILE, 'ROOT_TRUST_ANCHORS_INFO', 'version', today);
  }
  setInfo(HINTS_FILE, 'ROOT_HINTS_INFO', 'refreshed', today);
  if (roots.length) {
    replace(
      HINTS_FILE,
      /export const ROOT_HINTS: readonly NameserverHint\[\] = \[[\s\S]*?\n\];/,
      hintsLiteral(hints)
    );
  }
  if (version) {
    setInfo(HINTS_FILE, 'ROOT_HINTS_INFO', 'version', version);
  }
  console.log(`\nRewrote ${ANCHORS_FILE} and ${HINTS_FILE}. Check the diff before committing.`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
