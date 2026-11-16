// compare the bundled root trust anchors and root hints with what IANA publishes, and
// rewrite them when they differ.
//
//   yarn workspace @aoxborrow/dns refresh-anchors          rewrite the bundled data
//   yarn workspace @aoxborrow/dns refresh-anchors --check  report, and fail on a difference
//
// the anchors come from https://data.iana.org/root-anchors/root-anchors.xml and the hints
// from https://www.internic.net/domain/named.root, fetched over TLS only. Before committing
// a rewrite, check the anchor file's signature as docs/reference/dnssec-trust-anchors.md says
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT_TRUST_ANCHOR_SOURCE, ROOT_TRUST_ANCHORS } from '../src/dnssec/anchors';
import { ROOT_HINTS, ROOT_HINTS_SOURCE } from '../src/resolvers/root-hints';
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

const constant = (name: string) => new RegExp(`export const ${name} = '[^']*';`);

async function main() {
  const [xml, named] = await Promise.all([
    fetchText(ROOT_TRUST_ANCHOR_SOURCE),
    fetchText(ROOT_HINTS_SOURCE),
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
      console.log('\nRun `yarn workspace @aoxborrow/dns refresh-anchors` and follow');
      console.log('docs/reference/dnssec-trust-anchors.md to update the bundled data.');
      process.exitCode = 1;
    }
    return;
  }

  replace(
    ANCHORS_FILE,
    constant('ROOT_TRUST_ANCHORS_REFRESHED'),
    `export const ROOT_TRUST_ANCHORS_REFRESHED = '${today}';`
  );
  if (anchors.length) {
    // what IANA publishes, less what retired before today
    const keep = published.filter(anchor => !anchor.validUntil || anchor.validUntil >= today);
    replace(
      ANCHORS_FILE,
      /export const ROOT_TRUST_ANCHORS: TrustAnchor\[\] = \[[\s\S]*?\n\];/,
      anchorsLiteral(keep, ROOT_TRUST_ANCHORS, today)
    );
    replace(
      ANCHORS_FILE,
      constant('ROOT_TRUST_ANCHORS_DATA_VERSION'),
      `export const ROOT_TRUST_ANCHORS_DATA_VERSION = '${today}';`
    );
  }
  replace(
    HINTS_FILE,
    constant('ROOT_HINTS_REFRESHED'),
    `export const ROOT_HINTS_REFRESHED = '${today}';`
  );
  if (roots.length) {
    replace(
      HINTS_FILE,
      /export const ROOT_HINTS: readonly NameserverHint\[\] = \[[\s\S]*?\n\];/,
      hintsLiteral(hints)
    );
  }
  if (version) {
    replace(
      HINTS_FILE,
      constant('ROOT_HINTS_DATA_VERSION'),
      `export const ROOT_HINTS_DATA_VERSION = '${version}';`
    );
  }
  console.log(`\nRewrote ${ANCHORS_FILE} and ${HINTS_FILE}. Check the diff before committing.`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
