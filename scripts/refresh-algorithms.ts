// compare the bundled DNSSEC algorithm and DS digest tables (src/dnssec/constants.ts) with
// IANA's registries, and rewrite them when they differ.
//
//   yarn refresh-algorithms          rewrite the bundled tables
//   yarn refresh-algorithms --check  report, and fail on a difference
//
// the registries come from https://www.iana.org/assignments/dns-sec-alg-numbers and
// https://www.iana.org/assignments/ds-rr-types, fetched over TLS. A rewrite takes each row's
// name and standing from IANA (how the columns map to a standing is registryStanding in
// iana-data.ts) and keeps what the library knows: whether it verifies the algorithm, and a
// digest's strength. Check the diff before committing, as CONTRIBUTING.md says
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import prettier from 'prettier';
import {
  DNSSEC_ALGORITHMS,
  DNSSEC_ALGORITHMS_INFO,
  DS_DIGEST_TYPES,
  DS_DIGEST_TYPES_INFO,
} from '../src/dnssec/constants';
import type { DatasetInfo } from '../src/dataset';
import {
  parseAlgorithmRegistry,
  parseDigestRegistry,
  registryChanges,
  registryLiteral,
  registryUpdated,
} from './iana-data';

export const ALGORITHM_REGISTRY_SOURCE =
  'https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml';
export const DIGEST_REGISTRY_SOURCE =
  'https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xml';

const here = dirname(fileURLToPath(import.meta.url));
const CONSTANTS_FILE = resolve(here, '..', 'src', 'dnssec', 'constants.ts');
const check = process.argv.includes('--check');
const today = new Date().toISOString().slice(0, 10);

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.text();
}

function replace(source: string, pattern: RegExp, text: string): string {
  if (!pattern.test(source)) throw new Error(`${CONSTANTS_FILE}: nothing matches ${pattern}`);
  return source.replace(pattern, () => text);
}

// a table's info object, checked today against the registry revision `xml` is
function infoLiteral(name: string, info: DatasetInfo, xml: string): string {
  const version = registryUpdated(xml);
  if (!version) throw new Error(`${info.source}: the registry names no <updated> date`);
  return [
    `export const ${name}: DatasetInfo = {`,
    `  source: '${info.source}',`,
    `  version: '${version}',`,
    `  refreshed: '${today}',`,
    '};',
  ].join('\n');
}

const infoPattern = (name: string) =>
  new RegExp(`export const ${name}: DatasetInfo = \\{[\\s\\S]*?\\n\\};`);

async function main() {
  const [algorithmXml, digestXml] = await Promise.all([
    fetchText(ALGORITHM_REGISTRY_SOURCE),
    fetchText(DIGEST_REGISTRY_SOURCE),
  ]);
  const algorithms = parseAlgorithmRegistry(algorithmXml);
  const digests = parseDigestRegistry(digestXml);
  // the rows every validator has to know: a registry that reads without them is a parse
  // that went wrong, not a change
  if (![8, 13].every(number => algorithms.some(entry => entry.number === number))) {
    throw new Error(
      'the algorithm registry did not read as one with RSASHA256 and ECDSAP256SHA256'
    );
  }
  if (!digests.some(entry => entry.number === 2)) {
    throw new Error('the digest registry did not read as one with SHA-256');
  }

  const changes = [
    ...registryChanges('algorithm', DNSSEC_ALGORITHMS, algorithms),
    ...registryChanges('digest type', DS_DIGEST_TYPES, digests),
  ];
  for (const line of changes) console.log(line);
  if (changes.length === 0) {
    console.log('The bundled DNSSEC algorithm and digest tables match what IANA publishes.');
  }

  if (check) {
    if (changes.length > 0) {
      console.log('\nRun `yarn refresh-algorithms` and follow');
      console.log(
        'the algorithm registry procedure in CONTRIBUTING.md to update the bundled tables.'
      );
      process.exitCode = 1;
    }
    return;
  }

  let source = readFileSync(CONSTANTS_FILE, 'utf8');
  source = replace(
    source,
    infoPattern('DNSSEC_ALGORITHMS_INFO'),
    infoLiteral('DNSSEC_ALGORITHMS_INFO', DNSSEC_ALGORITHMS_INFO, algorithmXml)
  );
  source = replace(
    source,
    infoPattern('DS_DIGEST_TYPES_INFO'),
    infoLiteral('DS_DIGEST_TYPES_INFO', DS_DIGEST_TYPES_INFO, digestXml)
  );
  if (changes.length) {
    source = replace(
      source,
      /export const DNSSEC_ALGORITHMS = \{[\s\S]*?\n\} as const;/,
      registryLiteral('DNSSEC_ALGORITHMS', DNSSEC_ALGORITHMS, algorithms)
    );
    source = replace(
      source,
      /export const DS_DIGEST_TYPES = \{[\s\S]*?\n\} as const;/,
      registryLiteral('DS_DIGEST_TYPES', DS_DIGEST_TYPES, digests)
    );
  }
  const options = await prettier.resolveConfig(CONSTANTS_FILE);
  writeFileSync(
    CONSTANTS_FILE,
    await prettier.format(source, { ...options, filepath: CONSTANTS_FILE })
  );
  console.log(`\nRewrote ${CONSTANTS_FILE}. Check the diff before committing.`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
