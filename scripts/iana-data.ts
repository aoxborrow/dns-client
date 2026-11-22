// reading IANA's root trust anchor file, the root hints file and the DNSSEC algorithm and
// DS digest registries, and telling where the bundled copies differ. Used by
// refresh-anchors.ts and refresh-algorithms.ts, and tested offline against saved copies
import type { TrustAnchor } from '../src/dnssec/types';
import type { NameserverHint } from '../src/resolvers/root-hints';

// an anchor as the comparison reads it: days as YYYY-MM-DD, the digest in lowercase hex
export interface PublishedAnchor {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
  validFrom?: string;
  validUntil?: string;
}

function tag(block: string, name: string): string | undefined {
  return new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`).exec(block)?.[1];
}

function attribute(block: string, name: string): string | undefined {
  return new RegExp(`${name}="([^"]*)"`).exec(block)?.[1];
}

function day(value: string | undefined): string | undefined {
  return value ? new Date(value).toISOString().slice(0, 10) : undefined;
}

// the KeyDigest entries of root-anchors.xml (RFC 9718 §2)
export function parseRootAnchors(xml: string): PublishedAnchor[] {
  const zone = tag(xml, 'Zone');
  if (zone !== '.') throw new Error(`root-anchors.xml is for zone ${zone}, not the root`);
  return [...xml.matchAll(/<KeyDigest\b([^>]*)>([\s\S]*?)<\/KeyDigest>/g)].map(
    ([, attributes, body]) => ({
      keyTag: Number(tag(body, 'KeyTag')),
      algorithm: Number(tag(body, 'Algorithm')),
      digestType: Number(tag(body, 'DigestType')),
      digest: tag(body, 'Digest')!.toLowerCase(),
      validFrom: day(attribute(attributes, 'validFrom')),
      validUntil: day(attribute(attributes, 'validUntil')),
    })
  );
}

export function fromBundle(anchor: TrustAnchor): PublishedAnchor {
  return {
    keyTag: anchor.keyTag,
    algorithm: anchor.algorithm,
    digestType: anchor.digestType,
    digest: anchor.digest.toLowerCase(),
    validFrom: day(anchor.validFrom?.toISOString()),
    validUntil: day(anchor.validUntil?.toISOString()),
  };
}

const anchorKey = (anchor: PublishedAnchor) =>
  [
    `key tag ${anchor.keyTag}`,
    `algorithm ${anchor.algorithm}`,
    `digest type ${anchor.digestType}`,
    anchor.digest,
    `valid from ${anchor.validFrom ?? '-'}`,
    `until ${anchor.validUntil ?? '-'}`,
  ].join(', ');

// where the bundled anchors and IANA's differ, one line each. An anchor whose validity
// ended before `today` is left out on both sides: IANA keeps retired anchors in its file
// (KSK-2010), and the bundle does not. A validUntil IANA adds is a difference whether it is
// in the past or the future, so the bundle cannot go on trusting a retired key
export function anchorChanges(
  bundled: readonly TrustAnchor[],
  published: readonly PublishedAnchor[],
  today: string
): string[] {
  const current = (anchor: PublishedAnchor) => !anchor.validUntil || anchor.validUntil >= today;
  const ours = bundled.map(fromBundle).map(anchor => ({
    anchor,
    // a bundled anchor IANA has retired since is compared, not dropped
    keep: current(anchor) || published.some(theirs => theirs.digest === anchor.digest),
  }));
  return difference(
    'anchor',
    ours.filter(entry => entry.keep).map(entry => anchorKey(entry.anchor)),
    published
      .filter(
        anchor => current(anchor) || ours.some(entry => entry.anchor.digest === anchor.digest)
      )
      .map(anchorKey)
  );
}

// the root servers in named.root, with the version of the root zone it goes with
export function parseRootHints(text: string): { hints: NameserverHint[]; version?: string } {
  const lines = text
    .split('\n')
    .map(line => line.replace(/;.*$/, '').trim())
    .filter(Boolean)
    .map(line => line.split(/\s+/));
  const lower = (name: string) => name.toLowerCase().replace(/\.$/, '');
  const names = lines
    .filter(([owner, , type]) => owner === '.' && type === 'NS')
    .map(([, , , target]) => lower(target));
  const address = (name: string, type: string) =>
    lines.find(([owner, , recordType]) => lower(owner) === name && recordType === type)?.[3];
  const version = /related version of root zone:\s*(\d+)/.exec(text)?.[1];
  return {
    hints: names.map(name => ({ name, ipv4: address(name, 'A'), ipv6: address(name, 'AAAA') })),
    version,
  };
}

const hintKey = (hint: NameserverHint) => `${hint.name} ${hint.ipv4 ?? '-'} ${hint.ipv6 ?? '-'}`;

export function hintChanges(
  bundled: readonly NameserverHint[],
  published: readonly NameserverHint[]
): string[] {
  return difference('root hint', bundled.map(hintKey), published.map(hintKey));
}

function difference(label: string, bundled: string[], published: string[]): string[] {
  const out: string[] = [];
  for (const entry of published) {
    if (!bundled.includes(entry))
      out.push(`${label} IANA publishes and the bundle lacks: ${entry}`);
  }
  for (const entry of bundled) {
    if (!published.includes(entry)) out.push(`${label} the bundle has and IANA does not: ${entry}`);
  }
  return out;
}

// one row of IANA's DNSSEC algorithm registry or its DS digest registry, as the comparison
// reads it: the number, the name the bundle uses for it, and the four columns RFC 9904
// gives each row (for digests, `sign` is the "Use for DNSSEC Delegation" column)
export interface RegistryEntry {
  number: number;
  name: string;
  sign: string;
  validate: string;
  implementSign: string;
  implementValidate: string;
}

export type Standing = 'recommended' | 'supported' | 'deprecated' | 'prohibited' | 'regional';

function rows(xml: string): string[] {
  return [...xml.matchAll(/<record\b[^>]*>([\s\S]*?)<\/record>/g)].map(([, body]) => body!);
}

// the signing algorithms: the rows with one number, a mnemonic and a validation column,
// less 253 and 254, which stand for private algorithms rather than one algorithm each
export function parseAlgorithmRegistry(xml: string): RegistryEntry[] {
  if (!xml.includes('id="dns-sec-alg-numbers"')) {
    throw new Error('the algorithm registry did not read as dns-sec-alg-numbers');
  }
  return rows(xml)
    .filter(row => /^\d+$/.test(tag(row, 'number') ?? '') && tag(row, 'mnemonic'))
    .filter(row => tag(row, 'usevalid'))
    .map(row => ({
      number: Number(tag(row, 'number')),
      name: tag(row, 'mnemonic')!,
      sign: tag(row, 'usesigning')!,
      validate: tag(row, 'usevalid')!,
      implementSign: tag(row, 'impsigning') ?? '',
      implementValidate: tag(row, 'impvalid') ?? '',
    }))
    .filter(entry => entry.number !== 253 && entry.number !== 254);
}

// the DS digest types: the rows with one number and a validation column that are not
// reserved. A name loses IANA's "(DEPRECATED)" note, which the standing carries
export function parseDigestRegistry(xml: string): RegistryEntry[] {
  if (!xml.includes('id="ds-rr-types"')) {
    throw new Error('the digest registry did not read as ds-rr-types');
  }
  return rows(xml)
    .filter(row => /^\d+$/.test(tag(row, 'value') ?? '') && tag(row, 'usevalid'))
    .filter(row => !/^Reserved/.test(tag(row, 'description') ?? ''))
    .map(row => ({
      number: Number(tag(row, 'value')),
      name: tag(row, 'description')!.replace(/\s*\([^)]*\)$/, ''),
      sign: tag(row, 'usedeleg')!,
      validate: tag(row, 'usevalid')!,
      implementSign: tag(row, 'impdeleg') ?? '',
      implementValidate: tag(row, 'impvalid') ?? '',
    }));
}

// a row's standing, read from its columns in this order: one validators MUST NOT use is
// prohibited; one signers (or parents) MUST NOT use is deprecated; one RECOMMENDED for
// signing is recommended; one that is MAY in every column (the national algorithms, and
// any row added through Specification Required) is regional; the rest are supported
export function registryStanding(entry: RegistryEntry): Standing {
  if (entry.validate === 'MUST NOT') return 'prohibited';
  if (entry.sign === 'MUST NOT') return 'deprecated';
  if (entry.sign === 'RECOMMENDED') return 'recommended';
  const columns = [entry.sign, entry.validate, entry.implementSign, entry.implementValidate];
  if (columns.every(column => column === 'MAY')) return 'regional';
  return 'supported';
}

// a bundled table (DNSSEC_ALGORITHMS or DS_DIGEST_TYPES) as number, name and standing
export type BundledTable = Record<number, { name: string; standing: string }>;

const entryKey = (number: number, name: string, standing: string) =>
  `${number} ${name} (${standing})`;

// where a bundled table and IANA's registry differ, one line each
export function registryChanges(
  label: string,
  bundled: BundledTable,
  published: readonly RegistryEntry[]
): string[] {
  return difference(
    label,
    Object.entries(bundled).map(([number, entry]) =>
      entryKey(Number(number), entry.name, entry.standing)
    ),
    published.map(entry => entryKey(entry.number, entry.name, registryStanding(entry)))
  );
}

// a bundled table as source, for the rewrite: names and standings from IANA, and what the
// library knows (`verify`, and a digest's `strength`) kept from the bundle. A row new to the
// bundle cannot be verified until code is written for it, so it starts at verify: false
export function registryLiteral(
  constant: 'DNSSEC_ALGORITHMS' | 'DS_DIGEST_TYPES',
  bundled: Record<number, { verify: boolean; strength?: number }>,
  published: readonly RegistryEntry[]
): string {
  const entries = published.map(entry => {
    const known = bundled[entry.number];
    const fields = [`name: '${entry.name}'`, `verify: ${known?.verify ?? false}`];
    if (constant === 'DS_DIGEST_TYPES') fields.push(`strength: ${known?.strength ?? 0}`);
    fields.push(`standing: ALGORITHM_STANDINGS.${registryStanding(entry).toUpperCase()}`);
    return `  ${entry.number}: { ${fields.join(', ')} },`;
  });
  return `export const ${constant} = {\n${entries.join('\n')}\n} as const;`;
}

// the bundled data as source, for the rewrite
export function anchorsLiteral(
  anchors: readonly PublishedAnchor[],
  bundled: readonly TrustAnchor[],
  today: string
): string {
  const entries = anchors.map(anchor => {
    const known = bundled.find(entry => entry.digest.toLowerCase() === anchor.digest);
    const id = known?.id ?? `KSK-${(anchor.validFrom ?? today).slice(0, 4)}`;
    const lines = [
      `    id: '${id}',`,
      `    keyTag: ${anchor.keyTag},`,
      `    algorithm: ${anchor.algorithm},`,
      `    digestType: ${anchor.digestType},`,
      `    digest: '${anchor.digest}',`,
    ];
    if (anchor.validFrom) {
      lines.push(`    validFrom: new Date('${anchor.validFrom}T00:00:00.000Z'),`);
    }
    if (anchor.validUntil) {
      lines.push(`    validUntil: new Date('${anchor.validUntil}T00:00:00.000Z'),`);
    }
    return `  {\n${lines.join('\n')}\n  },`;
  });
  return `export const ROOT_TRUST_ANCHORS: TrustAnchor[] = [\n${entries.join('\n')}\n];`;
}

export function hintsLiteral(hints: readonly NameserverHint[]): string {
  const entries = hints.map(
    hint => `  { name: '${hint.name}', ipv4: '${hint.ipv4}', ipv6: '${hint.ipv6}' },`
  );
  return `export const ROOT_HINTS: readonly NameserverHint[] = [\n${entries.join('\n')}\n];`;
}
