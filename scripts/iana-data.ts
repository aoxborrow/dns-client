// reading IANA's root trust anchor file and root hints file, and telling where the bundled
// copies differ. Used by refresh-anchors.ts, and tested offline against saved copies
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
