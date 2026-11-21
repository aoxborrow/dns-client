import type { TrustAnchor } from './types';

// the IANA root trust anchors, shipped as data: the default `trustAnchors` of both
// resolvers and of the judging core.
//
// this is the one piece of the library that expires on a schedule, so it is deliberately a
// literal rather than a network fetch: a validator whose anchor comes from the network has
// no anchor. `scripts/refresh-anchors.ts` compares it with IANA's file (a weekly CI job runs
// it in check mode) and rewrites it; the procedure is in CONTRIBUTING.md.
//
// both current KSKs are held at once. KSK-2024 (38696) signs the root zone since
// 2026-10-11 and KSK-2017 (20326) is due to be revoked on 2027-01-11. As of the refresh
// below IANA's file gives KSK-2017 no validUntil, so neither has one here. Once it is
// revoked, KSK-2017 is published with the RFC 5011 revoke bit and anchors nothing: a
// revoked key's digest no longer matches its anchor, a revoked key's signature never counts
// (RFC 5011 §2.1), and an anchor whose key signs the key set revoked is dropped
// (`checkAnchors`). When IANA then gives it a validUntil, the CI check fails until it is
// copied here.
export const ROOT_TRUST_ANCHOR_SOURCE = 'https://data.iana.org/root-anchors/root-anchors.xml';

// a version for the data below: the date it last changed. The refresh script sets it when
// what IANA publishes differs from it
export const ROOT_TRUST_ANCHORS_DATA_VERSION = '2026-07-28';

// when the literal below was last checked against the source above
export const ROOT_TRUST_ANCHORS_REFRESHED = '2026-11-16';

export const ROOT_TRUST_ANCHORS: TrustAnchor[] = [
  {
    id: 'KSK-2017',
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digest: 'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d',
    validFrom: new Date('2017-02-02T00:00:00.000Z'),
  },
  {
    id: 'KSK-2024',
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digest: '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16',
    validFrom: new Date('2024-07-18T00:00:00.000Z'),
  },
];

// an anchor is usable when the scan time falls inside its published validity window
export function isAnchorCurrent(anchor: TrustAnchor, at: Date): boolean {
  if (anchor.validFrom && at < anchor.validFrom) return false;
  if (anchor.validUntil && at > anchor.validUntil) return false;
  return true;
}
