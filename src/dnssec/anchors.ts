import type { TrustAnchor } from './types';

// the IANA root trust anchors, shipped as data.
//
// this is the one piece of the tool that expires on a schedule, so it is deliberately a
// literal rather than a network fetch: a validator whose anchor comes from the network has
// no anchor. refresh procedure is in docs/reference/dnssec-trust-anchors.md.
//
// both current KSKs are held at once. KSK-2024 (38696) begins signing the root zone on
// 2026-10-11 and KSK-2017 (20326) is revoked on 2027-01-11; both are published in the root
// DNSKEY RRset today, and "two KSKs published" is a normal rollover, not an anomaly.
export const ROOT_TRUST_ANCHOR_SOURCE = 'https://data.iana.org/root-anchors/root-anchors.xml';

// when the literal below was last reconciled with the source above
export const ROOT_TRUST_ANCHORS_REFRESHED = '2026-07-28';

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
