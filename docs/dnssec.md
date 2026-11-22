# DNSSEC

DNSSEC validation in the resolvers (`validate: true`), and `@aoxborrow/dns/dnssec`: the
judging core they use, the primitives it is built from, and the codes and registries those
return and read. `/dnssec` runs anywhere, browsers and Cloudflare Workers included.

## Validating answers

```ts network
import { AuthoritativeResolver, Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1'], validate: true });
const answer = await resolver.query('example.com', 'A');

answer.security?.status; // 'secure', 'insecure', 'bogus' or 'indeterminate'
answer.security?.reason; // { code: 'verified', zone: 'example.com', name: 'example.com', type: 'A' }

const iterative = new AuthoritativeResolver({ validate: true });
const broken = await iterative.query('dnssec-failed.org', 'A');
broken.security?.status; // 'bogus'
broken.security?.reason; // { code: 'no-matching-dnskey', zone: 'dnssec-failed.org', keyTag: …, ede: 9 }
broken.security?.failure; // the first link that broke: { kind: 'keys', zone: 'dnssec-failed.org', … }
```

With `validate: true`, both resolvers check every answer's chain of trust and say what came
of it in `answer.security`. The data is asked for with DO set (and CD, for `Resolver`, so a
validating resolver upstream hands over broken records instead of a SERVFAIL); then each
zone between the root and the data has its DS and DNSKEY records fetched the same way, and
the judging core decides. The answer itself is unchanged apart from carrying its
signatures in `answers`; nothing is withheld, whatever the verdict. Without `validate`,
nothing changes. Validation needs EDNS, which carries the DO bit: `edns: false` on a
validating resolver, or on one of its queries, is a `TypeError`.

| Status          | Meaning                                                                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secure`        | a chain of valid signatures runs from a trust anchor to the data                                                                                                                      |
| `insecure`      | the data is proven to sit below a delegation with no DS (or an opt-out range, or a DS set naming only algorithms this runtime cannot verify, RFC 6840 §5.2), so nothing could sign it |
| `bogus`         | a chain should be there and is broken: an expired or invalid signature, a DS that matches no key, a missing proof                                                                     |
| `indeterminate` | it could not be told: a response missing or truncated, or every signature in an algorithm this runtime cannot check                                                                   |

`reason` is a code and the values it is about (zone, name, type, key tag, algorithm), never
English, with `ede` set to the extended DNS error (RFC 8914) a validating resolver would send
for it, where one fits: 7 for an expired signature, 9 for a missing DNSKEY, 10 for missing
RRSIGs, 12 for a missing NSEC proof, 1 for an unsupported algorithm, 27 for an NSEC3
iteration count past 50. `chain` lists every link judged, each zone's key set from the root
down and then each RRset and denial proof of the data, each with its own status and reason;
`failure` is the first bogus or indeterminate one. CNAME and DNAME chains are judged link by
link (a CNAME synthesized from a signed DNAME needs no signature of its own), answers from a
wildcard need the proof that the name itself does not exist, and NXDOMAIN and NODATA need
their NSEC or NSEC3 proofs, a NODATA from a wildcard or at an empty non-terminal included.
An opt-out range makes an answer insecure only where the NSEC3 covering the next closer name
sets it (RFC 5155 §9.2).

One answer may cost at most 128 signature verifications, 4 keys tried per signature and 8
signatures per RRset; past that it is `bogus` with the code `validation-limit`, as
validators have done since KeyTrap (CVE-2023-50387). `judgeChain` takes other `limits`.
NSEC3 names are hashed once per parameter set, and not at all past 50 iterations.

What each zone's key set came to is kept for as long as the TTLs and signatures it rests on
allow (with `cache: false`, not at all), and `clearCache()` forgets it. Validation starts
from `trustAnchors`, IANA's root anchors by default (`ROOT_TRUST_ANCHORS`, with
`ROOT_TRUST_ANCHORS_DATA_VERSION` and `ROOT_TRUST_ANCHORS_REFRESHED`). A key published with
the RFC 5011 revoke bit anchors nothing and signs nothing.

## The judging core

The resolvers fetch, and `judgeChain` judges. Given the root's DNSKEY response, each name's
DS response (and DNSKEY response, where it is a zone of its own), the responses holding the
data, the trust anchors and a time, it returns the status and reason of every link. It
fetches nothing and keeps nothing, so the same records and time always give the same
judgement.

```ts network
import { Resolver } from '@aoxborrow/dns';
import { typeCode } from '@aoxborrow/dns/records';
import { judgeChain } from '@aoxborrow/dns/dnssec';
import type { DnssecResponse } from '@aoxborrow/dns/dnssec';

const resolver = new Resolver({ servers: ['1.1.1.1'], dnssecOk: true, checkingDisabled: true });

// one response as the core reads it: the question as sent, and the records with their
// signatures
async function ask(name: string, type: string): Promise<DnssecResponse> {
  const answer = await resolver.query(name, type);
  const { answers, authorities } = answer.message;
  return {
    name: answer.query.name,
    type: typeCode(type),
    rcode: answer.rcode,
    answers,
    authorities,
  };
}

const judgement = await judgeChain(
  {
    anchored: await ask('.', 'DNSKEY'),
    names: [
      { name: 'com', ds: await ask('com', 'DS'), dnskey: await ask('com', 'DNSKEY') },
      {
        name: 'example.com',
        ds: await ask('example.com', 'DS'),
        dnskey: await ask('example.com', 'DNSKEY'),
      },
    ],
    responses: [await ask('example.com', 'A')],
  },
  { mode: 'all', now: new Date() }
);
judgement.status; // 'secure'
judgement.links; // every link, with a status, a reason and the checks it rests on
```

A response marked `truncated: true` (it came with TC set) is not the whole answer: in a
signed zone its data is `indeterminate`, whatever signatures it carries.

`mode: 'first'` (what the resolvers use) stops at the first link that settles the outcome;
`mode: 'all'` judges every link and every signature. `requireEveryAlgorithm` asks for each
RRset to be signed with every algorithm in its zone's key set (RFC 4035 §2.2), which
validators do not require (RFC 6840 §5.11). `limits` caps the signature checks a judgement
may make (KeyTrap, CVE-2023-50387). In `mode: 'first'` one budget covers the whole judgement,
however many zones an answer crosses; in `mode: 'all'` a zone's key set and the RRsets and
proofs it signs draw on a budget of their own, so one zone cannot use up another's.

Each link carries its `evidence`, the checks it rests on, as codes and data:

- a `keys` link has the zone's keys (`DnssecKey`), what the trust anchors made of them
  (`AnchorCheck`) or the parent's signature over the DS RRset and the DS records against the
  keys (`RrsetCheck`, `DsSetCheck`), the key set's signatures (`KeySetCheck`), and, for a
  zone proven unsigned, the parent's proof that it has no DS;
- an `rrset` link has the RRset and every signature over it (`RrsetCheck`);
- a `denial` link has each NSEC or NSEC3 RRset, checked, the proof worked out from them
  step by step (`DenialProof`), and what it is for (`purpose`: `nxdomain`, `nodata` or
  `wildcard`). Past the NSEC3 iterations validators hash
  (`NSEC3_ITERATIONS_INSECURE_THRESHOLD`, RFC 9276 §3.2) the proof is left unworked, with
  status `iterations-exceeded`, and the answer is `insecure`.

A link that only takes a zone's outcome, below a zone that is not secure or from a `known`
fact, has no evidence. Key size never changes a verdict: an RSA key under 1024 bits is
verified like any other, as validators do by default, so a good signature by one counts and
a forged one fails. A caller that wants to flag such keys reads them from the evidence
(`keySet.rrset`, or the `key` of each signature check) and sizes them with `keySizeBits()`.

## The primitives

```ts network
import { Resolver } from '@aoxborrow/dns';
import {
  buildSignedData,
  computeKeyTag,
  groupRrsets,
  verifySignature,
} from '@aoxborrow/dns/dnssec';
import { decodeDnskey, decodeRrsig, RECORD_TYPES } from '@aoxborrow/dns/records';

// a zone's keys and the signatures over them, from a resolver asked not to validate
const resolver = new Resolver({ servers: ['1.1.1.1'] });
const answer = await resolver.query('example.com', 'DNSKEY', {
  dnssecOk: true,
  checkingDisabled: true,
});
const { answers } = answer.message;
const [keys] = groupRrsets(answers);

for (const record of answers.filter(rr => rr.type === RECORD_TYPES.RRSIG)) {
  const rrsig = decodeRrsig(record.rdata); // throws ParseError for malformed data
  const key = keys.records.find(rr => computeKeyTag(rr.rdata) === rrsig.keyTag);
  const signed = buildSignedData(rrsig, keys);
  if (!key || !signed) continue;

  const { publicKey } = decodeDnskey(key.rdata);
  const outcome = await verifySignature(rrsig.algorithm, publicKey, signed.data, rrsig.signature);
  outcome.verified; // true, false, or undefined when this runtime cannot check the algorithm
}
```

These are the pieces the judging core is built from, each checking one thing.
`verifySignature` checks RSA, ECDSA and EdDSA signatures through WebCrypto; an algorithm
the runtime cannot verify comes back not checked, never as a pass, and
`isAlgorithmSupported` says beforehand whether it can (a WebCrypto may lack Ed25519 or
Ed448). `computeDsDigest` and `computeKeyTag` match a DS record to the key it names.
`verifyNoDsProof`, `verifyNxdomainProof`, `verifyNodataProof` and `verifyWildcardProof`
check NSEC and NSEC3 denial proofs and return the reasoning step by step;
`verifyWildcardProof` takes the wildcard an answer was synthesised from, which
`wildcardOwner` rebuilds from the RRSIG's labels field. Digests and NSEC3 hashes use the
library's own SHA-1, SHA-256 and SHA-384. They all take records as the library decodes them,
the `ResourceRecord`s of `answer.message`; `buildSignedData` puts their data in the canonical
form signatures are computed over (RFC 4034 §6.2).
The record-data decoders (`decodeRrsig`, `decodeDnskey` and the rest) are in `/records`.

## Codes, registries and helpers

What the judgements and the checks return is spelled out as constants:

| Name                                                          |                                                                                                                                                                              |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECURITY_STATUSES`                                           | the four statuses: `secure`, `insecure`, `bogus`, `indeterminate`                                                                                                            |
| `REASON_CODES`                                                | every reason code a link can carry. A reason with an extended DNS error (RFC 8914) carries its code in `ede`                                                                 |
| `DS_CODES`, `KEY_SET_CODES`, `RRSET_CODES`, `SIGNATURE_CODES` | the codes the checks give a DS set, a key set, an RRset and one signature                                                                                                    |
| `CHECK_LIMITS` | the default `limits` on signature checking: 128 verifications (for each zone in `mode: 'all'`), 4 keys tried per signature, 8 signatures per RRset |
| `VERIFICATION_RESULTS`                                        | what a signature or digest check came to: `verified`, `failed` or `unchecked`                                                                                                |
| `NSEC3_ITERATIONS_INSECURE_THRESHOLD`, `NSEC3_ITERATIONS_SERVFAIL_THRESHOLD` | the NSEC3 iterations past which validators treat a denial as insecure (50), and past which most return SERVFAIL (500) (RFC 9276 §3.2) |
| `PROOF_TYPES`, `PROOF_PURPOSES`, `PROOF_STATUSES`             | a denial proof's kind (NSEC or NSEC3), what it was asked to show, and how it came out                                                                                        |

The registries the checks read:

| Name                                                                       |                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DNSSEC_ALGORITHMS`, `ALGORITHM_STANDINGS`, `ALGORITHM_REGISTRY_REFRESHED` | each signing algorithm's name, whether the library verifies it, and its standing in IANA's registry (RFC 9904); the standings themselves, which are `recommended`, `supported`, `deprecated`, `prohibited` and `regional`; and the date they were last checked against IANA |
| `DS_DIGEST_TYPES`                                                          | each DS digest type's name, standing and strength. Strength picks among several digests published for one key (RFC 4509 §3)                                                                                                                                                 |
| `NSEC3_HASH_ALGORITHMS`                                                    | the NSEC3 hash algorithms, which is SHA-1 alone                                                                                                                                                                                                                             |
| `DNSKEY_FLAGS`, `DNSKEY_PROTOCOL`, `NSEC3_FLAGS`                           | the flag bits of a DNSKEY, the one protocol value it may carry (3), and the flag bits of an NSEC3                                                                                                                                                                           |
| `ROOT_TRUST_ANCHOR_SOURCE`                                                 | the URL of the IANA file `ROOT_TRUST_ANCHORS` is taken from                                                                                                                                                                                                                 |

And the smaller functions:

| Name                                                          |                                                                                                                                                                             |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `algorithmName()`, `isAlgorithmVerifiable()`, `keySizeBits()` | an algorithm's mnemonic; whether the library has code to verify it, which `isAlgorithmSupported` goes on to check against the runtime; and the size of a public key in bits |
| `isDigestDeprecated()`                                        | whether a DS digest type is deprecated (SHA-1)                                                                                                                              |
| `readKeys()`                                                  | the DNSKEYs among some records, decoded, leaving out any that do not decode                                                                                                 |
| `canonicalRdata()`                                            | record data in canonical form (RFC 4034 §6.2)                                                                                                                               |
| `nsec3Hash()`, `assessNsec3Params()`                          | a name's NSEC3 hash, and a zone's NSEC3 parameters held against RFC 9276                                                                                                    |
