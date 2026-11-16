import { describe, expect, it } from 'vitest';
import {
  checkAnchors,
  EXTENDED_DNS_ERRORS,
  judgeChain,
  readKeys,
  REASON_CODES,
  REASON_EDE,
} from '../../src/dnssec/index';
import type { DnssecResponse } from '../../src/dnssec/index';
import { dnssecResponse } from '../../src/dnssec/validate';
import { Resolver } from '../../src/index';
import { simulateNetwork } from '../support/simulated-network';
import { anchorFor, ecdsaKey, revokedKey, signedNetwork } from '../support/signed-zones';
import type { SignedZone } from '../support/signed-zones';

// the judging core on its own: the records are fetched here, by hand, and handed over

const DAY = 86_400_000;

// ask each zone's own server, as the analysis does, and keep the responses as they came
async function fetchAll(zones: SignedZone[], questions: [string, string, string][]) {
  const signed = signedNetwork(zones);
  const network = simulateNetwork(signed.servers);
  const resolver = new Resolver({ transports: network.transports, cache: false });
  const responses = new Map<string, DnssecResponse>();
  for (const [zone, name, type] of questions) {
    const index = zones.findIndex(spec => spec.zone === zone);
    const answer = await resolver.query(name, type, {
      server: `10.53.0.${index + 1}`,
      dnssecOk: true,
      recursionDesired: false,
    });
    responses.set(
      `${name} ${type}`,
      dnssecResponse(answer.message, name, answer.message.questions[0].type)
    );
  }
  return { signed, responses };
}

const zones: SignedZone[] = [
  { zone: '.' },
  { zone: 'example' },
  {
    zone: 'secure.example',
    records: [['www.secure.example', 'A', '192.0.2.1']],
    inception: new Date(Date.now() - 30 * DAY),
    expiration: new Date(Date.now() - DAY),
  },
];

const questions: [string, string, string][] = [
  ['.', '.', 'DNSKEY'],
  ['.', 'example', 'DS'],
  ['example', 'example', 'DNSKEY'],
  ['example', 'secure.example', 'DS'],
  ['secure.example', 'secure.example', 'DNSKEY'],
  ['secure.example', 'www.secure.example', 'DS'],
  ['secure.example', 'www.secure.example', 'A'],
];

async function input() {
  const { signed, responses } = await fetchAll(zones, questions);
  const get = (key: string) => responses.get(key)!;
  return {
    trustAnchors: signed.trustAnchors,
    chain: {
      anchored: get('. DNSKEY'),
      names: [
        { name: 'example', ds: get('example DS'), dnskey: get('example DNSKEY') },
        {
          name: 'secure.example',
          ds: get('secure.example DS'),
          dnskey: get('secure.example DNSKEY'),
        },
        { name: 'www.secure.example', ds: get('www.secure.example DS') },
      ],
      responses: [get('www.secure.example A')],
    },
  };
}

describe('judgeChain', () => {
  it('stops at the first decisive link, or judges every link', async () => {
    const { trustAnchors, chain } = await input();

    const first = await judgeChain(chain, { trustAnchors, mode: 'first' });
    expect(first.status).toBe('bogus');
    expect(first.reason).toMatchObject({
      code: 'signature-expired',
      zone: 'secure.example',
      ede: 7,
    });
    // the zone's key set is where it broke, and nothing after it was judged
    expect(first.links.map(link => [link.kind, link.zone, link.status])).toEqual([
      ['keys', '.', 'secure'],
      ['keys', 'example', 'secure'],
      ['keys', 'secure.example', 'bogus'],
    ]);
    expect(first.failure).toBe(first.links[2]);

    const all = await judgeChain(chain, { trustAnchors, mode: 'all' });
    expect(all.status).toBe('bogus');
    // the data is judged too, and takes the broken zone's outcome
    expect(all.links.at(-1)).toMatchObject({
      kind: 'rrset',
      name: 'www.secure.example',
      status: 'bogus',
    });
  });

  it('gives the same judgement for the same records and time', async () => {
    const { trustAnchors, chain } = await input();
    const now = new Date();
    const a = await judgeChain(chain, { trustAnchors, now, mode: 'all' });
    const b = await judgeChain(chain, { trustAnchors, now, mode: 'all' });
    expect(a).toEqual(b);
  });

  it('is indeterminate with nothing to start from', async () => {
    const judgement = await judgeChain({}, {});
    expect(judgement.status).toBe('indeterminate');
    expect(judgement.reason).toMatchObject({ code: 'response-missing', zone: '.' });
  });
});

describe('reasons', () => {
  it('maps each failure to its extended DNS error where RFC 8914 has one', () => {
    expect(REASON_EDE[REASON_CODES.SIGNATURE_EXPIRED]).toBe(EXTENDED_DNS_ERRORS.SIGNATURE_EXPIRED);
    expect(REASON_EDE[REASON_CODES.DNSKEY_MISSING]).toBe(9);
    expect(REASON_EDE[REASON_CODES.RRSIGS_MISSING]).toBe(10);
    expect(REASON_EDE[REASON_CODES.UNSUPPORTED_ALGORITHM]).toBe(1);
    expect(REASON_EDE[REASON_CODES.SIGNATURE_INVALID]).toBe(6);
    expect(REASON_EDE[REASON_CODES.DENIAL_MISSING]).toBe(12);
    expect(REASON_EDE[REASON_CODES.NSEC3_ITERATIONS]).toBe(27);
    // a secure or plainly unsigned outcome is no error
    expect(REASON_EDE[REASON_CODES.VERIFIED]).toBeUndefined();
    expect(REASON_EDE[REASON_CODES.NO_DS]).toBeUndefined();
  });
});

describe('checkAnchors', () => {
  it('drops an anchor whose key signs the key set with the revoke bit set (RFC 5011 §2.1)', async () => {
    const old = ecdsaKey();
    const current = ecdsaKey();
    const revoked = revokedKey(old);
    const { responses } = await fetchAll(
      [{ zone: '.', keys: [revoked, current], signers: [revoked, current] }],
      [['.', '.', 'DNSKEY']]
    );
    const answers = responses.get('. DNSKEY')!.answers;
    const keys = readKeys(answers);
    const rrset = {
      name: '.',
      type: 48,
      typeName: 'DNSKEY',
      class: 1,
      ttl: 3600,
      records: answers.filter(record => record.type === 48),
    };
    const rrsigs = answers.filter(record => record.type === 46);
    const anchors = [anchorFor(old), anchorFor(current)];

    const check = await checkAnchors('.', keys, anchors, new Date(), { rrset, rrsigs });
    expect(check.revokedAnchors).toEqual([anchors[0]]);
    expect(check.revokedKeyTags).toEqual([revoked.keyTag]);
    expect(check.anchors).toEqual([anchors[1]]);
    expect(check.keys.map(key => key.keyTag)).toEqual([current.keyTag]);
  });

  it('skips an anchor outside its validity window', async () => {
    const key = ecdsaKey();
    const { responses } = await fetchAll([{ zone: '.', keys: [key] }], [['.', '.', 'DNSKEY']]);
    const keys = readKeys(responses.get('. DNSKEY')!.answers);
    const retired = { ...anchorFor(key), validUntil: new Date(Date.now() - DAY) };
    const check = await checkAnchors('.', keys, [retired], new Date());
    expect(check.result).toBe('failed');
    expect(check.keys).toEqual([]);
  });
});
