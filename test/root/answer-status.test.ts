import { describe, expect, it } from 'vitest';
import type { ExchangeResult } from '../../src/exchange';
import { buildAnswer } from '../../src/resolvers/answer';
import type { AnswerExtras } from '../../src/resolvers/answer';
import { decodeMessage, encodeMessage, encodeName } from '../../src/wire/index';
import type { EncodableMessage, ResourceRecord } from '../../src/wire/index';
import { soaRecord } from '../support/simulated-network';

// what buildAnswer makes of a response's rcode and sections: its status and negativeTtl

const TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, MX: 15 };

function answer(
  name: string,
  type: string,
  parts: Partial<EncodableMessage> = {},
  extras: AnswerExtras & { tcpFallbackError?: ExchangeResult['tcpFallbackError'] } = {}
) {
  const { tcpFallbackError, ...rest } = extras;
  const bytes = encodeMessage({
    id: 1,
    questions: [{ name, type: TYPES[type], class: 1 }],
    ...parts,
    flags: { qr: true, ...parts.flags },
  });
  return buildAnswer(
    {
      message: decodeMessage(bytes),
      bytes,
      query: {
        name,
        type,
        class: 'IN',
        flags: { rd: true, cd: false, ad: false },
        edns: false,
        id: 1,
        bytes: new Uint8Array(),
      },
      server: '192.0.2.53',
      port: 53,
      transport: 'udp',
      elapsed: 1,
      attempts: 1,
      ...(tcpFallbackError && { tcpFallbackError }),
    },
    rest
  );
}

const address = (name: string): ResourceRecord => ({
  name,
  type: 1,
  class: 1,
  ttl: 300,
  rdata: Uint8Array.of(192, 0, 2, 1),
  section: 'answer',
});

const cname = (name: string, target: string, ttl = 300): ResourceRecord => ({
  name,
  type: 5,
  class: 1,
  ttl,
  rdata: encodeName(target),
  section: 'answer',
});

const ns = (zone: string, target: string): ResourceRecord => ({
  name: zone,
  type: 2,
  class: 1,
  ttl: 3600,
  rdata: encodeName(target),
  section: 'authority',
});

describe('answer status', () => {
  it('is ok when there are records, with no negativeTtl', () => {
    const ok = answer('example.com', 'A', { answers: [address('example.com')] });
    expect(ok.status).toBe('ok');
    expect(ok).not.toHaveProperty('negativeTtl');
    // a question for an alias is answered by it
    const alias = answer('www.example.com', 'CNAME', {
      answers: [cname('www.example.com', 'host.other.net')],
    });
    expect(alias.status).toBe('ok');
  });

  describe('nxdomain', () => {
    it('keeps it for the smaller of the SOA TTL and minimum', () => {
      const missing = answer('missing.example.com', 'A', {
        rcode: 3,
        authorities: [soaRecord('example.com', 3600, 300)],
      });
      expect(missing.status).toBe('nxdomain');
      expect(missing.negativeTtl).toBe(300);
    });

    it('is the name at the end of an alias chain, kept no longer than the alias', () => {
      const missing = answer('www.example.com', 'A', {
        rcode: 3,
        answers: [cname('www.example.com', 'gone.example.com', 60)],
        authorities: [soaRecord('example.com', 3600, 300)],
      });
      expect(missing.status).toBe('nxdomain');
      expect(missing.negativeTtl).toBe(60);
    });

    it('has a negativeTtl of 0 with no SOA, or one for another zone', () => {
      expect(answer('missing.example.com', 'A', { rcode: 3 })).toMatchObject({
        status: 'nxdomain',
        negativeTtl: 0,
      });
      expect(
        answer('missing.example.com', 'A', {
          rcode: 3,
          authorities: [soaRecord('other.net', 3600, 300)],
        })
      ).toMatchObject({ status: 'nxdomain', negativeTtl: 0 });
    });

    it('is nxdomain even with records beside it', () => {
      const odd = answer('example.com', 'A', { rcode: 3, answers: [address('example.com')] });
      expect(odd.status).toBe('nxdomain');
    });
  });

  describe('nodata', () => {
    it('is an empty NOERROR the zone SOA vouches for', () => {
      const empty = answer('example.com', 'MX', {
        authorities: [soaRecord('example.com', 3600, 300)],
      });
      expect(empty.status).toBe('nodata');
      expect(empty.negativeTtl).toBe(300);
    });

    it('is nodata at a zone apex that also lists its NS', () => {
      const apex = answer('example.com', 'MX', {
        authorities: [soaRecord('example.com', 3600, 300), ns('example.com', 'ns1.example.com')],
      });
      expect(apex.status).toBe('nodata');
    });

    it('is the end of an alias chain when the SOA there vouches for it (RFC 2308 §2.2)', () => {
      const empty = answer('www.example.com', 'MX', {
        answers: [cname('www.example.com', 'host.other.net', 120)],
        authorities: [soaRecord('other.net', 3600, 600)],
      });
      expect(empty.status).toBe('nodata');
      expect(empty.negativeTtl).toBe(120);
    });

    it('has a negativeTtl of 0 when no SOA says how long', () => {
      // an authoritative server, or a resolver, saying the name has nothing of the type
      expect(answer('example.com', 'MX', { flags: { aa: true } })).toMatchObject({
        status: 'nodata',
        negativeTtl: 0,
      });
      expect(answer('example.com', 'MX', { flags: { ra: true } })).toMatchObject({
        status: 'nodata',
        negativeTtl: 0,
      });
      // an SOA for a zone the name is not in says nothing about it
      expect(
        answer('example.com', 'MX', { authorities: [soaRecord('other.net', 3600, 300)] })
      ).toMatchObject({ status: 'nodata', negativeTtl: 0 });
    });

    it('trusts only an SOA from the zone that was asked', () => {
      const above = answer(
        'www.example.com',
        'MX',
        { flags: { aa: true }, authorities: [soaRecord('com', 900, 900)] },
        { zone: 'example.com' }
      );
      expect(above).toMatchObject({ status: 'nodata', negativeTtl: 0 });
    });

    it('is not capped at an hour, as the cache is', () => {
      const long = answer('example.com', 'MX', {
        authorities: [soaRecord('example.com', 86_400, 86_400)],
      });
      expect(long.negativeTtl).toBe(86_400);
    });

    it('counts down what is left of it on a cached answer, down to 0', () => {
      const parts = { authorities: [soaRecord('example.com', 3600, 300)] };
      expect(answer('example.com', 'MX', parts, { age: 100, cached: true }).negativeTtl).toBe(200);
      expect(answer('example.com', 'MX', parts, { age: 400, cached: true }).negativeTtl).toBe(0);
    });

    it('is the followed target that has nothing, not an alias', () => {
      const followed = answer(
        'host.other.net',
        'MX',
        { flags: { aa: true } },
        {
          name: 'www.example.com',
          zone: 'other.net',
          before: [
            {
              name: 'www.example.com',
              type: 'CNAME',
              class: 'IN',
              ttl: 300,
              target: 'host.other.net',
            },
          ],
        }
      );
      expect(followed.status).toBe('nodata');
    });
  });

  describe('alias', () => {
    it('is a chain whose target was not followed and that no SOA speaks for', () => {
      const away = answer('www.example.com', 'A', {
        flags: { aa: true },
        answers: [cname('www.example.com', 'host.other.net')],
      });
      expect(away.status).toBe('alias');
      expect(away).not.toHaveProperty('negativeTtl');
    });

    it('is still an alias when the SOA beside it is the alias zone, not the target zone', () => {
      const away = answer('www.example.com', 'A', {
        flags: { aa: true },
        answers: [cname('www.example.com', 'host.other.net')],
        authorities: [soaRecord('example.com', 3600, 300), ns('other.net', 'ns1.other.net')],
      });
      expect(away.status).toBe('alias');
    });

    it('is a chain out of the zone that was asked', () => {
      const away = answer(
        'www.example.com',
        'A',
        {
          flags: { aa: true },
          answers: [cname('www.example.com', 'host.other.net'), address('host.other.net')],
        },
        { zone: 'example.com' }
      );
      // the target's address is not one this zone's server can vouch for
      expect(away.records).toEqual([]);
      expect(away.status).toBe('alias');
    });
  });

  describe('referral', () => {
    it('is NS in authority with no SOA, from a server without authority', () => {
      const down = answer('www.example.com', 'A', {
        authorities: [ns('example.com', 'ns1.example.com')],
      });
      expect(down.status).toBe('referral');
      expect(down).not.toHaveProperty('negativeTtl');
    });

    it('is not a referral when the server says it has authority', () => {
      const own = answer('www.example.com', 'A', {
        flags: { aa: true },
        authorities: [ns('example.com', 'ns1.example.com')],
      });
      expect(own.status).toBe('nodata');
    });
  });

  describe('failed', () => {
    it('is any other rcode, even with records beside it', () => {
      expect(answer('example.com', 'A', { rcode: 2 }).status).toBe('failed');
      expect(answer('example.com', 'A', { rcode: 5 }).status).toBe('failed');
      const odd = answer('example.com', 'A', { rcode: 2, answers: [address('example.com')] });
      expect(odd.status).toBe('failed');
    });

    it("is nothing at all from a zone's server that does not claim authority", () => {
      // AuthoritativeResolver returns it when every one of the zone's servers was lame
      const lame = answer('example.com', 'MX', {}, { zone: 'example.com' });
      expect(lame.status).toBe('failed');
      expect(lame).not.toHaveProperty('negativeTtl');
    });

    it("is an NXDOMAIN from a zone's server with neither authority nor the zone's SOA", () => {
      const lame = answer('missing.example.com', 'A', { rcode: 3 }, { zone: 'example.com' });
      expect(lame.status).toBe('failed');
      // the zone's SOA, or authority, makes it the zone's word
      const soa = { rcode: 3, authorities: [soaRecord('example.com', 3600, 300)] };
      expect(answer('missing.example.com', 'A', soa, { zone: 'example.com' }).status).toBe(
        'nxdomain'
      );
      const authority = { rcode: 3, flags: { aa: true } };
      expect(answer('missing.example.com', 'A', authority, { zone: 'example.com' }).status).toBe(
        'nxdomain'
      );
    });

    it('is an empty truncated answer, which cannot tell NODATA from records cut off', () => {
      const tcpFallbackError = { name: 'ConnectionError', message: 'refused', retryable: true };
      const cut = answer(
        'example.com',
        'A',
        { flags: { tc: true }, authorities: [soaRecord('example.com', 3600, 300)] },
        { tcpFallbackError }
      );
      expect(cut.status).toBe('failed');
      expect(cut).not.toHaveProperty('negativeTtl');
    });
  });

  describe('a truncated answer', () => {
    it('is ok with whatever records it carried', () => {
      const cut = answer('example.com', 'A', {
        flags: { tc: true },
        answers: [address('example.com')],
      });
      expect(cut.status).toBe('ok');
    });

    it('is nxdomain, the rcode surviving truncation, kept for 0 seconds', () => {
      const cut = answer('missing.example.com', 'A', {
        rcode: 3,
        flags: { tc: true },
        authorities: [soaRecord('example.com', 3600, 300)],
      });
      expect(cut).toMatchObject({ status: 'nxdomain', negativeTtl: 0 });
    });
  });
});
