import {
  ConnectionError,
  EmptyResponseError,
  InvalidQueryError,
  InvalidResponseError,
  TimeoutError,
  TruncatedError,
} from '../../src/errors';
import { digCommand, exchange, toDig } from '../../src/exchange';
import type { ExchangeOptions } from '../../src/exchange';
import { createTransports } from '../../src/transports/index';
import type { Transports } from '../../src/transports/index';
import type { DnsEvent } from '../../src/transports/types';
import { decodeMessage, encodeQuery } from '../../src/wire/index';
import { answerTo, askedName, queryId } from '../support/answers';
import { startFixtureServer, truncated, withOtherId } from '../support/fixture-server';
import type { FixtureServer, Responder } from '../support/fixture-server';

// `exchange` against a server that can be told to misbehave. Nothing here leaves the
// machine

const QUESTION = { name: 'example.com', type: 'A' };

describe('exchange', () => {
  let server: FixtureServer;
  let transports: Transports;

  // start a server, and return the options that point an exchange at it
  async function serve(respond: Responder): Promise<ExchangeOptions> {
    server = await startFixtureServer(respond);
    return { port: server.port, transports, timeout: 150, retries: 0 };
  }

  beforeEach(() => {
    transports = createTransports();
  });

  afterEach(async () => {
    transports.close();
    await server?.close();
  });

  describe('over UDP', () => {
    it('asks the question and returns the decoded answer', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange(QUESTION, server.address, options);

      expect(result.transport).toBe('udp');
      expect(result.attempts).toBe(1);
      expect(result.server).toBe('127.0.0.1');
      expect(result.port).toBe(server.port);
      expect(result.message.answers).toHaveLength(1);
      expect([...result.message.answers[0].rdata]).toEqual([192, 0, 2, 1]);
      expect(result.bytes).toEqual(answerTo(result.query.bytes));
      expect(result.elapsed).toBeGreaterThan(0);

      expect(server.received).toHaveLength(1);
      expect(server.received[0].transport).toBe('udp');
      const sent = decodeMessage(server.received[0].query);
      expect(sent.questions).toEqual([{ name: 'example.com', type: 1, class: 1 }]);
      // nothing asked for: an ordinary recursive query, EDNS with the default payload size
      expect(sent.flags).toMatchObject({ rd: true, cd: false, ad: false });
      expect(result.query.flags).toEqual({ rd: true, cd: false, ad: false });
      expect(toDig(result)).toBe(`dig -p ${server.port} @127.0.0.1 example.com A`);
      expect(sent.edns).toMatchObject({ udpPayloadSize: 1232, dnssecOk: false });
    });

    it('sends the flags and EDNS settings it is given', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange(QUESTION, server.address, {
        ...options,
        checkingDisabled: true,
        authenticData: true,
        dnssecOk: true,
        udpPayloadSize: 4096,
      });
      const sent = decodeMessage(server.received[0].query);
      expect(sent.flags).toMatchObject({ rd: true, cd: true, ad: true });
      expect(sent.edns).toMatchObject({ udpPayloadSize: 4096, dnssecOk: true });
      expect(result.query.flags).toEqual({ rd: true, cd: true, ad: true });
      expect(result.query.edns).toEqual({ udpPayloadSize: 4096, dnssecOk: true });
    });

    it('gives the name it sent with no trailing dot, in the case it was written', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange({ name: 'Example.COM.', type: 'A' }, server.address, options);
      expect(result.query.name).toBe('Example.COM');
      expect(result.url).toBeUndefined();
    });

    it('can send a query with no EDNS at all', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange(QUESTION, server.address, { ...options, edns: false });
      expect(decodeMessage(server.received[0].query).edns).toBeUndefined();
      expect(result.query.edns).toBe(false);
    });

    it('takes the port from the server when one is written there', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange(QUESTION, `${server.address}:${server.port}`, {
        ...options,
        port: 1,
      });
      expect(result.port).toBe(server.port);
    });

    it('sends a Unicode name as punycode', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange({ name: 'münchen.de', type: 'A' }, server.address, options);
      expect(askedName(server.received[0].query)).toBe('xn--mnchen-3ya.de');
      expect(result.query.name).toBe('xn--mnchen-3ya.de');
    });

    it('uses a different random ID for each query', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const results = await Promise.all(
        Array.from({ length: 40 }, (_, index) =>
          exchange({ name: `host${index}.example.com`, type: 'A' }, server.address, options)
        )
      );
      // each got the answer to its own question
      results.forEach((result, index) => {
        expect(result.message.questions[0].name).toBe(`host${index}.example.com`);
      });
      expect(new Set(server.received.map(({ query }) => queryId(query))).size).toBeGreaterThan(30);
    });

    it('ignores a response that carries another ID', async () => {
      const options = await serve(({ query }) => ({
        response: withOtherId(answerTo(query)),
        keepId: true,
      }));
      await expect(exchange(QUESTION, server.address, options)).rejects.toBeInstanceOf(
        TimeoutError
      );
    });

    it('ignores a response from a different source address', async () => {
      const options = await serve(({ query }) => ({
        response: answerTo(query),
        fromOtherSource: true,
      }));
      await expect(exchange(QUESTION, server.address, options)).rejects.toBeInstanceOf(
        TimeoutError
      );
    });

    it('ignores a response to a different question', async () => {
      const other = encodeQuery({ id: 1, name: 'other.example', type: 'A' });
      const options = await serve(() => ({ response: answerTo(other) }));
      await expect(exchange(QUESTION, server.address, options)).rejects.toBeInstanceOf(
        TimeoutError
      );
    });

    it('ignores a datagram that is a query, not a response', async () => {
      const options = await serve(({ query }) => ({ response: query }));
      await expect(exchange(QUESTION, server.address, options)).rejects.toBeInstanceOf(
        TimeoutError
      );
    });

    it('matches names without regard to case', async () => {
      const options = await serve(({ query }) => ({
        response: answerTo(query, {
          questions: [{ name: 'EXAMPLE.com', type: 1, class: 1 }],
        }),
      }));
      const result = await exchange(QUESTION, server.address, options);
      expect(result.message.questions[0].name).toBe('EXAMPLE.com');
    });

    it.each(['udp', 'tcp'] as const)(
      'matches a name written with escapes to the response over %s',
      async transport => {
        const options = await serve(({ query }) => ({ response: answerTo(query) }));
        // \101 is "e": the same name as example.com on the wire
        const result = await exchange({ name: '\\101xample.COM', type: 'A' }, server.address, {
          ...options,
          transport,
        });
        expect(result.message.questions[0].name).toBe('example.COM');
        expect(result.message.answers).toHaveLength(1);
      }
    );

    it('accepts an error response that does not repeat the question', async () => {
      const options = await serve(({ query }) => ({
        response: answerTo(query, { rcode: 1, questions: [], answers: [] }),
      }));
      const result = await exchange(QUESTION, server.address, options);
      expect(result.message.rcode).toBe(1);
    });

    it('returns an error response as a response', async () => {
      const options = await serve(({ query }) => ({
        response: answerTo(query, { rcode: 3, answers: [] }),
      }));
      const result = await exchange(QUESTION, server.address, options);
      expect(result.message.rcode).toBe(3);
    });

    it('rejects a matching response that cannot be decoded', async () => {
      const options = await serve(({ query }) => {
        const broken = answerTo(query);
        // claim more answers than there are bytes for
        broken[7] = 9;
        return { response: broken };
      });
      const error = await exchange(QUESTION, server.address, options).catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.retryable).toBe(false);
      expect(error).toMatchObject({
        server: '127.0.0.1',
        query: 'example.com',
        type: 'A',
        transport: 'udp',
      });
    });

    it('times out when the server says nothing', async () => {
      const options = await serve(() => undefined);
      const error = await exchange(QUESTION, server.address, options).catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(error.retryable).toBe(true);
      expect(error.rcode).toBeUndefined();
      expect(error).toMatchObject({ server: '127.0.0.1', query: 'example.com', type: 'A' });
      expect(server.received).toHaveLength(1);
    });

    it('sends the same query again after a timeout, and takes the answer', async () => {
      let seen = 0;
      const options = await serve(({ query }) =>
        ++seen < 3 ? undefined : { response: answerTo(query) }
      );
      const result = await exchange(QUESTION, server.address, { ...options, retries: 2 });
      expect(result.attempts).toBe(3);
      expect(server.received).toHaveLength(3);
      // a retransmission, not a new query: an answer to any copy would do
      expect(new Set(server.received.map(({ query }) => queryId(query))).size).toBe(1);
    });

    it('takes a late answer to the first copy after retransmitting', async () => {
      let seen = 0;
      const options = await serve(({ query }) =>
        ++seen === 1 ? { response: answerTo(query), delayMs: 450 } : undefined
      );
      // the answer to the first copy lands in the middle of the second attempt's wait
      const result = await exchange(QUESTION, server.address, {
        ...options,
        timeout: 300,
        retries: 1,
      });
      expect(result.attempts).toBe(2);
    });

    it('gives up after the retries it was allowed', async () => {
      const options = await serve(() => undefined);
      await expect(
        exchange(QUESTION, server.address, { ...options, timeout: 60, retries: 2 })
      ).rejects.toBeInstanceOf(TimeoutError);
      expect(server.received).toHaveLength(3);
    });

    it('keeps every attempt inside the total timeout', async () => {
      const options = await serve(() => undefined);
      const started = Date.now();
      // a second of patience for each of three attempts, 100 ms for all of them
      const error = await exchange(QUESTION, server.address, {
        ...options,
        timeout: 1000,
        retries: 2,
        totalTimeout: 100,
      }).catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(Date.now() - started).toBeLessThan(180);
      // the first attempt used up the time, so there is no second
      expect(server.received).toHaveLength(1);
    });

    it('does not ask again when a timer fires before the clock reaches the deadline', async () => {
      const options = await serve(() => undefined);
      // a clock that runs slow, so the timer for the rest of the time fires with the
      // clock still short of the deadline, as a timer firing a millisecond early does
      const real = performance.now.bind(performance);
      const origin = real();
      const clock = vi
        .spyOn(performance, 'now')
        .mockImplementation(() => origin + (real() - origin) * 0.8);
      try {
        const error = await exchange(QUESTION, server.address, {
          ...options,
          timeout: 1000,
          retries: 2,
          totalTimeout: 50,
        }).catch(caught => caught);
        expect(error).toBeInstanceOf(TimeoutError);
        expect(server.received).toHaveLength(1);
      } finally {
        clock.mockRestore();
      }
    });

    it('asks again over TCP when the answer is truncated', async () => {
      const events: DnsEvent[] = [];
      const options = await serve(({ transport, query }) => ({
        response: transport === 'udp' ? truncated(answerTo(query)) : answerTo(query),
      }));
      const result = await exchange(QUESTION, server.address, {
        ...options,
        onEvent: event => events.push(event),
      });
      expect(result.transport).toBe('tcp');
      expect(result.attempts).toBe(2);
      expect(result.message.answers).toHaveLength(1);
      expect(server.received.map(({ transport }) => transport)).toEqual(['udp', 'tcp']);
      expect(events.map(({ event }) => event)).toEqual(['query', 'tcp-fallback', 'query']);
      expect(events[1]).toMatchObject({ reason: 'truncated', query: 'example.com', type: 'A' });
      expect(toDig(result)).toContain('+tcp');
    });

    it('returns the truncated answer when told not to fall back', async () => {
      const options = await serve(({ query }) => ({ response: truncated(answerTo(query)) }));
      const result = await exchange(QUESTION, server.address, { ...options, tcpFallback: false });
      expect(result.transport).toBe('udp');
      expect(result.message.flags.tc).toBe(true);
      expect(server.received).toHaveLength(1);
    });

    describe('when the TCP retry of a truncated answer fails', () => {
      // a truncated answer that still carries the one record it had room for
      const cut = (query: Uint8Array) =>
        answerTo(query, { flags: { qr: true, aa: true, tc: true, rd: true } });

      it('returns the truncated answer as it came, saying why TCP failed', async () => {
        const events: DnsEvent[] = [];
        // TCP:53 blocked: the query goes out and nothing comes back
        const options = await serve(({ transport, query }) =>
          transport === 'udp' ? { response: cut(query) } : undefined
        );
        const result = await exchange(QUESTION, server.address, {
          ...options,
          onEvent: event => events.push(event),
        });
        expect(result.transport).toBe('udp');
        expect(result.message.flags.tc).toBe(true);
        expect(result.message.answers).toHaveLength(1);
        expect(result.attempts).toBe(2);
        expect(result.tcpFallbackError).toMatchObject({ name: 'TimeoutError', retryable: true });
        // the query is the UDP one the answer came back to
        expect(result.query.id).toBe(queryId(server.received[0].query));
        expect(toDig(result)).not.toContain('+tcp');
        expect(server.received.map(({ transport }) => transport)).toEqual(['udp', 'tcp']);
        expect(events.map(({ event }) => event)).toEqual([
          'query',
          'tcp-fallback',
          'query',
          'tcp-fallback-failed',
        ]);
        expect(events[2]).toMatchObject({ transport: 'tcp', error: { name: 'TimeoutError' } });
        expect(events[3]).toMatchObject({
          server: '127.0.0.1',
          query: 'example.com',
          type: 'A',
          error: { name: 'TimeoutError' },
        });
      });

      it('returns it when the TCP connection closes without an answer', async () => {
        const options = await serve(({ transport, query }) =>
          transport === 'udp'
            ? { response: cut(query) }
            : { response: answerTo(query), closeAfterBytes: 0 }
        );
        const result = await exchange(QUESTION, server.address, options);
        expect(result.message.flags.tc).toBe(true);
        expect(result.tcpFallbackError?.name).toMatch(/EmptyResponseError|ConnectionError/);
      });

      it('returns the empty truncated answer too, TC set', async () => {
        const options = await serve(({ transport, query }) =>
          transport === 'udp' ? { response: truncated(answerTo(query)) } : undefined
        );
        const result = await exchange(QUESTION, server.address, options);
        expect(result.message.flags.tc).toBe(true);
        expect(result.message.answers).toHaveLength(0);
        expect(result.tcpFallbackError?.name).toBe('TimeoutError');
      });

      it('returns it when the TCP retry runs into the total timeout', async () => {
        const options = await serve(({ transport, query }) =>
          transport === 'udp' ? { response: cut(query) } : undefined
        );
        const started = Date.now();
        const result = await exchange(QUESTION, server.address, {
          ...options,
          timeout: 1000,
          retries: 2,
          totalTimeout: 100,
        });
        expect(Date.now() - started).toBeLessThan(180);
        expect(result.message.flags.tc).toBe(true);
        expect(result.tcpFallbackError?.name).toBe('TimeoutError');
        // the TCP query was not sent again: there was no time for it
        expect(server.received.map(({ transport }) => transport)).toEqual(['udp', 'tcp']);
      });

      it('returns it when there is no time left to ask over TCP at all', async () => {
        const events: DnsEvent[] = [];
        // the clock jumps past the deadline while the UDP answer is on its way
        const real = performance.now.bind(performance);
        let skipped = 0;
        const clock = vi.spyOn(performance, 'now').mockImplementation(() => real() + skipped);
        try {
          const options = await serve(({ query }) => {
            skipped = 10_000;
            return { response: cut(query) };
          });
          const result = await exchange(QUESTION, server.address, {
            ...options,
            totalTimeout: 1000,
            onEvent: event => events.push(event),
          });
          expect(result.message.flags.tc).toBe(true);
          expect(result.tcpFallbackError?.name).toBe('TimeoutError');
          expect(server.received.map(({ transport }) => transport)).toEqual(['udp']);
          expect(events.map(({ event }) => event)).toEqual(['query', 'tcp-fallback-failed']);
        } finally {
          clock.mockRestore();
        }
      });

      it('retries TCP as it would any query before giving up on it', async () => {
        const options = await serve(({ transport, query }) =>
          transport === 'udp' ? { response: cut(query) } : undefined
        );
        const result = await exchange(QUESTION, server.address, {
          ...options,
          timeout: 50,
          retries: 1,
        });
        expect(result.tcpFallbackError?.name).toBe('TimeoutError');
        expect(result.attempts).toBe(3);
        expect(server.received.map(({ transport }) => transport)).toEqual(['udp', 'tcp', 'tcp']);
      });

      it('still rejects with the reason when the caller aborts during the TCP retry', async () => {
        const options = await serve(({ transport, query }) =>
          transport === 'udp' ? { response: cut(query) } : undefined
        );
        const controller = new AbortController();
        const reason = new Error('never mind');
        const pending = exchange(QUESTION, server.address, {
          ...options,
          timeout: 5000,
          signal: controller.signal,
        });
        setTimeout(() => controller.abort(reason), 30);
        await expect(pending).rejects.toBe(reason);
      });
    });
  });

  describe('over TCP', () => {
    const tcp = (options: ExchangeOptions): ExchangeOptions => ({ ...options, transport: 'tcp' });

    it('asks the question and returns the decoded answer', async () => {
      const options = tcp(await serve(({ query }) => ({ response: answerTo(query) })));
      const result = await exchange(QUESTION, server.address, options);
      expect(result.transport).toBe('tcp');
      expect(result.message.answers).toHaveLength(1);
      expect(server.received[0].transport).toBe('tcp');
    });

    it('reassembles an answer that arrives a byte at a time', async () => {
      const options = tcp(
        await serve(({ query }) => ({ response: answerTo(query), chunkBytes: 1 }))
      );
      const result = await exchange(QUESTION, server.address, { ...options, timeout: 2000 });
      expect(result.bytes).toEqual(answerTo(result.query.bytes));
    });

    it('gives each query a connection of its own by default', async () => {
      const options = tcp(await serve(({ query }) => ({ response: answerTo(query) })));
      await Promise.all(
        Array.from({ length: 4 }, (_, index) =>
          exchange({ name: `host${index}.example.com`, type: 'A' }, server.address, options)
        )
      );
      await exchange(QUESTION, server.address, options);
      // what dig does, and what every server can cope with
      expect(server.tcpConnections).toBe(5);
    });

    it('is not held up by a server that answers only the first query on a connection', async () => {
      // the first query on each connection is answered, the rest are ignored, and the
      // connection stays open: what some large authoritative servers do
      const seen = new Map<string, number>();
      const options = tcp(
        await serve(({ query }) => {
          const connection = String(server.tcpConnections);
          const count = (seen.get(connection) ?? 0) + 1;
          seen.set(connection, count);
          return count === 1 ? { response: answerTo(query) } : undefined;
        })
      );
      for (let index = 0; index < 3; index++) {
        const result = await exchange(QUESTION, server.address, options);
        expect(result.attempts).toBe(1);
      }
    });

    describe('with pipelining on', () => {
      beforeEach(() => {
        transports.close();
        transports = createTransports({ pipeline: true });
      });

      it('pipelines a burst of queries over one connection', async () => {
        const options = tcp(await serve(({ query }) => ({ response: answerTo(query) })));
        const results = await Promise.all(
          Array.from({ length: 25 }, (_, index) =>
            exchange({ name: `host${index}.example.com`, type: 'A' }, server.address, options)
          )
        );
        results.forEach((result, index) => {
          expect(result.message.questions[0].name).toBe(`host${index}.example.com`);
        });
        expect(server.tcpConnections).toBe(1);
      });

      it('matches answers that come back out of order', async () => {
        const options = tcp(
          await serve(({ query }) => ({
            response: answerTo(query),
            delayMs: askedName(query) === 'slow.example.com' ? 60 : 0,
          }))
        );
        const [slow, fast] = await Promise.all([
          exchange({ name: 'slow.example.com', type: 'A' }, server.address, options),
          exchange({ name: 'fast.example.com', type: 'A' }, server.address, options),
        ]);
        expect(slow.message.questions[0].name).toBe('slow.example.com');
        expect(fast.message.questions[0].name).toBe('fast.example.com');
        expect(fast.elapsed).toBeLessThan(slow.elapsed);
      });

      it('reuses the connection for a later query', async () => {
        const options = tcp(await serve(({ query }) => ({ response: answerTo(query) })));
        await exchange(QUESTION, server.address, options);
        await exchange(QUESTION, server.address, options);
        expect(server.tcpConnections).toBe(1);
      });

      it('opens a connection per query when the idle timeout is zero', async () => {
        const options = tcp(await serve(({ query }) => ({ response: answerTo(query) })));
        const own = createTransports({ pipeline: true, idleTimeout: 0 });
        try {
          await exchange(QUESTION, server.address, { ...options, transports: own });
          await exchange(QUESTION, server.address, { ...options, transports: own });
        } finally {
          own.close();
        }
        expect(server.tcpConnections).toBe(2);
      });

      it('sends a query again when a reused connection turns out to be closed', async () => {
        // answer, then close: the next query finds the connection gone
        const options = tcp(
          await serve(({ query }) => ({ response: answerTo(query), closeAfterBytes: 0xffff }))
        );
        const first = await exchange(QUESTION, server.address, options);
        const second = await exchange(QUESTION, server.address, options);
        expect(first.attempts).toBe(1);
        expect(second.attempts).toBe(1);
        expect(second.message.answers).toHaveLength(1);
      });

      it('recovers when a server closes on pipelined queries', async () => {
        // one answer per connection, however many queries were sent on it
        const options = tcp(
          await serve(({ query }) => ({ response: answerTo(query), closeAfterBytes: 0xffff }))
        );
        const results = await Promise.all(
          Array.from({ length: 6 }, (_, index) =>
            exchange({ name: `host${index}.example.com`, type: 'A' }, server.address, options)
          )
        );
        results.forEach((result, index) => {
          expect(result.message.questions[0].name).toBe(`host${index}.example.com`);
        });
        // and from then on that server gets one query per connection
        const before = server.tcpConnections;
        await Promise.all([
          exchange(QUESTION, server.address, options),
          exchange(QUESTION, server.address, options),
        ]);
        expect(server.tcpConnections - before).toBe(2);
      });
    });

    it('reports a connection closed without an answer', async () => {
      const options = tcp(
        await serve(({ query }) => ({ response: answerTo(query), closeAfterBytes: 0 }))
      );
      const error = await exchange(QUESTION, server.address, options).catch(caught => caught);
      expect(error).toBeInstanceOf(EmptyResponseError);
      expect(error.retryable).toBe(true);
      expect(error.transport).toBe('tcp');
    });

    it('reports a connection closed in the middle of an answer', async () => {
      const options = tcp(
        await serve(({ query }) => ({ response: answerTo(query), closeAfterBytes: 10 }))
      );
      const error = await exchange(QUESTION, server.address, options).catch(caught => caught);
      expect(error).toBeInstanceOf(ConnectionError);
      expect(error.message).toContain('mid-response');
    });

    it('tries again after a dropped connection', async () => {
      let seen = 0;
      const options = tcp(
        await serve(({ query }) =>
          ++seen === 1
            ? { response: answerTo(query), closeAfterBytes: 0 }
            : { response: answerTo(query) }
        )
      );
      const result = await exchange(QUESTION, server.address, { ...options, retries: 1 });
      expect(result.attempts).toBe(2);
      // a new query, not a retransmission
      const ids = server.received.map(({ query }) => queryId(query));
      expect(ids[0]).not.toBe(ids[1]);
    });

    it('reports a refused connection', async () => {
      const options = tcp(await serve(() => undefined));
      const { port } = server;
      await server.close();
      const error = await exchange(QUESTION, server.address, { ...options, port }).catch(
        caught => caught
      );
      expect(error).toBeInstanceOf(ConnectionError);
      expect(error.retryable).toBe(true);
    });

    it('times out when the server says nothing', async () => {
      const options = tcp(await serve(() => undefined));
      await expect(exchange(QUESTION, server.address, options)).rejects.toBeInstanceOf(
        TimeoutError
      );
    });

    it('rejects a response to a different question', async () => {
      const other = encodeQuery({ id: 1, name: 'other.example', type: 'A' });
      const options = tcp(await serve(() => ({ response: answerTo(other) })));
      const error = await exchange(QUESTION, server.address, options).catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.message).toContain('different question');
    });

    it('rejects a truncated answer, with nowhere larger to go', async () => {
      const options = tcp(await serve(({ query }) => ({ response: truncated(answerTo(query)) })));
      const error = await exchange(QUESTION, server.address, options).catch(caught => caught);
      expect(error).toBeInstanceOf(TruncatedError);
      expect(error.retryable).toBe(false);
      expect(error.rcodeName).toBe('NOERROR');
    });
  });

  describe('a server that does not speak EDNS', () => {
    // answers FORMERR, with no EDNS record, to any query that carries one (RFC 6891 §7)
    const old: Responder = ({ query }) => {
      const asked = decodeMessage(query);
      if (asked.edns) {
        return { response: answerTo(query, { rcode: 1, answers: [], flags: { qr: true } }) };
      }
      return { response: answerTo(query) };
    };

    it('is asked again without EDNS, and the plain query is what the result reports', async () => {
      const events: DnsEvent[] = [];
      const options = await serve(old);
      const result = await exchange(QUESTION, server.address, {
        ...options,
        onEvent: event => events.push(event),
      });

      expect(result.message.rcode).toBe(0);
      expect(result.message.answers).toHaveLength(1);
      expect(result.query.edns).toBe(false);
      expect(result.attempts).toBe(2);
      expect(server.received.map(({ query }) => Boolean(decodeMessage(query).edns))).toEqual([
        true,
        false,
      ]);
      expect(events.find(event => event.event === 'retry')).toMatchObject({
        error: { message: expect.stringContaining('without it') },
      });
    });

    it('is not asked again when the query needs EDNS', async () => {
      const options = await serve(old);
      const result = await exchange(QUESTION, server.address, { ...options, dnssecOk: true });
      expect(result.message.rcode).toBe(1);
      expect(server.received).toHaveLength(1);
    });

    it('is not asked again when the FORMERR carries an EDNS record', async () => {
      const options = await serve(({ query }) => ({
        response: answerTo(query, {
          rcode: 1,
          answers: [],
          edns: { udpPayloadSize: 1232, version: 0, dnssecOk: false, options: [] },
        }),
      }));
      const result = await exchange(QUESTION, server.address, options);
      expect(result.message.rcode).toBe(1);
      expect(server.received).toHaveLength(1);
    });
  });

  describe('before the network', () => {
    it('rejects a type it does not know', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      await expect(
        exchange({ name: 'example.com', type: 'NOPE' }, server.address, options)
      ).rejects.toBeInstanceOf(InvalidQueryError);
      expect(server.received).toHaveLength(0);
    });

    it('rejects a name that cannot be encoded', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const error = await exchange(
        { name: `${'a'.repeat(64)}.example.com`, type: 'A' },
        server.address,
        options
      ).catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidQueryError);
      expect(error.retryable).toBe(false);
      expect(server.received).toHaveLength(0);
    });
  });

  describe('cancelling', () => {
    it('rejects with the reason when the signal is already aborted', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const reason = new Error('never mind');
      await expect(
        exchange(QUESTION, server.address, { ...options, signal: AbortSignal.abort(reason) })
      ).rejects.toBe(reason);
      expect(server.received).toHaveLength(0);
    });

    it.each(['udp', 'tcp'] as const)(
      'stops waiting when the signal aborts over %s',
      async transport => {
        const options = await serve(() => undefined);
        const controller = new AbortController();
        const reason = new Error('never mind');
        const pending = exchange(QUESTION, server.address, {
          ...options,
          transport,
          timeout: 5000,
          retries: 3,
          signal: controller.signal,
        });
        setTimeout(() => controller.abort(reason), 30);
        await expect(pending).rejects.toBe(reason);
        // an abort is not a failure to retry
        expect(server.received).toHaveLength(1);
      }
    );

    it('leaves no listener on the signal', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const controller = new AbortController();
      const added = vi.spyOn(controller.signal, 'addEventListener');
      const removed = vi.spyOn(controller.signal, 'removeEventListener');
      await exchange(QUESTION, server.address, { ...options, signal: controller.signal });
      await exchange(QUESTION, server.address, {
        ...options,
        transport: 'tcp',
        signal: controller.signal,
      });
      expect(added).toHaveBeenCalledTimes(2);
      expect(removed).toHaveBeenCalledTimes(2);
      for (const [type, listener] of added.mock.calls) {
        expect(removed).toHaveBeenCalledWith(type, listener);
      }
    });
  });

  describe('events', () => {
    it('reports one query event per attempt, failures included', async () => {
      const events: DnsEvent[] = [];
      let seen = 0;
      const options = await serve(({ query }) =>
        ++seen === 1 ? undefined : { response: answerTo(query, { rcode: 3, answers: [] }) }
      );
      await exchange(QUESTION, server.address, {
        ...options,
        retries: 1,
        onEvent: event => events.push(event),
      });

      expect(events.map(({ event }) => event)).toEqual(['query', 'retry', 'query']);
      expect(events[0]).toMatchObject({
        event: 'query',
        server: '127.0.0.1',
        port: server.port,
        query: 'example.com',
        type: 'A',
        transport: 'udp',
        attempt: 1,
        error: { name: 'TimeoutError', retryable: true },
      });
      expect(events[1]).toMatchObject({
        event: 'retry',
        attempt: 2,
        error: { name: 'TimeoutError' },
      });
      expect(events[2]).toMatchObject({
        event: 'query',
        attempt: 2,
        rcode: 3,
        rcodeName: 'NXDOMAIN',
        truncated: false,
      });
      expect(events[2]).not.toHaveProperty('error');
      expect((events[2] as { bytesReceived: number }).bytesReceived).toBeGreaterThan(12);
    });
  });

  describe('toDig', () => {
    it('writes the command that asks the same question the same way', async () => {
      const options = await serve(({ query }) => ({ response: answerTo(query) }));
      const result = await exchange({ name: 'example.com', type: 'DNSKEY' }, server.address, {
        ...options,
        transport: 'tcp',
        recursionDesired: false,
        checkingDisabled: true,
        dnssecOk: true,
      });
      expect(toDig(result)).toBe(
        `dig +dnssec +cd +norecurse +tcp -p ${server.port} @127.0.0.1 example.com DNSKEY`
      );
    });
  });
});

describe('digCommand', () => {
  it('prints the dig command that asks the same question', () => {
    expect(
      digCommand({ name: 'example.com', type: 'DNSKEY' }, '199.43.135.53', {
        transport: 'tcp',
        recursionDesired: false,
        checkingDisabled: true,
        dnssecOk: true,
      })
    ).toBe('dig +dnssec +cd +norecurse +tcp @199.43.135.53 example.com DNSKEY');
  });

  it('asks a recursive resolver plainly', () => {
    expect(digCommand({ name: 'example.com', type: 'mx' }, '1.1.1.1')).toBe(
      'dig @1.1.1.1 example.com MX'
    );
  });

  it('covers the other transports, ports, and EDNS settings', () => {
    expect(
      digCommand({ name: '.', type: 'NS' }, '9.9.9.9', {
        transport: 'tls',
        recursionDesired: false,
      })
    ).toBe('dig +norecurse +tls @9.9.9.9 . NS');
    expect(
      digCommand({ name: 'example.com', type: 'A' }, 'https://dns.example/custom', {
        authenticData: true,
      })
    ).toBe('dig +adflag @dns.example example.com A');
    expect(
      digCommand({ name: 'example.com', type: 'A' }, 'https://dns.example/custom', {
        transport: 'doh',
      })
    ).toBe('dig +https=/custom @dns.example example.com A');
    expect(
      digCommand({ name: 'example.com', type: 'A' }, '[2001:db8::1]:5353', {
        udpPayloadSize: 4096,
      })
    ).toBe('dig +bufsize=4096 -p 5353 @2001:db8::1 example.com A');
    expect(
      digCommand({ name: 'example.com', type: 'TXT', class: 'CH' }, '192.0.2.1', {
        edns: false,
      })
    ).toBe('dig +noedns @192.0.2.1 example.com TXT CH');
  });
});
