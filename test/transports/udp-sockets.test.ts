import { Socket } from 'node:dgram';
import { TimeoutError } from '../../src/errors';
import { exchange } from '../../src/exchange';
import { createUdpTransport } from '../../src/transports/index';
import type { Transport } from '../../src/transports/types';
import { encodeQuery } from '../../src/wire/index';
import { answerTo } from '../support/answers';
import { startFixtureServer } from '../support/fixture-server';
import type { FixtureServer } from '../support/fixture-server';

// a fresh source port per query, so an off-path attacker forging an answer has to guess the
// port as well as the ID (RFC 5452), and no socket outlives the query it was opened for

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const query = (id: number) => encodeQuery({ id, name: 'example.com', type: 'A' });

describe('UDP sockets', () => {
  let server: FixtureServer;
  let transport: Transport;
  // every socket that sends a query to `target`, and whether it has closed since. The
  // fixture server's sockets send only to the client, so they are not counted
  let sockets: { socket: Socket; closed: boolean }[] = [];
  let target = -1;

  beforeEach(() => {
    sockets = [];
    const send = Socket.prototype.send;
    vi.spyOn(Socket.prototype, 'send').mockImplementation(function (
      this: Socket,
      ...args: unknown[]
    ) {
      if (args[1] === target && !sockets.some(entry => entry.socket === this)) {
        const entry = { socket: this, closed: false };
        this.once('close', () => {
          entry.closed = true;
        });
        sockets.push(entry);
      }
      return (send as (...rest: unknown[]) => void).apply(this, args);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function serve(...args: Parameters<typeof startFixtureServer>) {
    server = await startFixtureServer(...args);
    target = server.port;
  }

  const ours = () => sockets;
  // closing is asynchronous: give the close events a moment to land
  const allClosed = async () => {
    await sleep(10);
    return ours().length > 0 && ours().every(entry => entry.closed);
  };

  it('sends each query from a socket of its own, on its own port', async () => {
    await serve(({ query: asked }) => ({
      response: answerTo(asked),
      delayMs: 20,
    }));
    transport = createUdpTransport();
    const endpoint = { host: server.address, port: server.port };
    await Promise.all([1, 2, 3, 4, 5, 6].map(id => transport.send({ endpoint, query: query(id) })));

    const ports = server.received.map(received => received.sourcePort);
    expect(new Set(ports).size).toBe(6);
    expect(ours()).toHaveLength(6);
    expect(await allClosed()).toBe(true);
  });

  it('closes the socket when the query is answered, aborted or the transport closes', async () => {
    await serve(({ query: asked }) => (asked[1] === 1 ? { response: answerTo(asked) } : undefined));
    transport = createUdpTransport();
    const endpoint = { host: server.address, port: server.port };

    await transport.send({ endpoint, query: query(1) });
    expect(ours()).toHaveLength(1);
    expect(await allClosed()).toBe(true);

    const giveUp = new AbortController();
    const aborted = transport.send({ endpoint, query: query(2), signal: giveUp.signal });
    await sleep(20);
    giveUp.abort(new Error('given up'));
    await expect(aborted).rejects.toThrow('given up');
    expect(ours()).toHaveLength(2);
    expect(await allClosed()).toBe(true);

    const cut = transport.send({ endpoint, query: query(3) });
    await sleep(20);
    transport.close();
    await expect(cut).rejects.toThrow('closed');
    expect(ours()).toHaveLength(3);
    expect(await allClosed()).toBe(true);
  });

  it('closes the socket when sending fails', async () => {
    await serve(() => undefined);
    target = 0;
    transport = createUdpTransport();
    // nothing can be sent to port 0
    await expect(
      transport.send({ endpoint: { host: '127.0.0.1', port: 0 }, query: query(4) })
    ).rejects.toThrow();
    expect(await allClosed()).toBe(true);
  });

  it('keeps one socket for an exchange, so a retransmission comes from the same port', async () => {
    await serve(() => undefined);
    transport = createUdpTransport();
    const transports = { get: () => transport, close() {} };
    const error = await exchange({ name: 'example.com', type: 'A' }, server.address, {
      port: server.port,
      transports,
      timeout: 40,
      retries: 2,
    }).catch(caught => caught);

    expect(error).toBeInstanceOf(TimeoutError);
    expect(server.received).toHaveLength(3);
    expect(new Set(server.received.map(received => received.sourcePort)).size).toBe(1);
    expect(ours()).toHaveLength(1);
    // the exchange is over, and its socket with it
    expect(await allClosed()).toBe(true);
  });

  it('moves to a new port for the next exchange', async () => {
    await serve(({ query: asked }) => ({ response: answerTo(asked) }));
    transport = createUdpTransport();
    const transports = { get: () => transport, close() {} };
    const options = { port: server.port, transports };
    await Promise.all([
      exchange({ name: 'example.com', type: 'A' }, server.address, options),
      exchange({ name: 'example.com', type: 'AAAA' }, server.address, options),
    ]);
    expect(new Set(server.received.map(received => received.sourcePort)).size).toBe(2);
    expect(await allClosed()).toBe(true);
  });
});
