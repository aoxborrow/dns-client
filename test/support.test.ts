import dgram from 'node:dgram';
import net from 'node:net';
import {
  recordedResponder,
  startFixtureServer,
  truncated,
  withOtherId,
  type FixtureServer,
  type Responder,
} from './support/fixture-server';
import {
  socketReader,
  startHttpConnectMock,
  startSocks5Mock,
  type ProxyMock,
} from './support/proxy-mocks';

// tests for the test servers themselves. The transports and the proxy tunnel are tested
// against these, so a mock that misbehaves by accident would hide a real bug

// ---- the smallest possible DNS messages: a header and one question

function buildQuery(id: number, name: string, qtype = 1): Uint8Array {
  const labels = name.split('.').flatMap(label => [label.length, ...Buffer.from(label, 'latin1')]);
  const message = Buffer.from([
    0,
    0,
    0x01,
    0x00,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    ...labels,
    0,
    0,
    qtype,
    0,
    1,
  ]);
  message.writeUInt16BE(id, 0);
  return Uint8Array.from(message);
}

// the query echoed back with the response bit set, under a different ID
function buildResponse(query: Uint8Array, id: number): Uint8Array {
  const message = Buffer.from(query);
  message.writeUInt16BE(id, 0);
  message[2] |= 0x80; // QR
  return Uint8Array.from(message);
}

const idOf = (message: Uint8Array) => Buffer.from(message).readUInt16BE(0);

// ---- raw clients

interface Datagram {
  message: Buffer;
  port: number;
}

function udpAsk(port: number, payload: Uint8Array, waitMs = 300): Promise<Datagram | undefined> {
  return new Promise(resolve => {
    const socket = dgram.createSocket('udp4');
    const done = (result?: Datagram) => {
      clearTimeout(timer);
      socket.close();
      resolve(result);
    };
    const timer = setTimeout(() => done(), waitMs);
    socket.on('message', (message, remote) => done({ message, port: remote.port }));
    socket.send(payload, port, '127.0.0.1');
  });
}

function open(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('error', reject);
    socket.once('connect', () => resolve(socket));
  });
}

const framed = (message: Uint8Array) => {
  const out = Buffer.alloc(2 + message.length);
  out.writeUInt16BE(message.length, 0);
  out.set(message, 2);
  return out;
};

// one DNS exchange over an open stream: length prefix, then the message
async function askOver(socket: net.Socket, query: Uint8Array): Promise<Buffer> {
  const input = socketReader(socket);
  socket.write(framed(query));
  const length = (await input.take(2)).readUInt16BE(0);
  const response = await input.take(length);
  input.release();
  return response;
}

const portBytes = (port: number) => [port >> 8, port & 0xff];

// ---------------------------------------------------------------------------

describe('fixture server', () => {
  let server: FixtureServer;
  let respond: Responder;

  beforeEach(async () => {
    respond = ({ query }) => ({ response: buildResponse(query, 0x1111) });
    server = await startFixtureServer(received => respond(received));
  });
  afterEach(() => server.close());

  it('answers over UDP with the ID of the query', async () => {
    const reply = await udpAsk(server.port, buildQuery(0xbeef, 'example.com'));
    expect(reply && idOf(reply.message)).toBe(0xbeef);
    expect(reply?.port).toBe(server.port);
    expect(server.received).toHaveLength(1);
    expect(server.received[0].transport).toBe('udp');
  });

  it('keeps the response ID when asked to', async () => {
    respond = ({ query }) => ({ response: buildResponse(query, 0x1111), keepId: true });
    const reply = await udpAsk(server.port, buildQuery(0xbeef, 'example.com'));
    expect(reply && idOf(reply.message)).toBe(0x1111);
  });

  it('stays silent when the responder returns nothing', async () => {
    respond = () => undefined;
    expect(await udpAsk(server.port, buildQuery(1, 'example.com'), 150)).toBeUndefined();
    expect(server.received).toHaveLength(1);
  });

  it('can reply from a different source port', async () => {
    respond = ({ query }) => ({ response: buildResponse(query, 1), fromOtherSource: true });
    const reply = await udpAsk(server.port, buildQuery(1, 'example.com'));
    expect(reply).toBeDefined();
    expect(reply?.port).not.toBe(server.port);
  });

  it('delays a reply', async () => {
    respond = ({ query }) => ({ response: buildResponse(query, 1), delayMs: 120 });
    const started = Date.now();
    expect(await udpAsk(server.port, buildQuery(1, 'example.com'), 500)).toBeDefined();
    expect(Date.now() - started).toBeGreaterThanOrEqual(100);
  });

  it('answers several queries on one TCP connection', async () => {
    const socket = await open(server.port);
    const first = await askOver(socket, buildQuery(0x0101, 'one.example'));
    const second = await askOver(socket, buildQuery(0x0202, 'two.example'));
    socket.destroy();
    expect(idOf(first)).toBe(0x0101);
    expect(idOf(second)).toBe(0x0202);
    expect(server.received.map(entry => entry.transport)).toEqual(['tcp', 'tcp']);
  });

  it('delivers a TCP response in pieces', async () => {
    respond = ({ query }) => ({ response: buildResponse(query, 1), chunkBytes: 3 });
    const query = buildQuery(0x0303, 'pieces.example');
    const socket = await open(server.port);
    const response = await askOver(socket, query);
    socket.destroy();
    expect(response).toEqual(Buffer.from(buildResponse(query, 0x0303)));
  });

  it('closes a TCP connection part-way through a response', async () => {
    respond = ({ query }) => ({ response: buildResponse(query, 1), closeAfterBytes: 5 });
    const socket = await open(server.port);
    const chunks: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => chunks.push(chunk));
    socket.write(framed(buildQuery(1, 'cut.example')));
    await new Promise(resolve => socket.once('close', resolve));
    expect(Buffer.concat(chunks)).toHaveLength(5);
  });
});

describe('fixture server shutdown', () => {
  it('cancels delayed replies on close instead of sending into closed sockets', async () => {
    const server = await startFixtureServer(({ query }) => ({
      response: buildResponse(query, 1),
      delayMs: 80,
    }));
    const uncaught: Error[] = [];
    const onUncaught = (error: Error) => uncaught.push(error);
    process.on('uncaughtException', onUncaught);
    try {
      expect(await udpAsk(server.port, buildQuery(1, 'example.com'), 20)).toBeUndefined();
      await server.close();
      // outlast the delay the cancelled reply would have fired after
      await new Promise(resolve => setTimeout(resolve, 150));
      expect(uncaught).toEqual([]);
    } finally {
      process.off('uncaughtException', onUncaught);
    }
  });
});

describe('fixture server helpers', () => {
  it('replays recorded exchanges whatever their IDs, and drops unknown queries', async () => {
    const recordedQuery = buildQuery(0x7777, 'recorded.example');
    const recordedResponse = buildResponse(recordedQuery, 0x7777);
    const server = await startFixtureServer(
      recordedResponder([
        {
          query: Buffer.from(recordedQuery).toString('base64'),
          response: Buffer.from(recordedResponse).toString('base64'),
        },
      ])
    );
    try {
      const known = await udpAsk(server.port, buildQuery(0x0042, 'recorded.example'));
      expect(known && idOf(known.message)).toBe(0x0042);
      expect(await udpAsk(server.port, buildQuery(1, 'unknown.example'), 150)).toBeUndefined();
    } finally {
      await server.close();
    }
  });

  it('marks a response truncated and empties it', () => {
    const response = buildResponse(buildQuery(9, 'example.com'), 9);
    const cut = truncated(response);
    expect(cut).toHaveLength(12);
    expect(cut[2] & 0x02).toBe(0x02);
    expect([...cut.subarray(4, 12)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(idOf(cut)).toBe(9);
  });

  it('changes a response ID', () => {
    const response = buildResponse(buildQuery(9, 'example.com'), 9);
    expect(idOf(withOtherId(response))).not.toBe(9);
    expect(withOtherId(response).subarray(2)).toEqual(response.subarray(2));
  });
});

// ---------------------------------------------------------------------------

describe('SOCKS5 mock', () => {
  let dns: FixtureServer;
  let proxy: ProxyMock;

  beforeEach(async () => {
    dns = await startFixtureServer(({ query }) => ({ response: buildResponse(query, 1) }));
  });
  afterEach(async () => {
    await proxy.close();
    await dns.close();
  });

  // greeting, optional username/password, then a request; returns the 10-byte reply
  async function handshake(
    socket: net.Socket,
    command: number,
    port: number,
    credentials?: { username: string; password: string }
  ): Promise<{ authStatus?: number; reply?: Buffer }> {
    const input = socketReader(socket);
    try {
      socket.write(Buffer.from([5, 1, credentials ? 2 : 0]));
      await input.take(2);
      let authStatus: number | undefined;
      if (credentials) {
        const user = Buffer.from(credentials.username);
        const pass = Buffer.from(credentials.password);
        socket.write(Buffer.from([1, user.length, ...user, pass.length, ...pass]));
        authStatus = (await input.take(2))[1];
        if (authStatus !== 0) return { authStatus };
      }
      socket.write(Buffer.from([5, command, 0, 1, 127, 0, 0, 1, ...portBytes(port)]));
      return { authStatus, reply: await input.take(10) };
    } finally {
      input.release();
    }
  }

  it('tunnels a TCP exchange to the target', async () => {
    proxy = await startSocks5Mock();
    const socket = await open(proxy.port);
    const { reply } = await handshake(socket, 1, dns.port);
    expect(reply?.[1]).toBe(0);

    const response = await askOver(socket, buildQuery(0x5151, 'via-socks.example'));
    socket.destroy();
    expect(idOf(response)).toBe(0x5151);
    expect(dns.received).toHaveLength(1);
    expect(proxy.requests).toEqual([{ command: 'connect', host: '127.0.0.1', port: dns.port }]);
  });

  it('accepts the right credentials and records them', async () => {
    const credentials = { username: 'alice', password: 'hunter22' };
    proxy = await startSocks5Mock({ auth: credentials });
    const socket = await open(proxy.port);
    const { authStatus, reply } = await handshake(socket, 1, dns.port, credentials);
    socket.destroy();
    expect(authStatus).toBe(0);
    expect(reply?.[1]).toBe(0);
    expect(proxy.requests[0]).toMatchObject(credentials);
  });

  it('rejects the wrong credentials before any request', async () => {
    proxy = await startSocks5Mock({ auth: { username: 'alice', password: 'hunter22' } });
    const socket = await open(proxy.port);
    const { authStatus } = await handshake(socket, 1, dns.port, {
      username: 'alice',
      password: 'no',
    });
    socket.destroy();
    expect(authStatus).toBe(1);
    expect(proxy.requests).toEqual([]);
  });

  it('refuses a connection with the reply code it was given', async () => {
    proxy = await startSocks5Mock({ refuseWith: 0x05 });
    const socket = await open(proxy.port);
    const { reply } = await handshake(socket, 1, dns.port);
    socket.destroy();
    expect(reply?.[1]).toBe(0x05);
    expect(dns.received).toEqual([]);
  });

  it('reports a target it cannot reach', async () => {
    proxy = await startSocks5Mock();
    // a port nothing listens on: bind one, note it, release it
    const spare = net.createServer();
    const closedPort = await new Promise<number>(resolve =>
      spare.listen(0, '127.0.0.1', () => resolve((spare.address() as net.AddressInfo).port))
    );
    await new Promise(resolve => spare.close(resolve));

    const socket = await open(proxy.port);
    const { reply } = await handshake(socket, 1, closedPort);
    socket.destroy();
    expect(reply?.[1]).toBe(0x05);
  });

  it('relays UDP when it offers UDP ASSOCIATE', async () => {
    proxy = await startSocks5Mock({ udpAssociate: true });
    const control = await open(proxy.port);
    const { reply } = await handshake(control, 3, 0);
    expect(reply?.[1]).toBe(0);
    const relayPort = reply!.readUInt16BE(8);

    const query = buildQuery(0x6161, 'udp-via-socks.example');
    const wrapped = Buffer.from([0, 0, 0, 1, 127, 0, 0, 1, ...portBytes(dns.port), ...query]);
    const datagram = await udpAsk(relayPort, wrapped);
    control.destroy();

    // the relay wraps the answer in the same header, naming the target as the source
    expect(datagram).toBeDefined();
    expect(datagram!.message.readUInt16BE(8)).toBe(dns.port);
    expect(idOf(datagram!.message.subarray(10))).toBe(0x6161);
    expect(dns.received[0].transport).toBe('udp');
  });

  it('says so when it does not offer UDP ASSOCIATE', async () => {
    proxy = await startSocks5Mock();
    const control = await open(proxy.port);
    const { reply } = await handshake(control, 3, 0);
    control.destroy();
    expect(reply?.[1]).toBe(0x07);
  });
});

describe('HTTP CONNECT mock', () => {
  let dns: FixtureServer;
  let proxy: ProxyMock;

  beforeEach(async () => {
    dns = await startFixtureServer(({ query }) => ({ response: buildResponse(query, 1) }));
  });
  afterEach(async () => {
    await proxy.close();
    await dns.close();
  });

  // send CONNECT and return the status code of the proxy's reply
  async function connectVia(
    socket: net.Socket,
    port: number,
    authorization?: string
  ): Promise<number> {
    const input = socketReader(socket);
    socket.write(
      `CONNECT 127.0.0.1:${port} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
        (authorization ? `Proxy-Authorization: ${authorization}\r\n` : '') +
        '\r\n'
    );
    const head = await input.takeUntil('\r\n\r\n');
    input.release();
    return Number(head.split(' ')[1]);
  }

  const basic = (username: string, password: string) =>
    `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

  it('tunnels a TCP exchange to the target', async () => {
    proxy = await startHttpConnectMock();
    const socket = await open(proxy.port);
    expect(await connectVia(socket, dns.port)).toBe(200);

    const response = await askOver(socket, buildQuery(0x7171, 'via-connect.example'));
    socket.destroy();
    expect(idOf(response)).toBe(0x7171);
    expect(proxy.requests).toEqual([{ command: 'connect', host: '127.0.0.1', port: dns.port }]);
  });

  it('checks credentials', async () => {
    proxy = await startHttpConnectMock({ auth: { username: 'alice', password: 'hunter22' } });

    const refused = await open(proxy.port);
    expect(await connectVia(refused, dns.port, basic('alice', 'no'))).toBe(407);
    refused.destroy();

    const accepted = await open(proxy.port);
    expect(await connectVia(accepted, dns.port, basic('alice', 'hunter22'))).toBe(200);
    accepted.destroy();
    expect(proxy.requests[1]).toMatchObject({ username: 'alice', password: 'hunter22' });
  });

  it('refuses with the status it was given', async () => {
    proxy = await startHttpConnectMock({ refuseWith: 403 });
    const socket = await open(proxy.port);
    expect(await connectVia(socket, dns.port)).toBe(403);
    socket.destroy();
    expect(dns.received).toEqual([]);
  });

  it('reports a target it cannot reach', async () => {
    proxy = await startHttpConnectMock();
    const spare = net.createServer();
    const closedPort = await new Promise<number>(resolve =>
      spare.listen(0, '127.0.0.1', () => resolve((spare.address() as net.AddressInfo).port))
    );
    await new Promise(resolve => spare.close(resolve));

    const socket = await open(proxy.port);
    expect(await connectVia(socket, closedPort)).toBe(502);
    socket.destroy();
  });
});
