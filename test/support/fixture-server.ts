import dgram from 'node:dgram';
import net from 'node:net';
import type { AddressInfo } from 'node:net';

// an in-process DNS server for tests: UDP and TCP on the same random localhost port.
//
// it knows nothing about DNS beyond the 12-byte header. A test hands it a `respond`
// function from raw query bytes to raw response bytes, and may ask for a misbehaviour so
// the client's handling of a bad network can be tested without one.

export type Transport = 'udp' | 'tcp';

export interface ReceivedQuery {
  transport: Transport;
  query: Uint8Array;
}

export interface Reply {
  response: Uint8Array;
  // send the response's own ID; by default it is rewritten to the query's ID, because
  // recorded responses carry the ID of the query they were recorded with
  keepId?: boolean;
  // wait this long before replying
  delayMs?: number;
  // UDP only: reply from a different socket, so the source port does not match
  fromOtherSource?: boolean;
  // TCP only: write the framed response in pieces of this many bytes
  chunkBytes?: number;
  // TCP only: close the connection after this many bytes of the framed response
  closeAfterBytes?: number;
}

// return a reply, or undefined to stay silent (a dropped query)
export type Responder = (received: ReceivedQuery) => Reply | undefined;

export interface FixtureServer {
  address: string;
  port: number;
  // every query received, in arrival order
  received: ReceivedQuery[];
  // how many TCP connections have been accepted
  readonly tcpConnections: number;
  close(): Promise<void>;
}

const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

// the response with the query's ID in its first two bytes
function withQueryId(reply: Reply, query: Uint8Array): Uint8Array {
  if (reply.keepId || reply.response.length < 2 || query.length < 2) return reply.response;
  const patched = Uint8Array.from(reply.response);
  patched.set(query.subarray(0, 2), 0);
  return patched;
}

export async function startFixtureServer(respond: Responder): Promise<FixtureServer> {
  const address = '127.0.0.1';
  const received: ReceivedQuery[] = [];
  const connections = new Set<net.Socket>();

  // ---- TCP: two-byte length prefix, any number of queries per connection
  let tcpConnections = 0;
  let stopped = false;
  const tcp = net.createServer(socket => {
    tcpConnections++;
    connections.add(socket);
    socket.on('close', () => connections.delete(socket));
    socket.on('error', () => socket.destroy());

    let buffered = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 2 && buffered.length >= 2 + buffered.readUInt16BE(0)) {
        const length = buffered.readUInt16BE(0);
        const query = Uint8Array.from(buffered.subarray(2, 2 + length));
        buffered = buffered.subarray(2 + length);
        void answerTcp(socket, query);
      }
    });
  });

  async function answerTcp(socket: net.Socket, query: Uint8Array): Promise<void> {
    const entry: ReceivedQuery = { transport: 'tcp', query };
    received.push(entry);
    const reply = respond(entry);
    if (!reply) return;
    if (reply.delayMs) await sleep(reply.delayMs);

    const body = withQueryId(reply, query);
    const framed = Buffer.alloc(2 + body.length);
    framed.writeUInt16BE(body.length, 0);
    framed.set(body, 2);

    const end = reply.closeAfterBytes ?? framed.length;
    const step = reply.chunkBytes ?? framed.length;
    for (let offset = 0; offset < end && !socket.destroyed; offset += step) {
      socket.write(framed.subarray(offset, Math.min(offset + step, end)));
      // give each piece its own turn on the wire
      if (step < framed.length) await sleep(1);
    }
    if (reply.closeAfterBytes !== undefined) socket.destroy();
  }

  // ---- UDP on the same port, plus a second socket for replies from the wrong source.
  // The TCP port is picked by the system and may already be taken for UDP by something
  // else on the machine, so the pair is retried until both halves bind
  let udp = dgram.createSocket('udp4');
  let port = 0;
  for (let attempt = 1; ; attempt++) {
    await new Promise<void>(resolve => tcp.listen(0, address, resolve));
    port = (tcp.address() as AddressInfo).port;
    const socket = udp;
    const bound = await new Promise<boolean>(resolve => {
      socket.once('error', () => resolve(false));
      socket.bind(port, address, () => resolve(true));
    });
    if (bound) break;
    await new Promise<void>(resolve => tcp.close(() => resolve()));
    if (attempt === 20) throw new Error('fixture server: no port free for both TCP and UDP');
    udp = dgram.createSocket('udp4');
  }
  udp.removeAllListeners('error');
  const otherSource = dgram.createSocket('udp4');
  udp.on('message', (message, remote) => {
    const entry: ReceivedQuery = { transport: 'udp', query: Uint8Array.from(message) };
    received.push(entry);
    const reply = respond(entry);
    if (!reply) return;
    const send = () =>
      (reply.fromOtherSource ? otherSource : udp).send(
        withQueryId(reply, entry.query),
        remote.port,
        remote.address
      );
    if (reply.delayMs) setTimeout(send, reply.delayMs);
    else send();
  });
  await new Promise<void>(resolve => otherSource.bind(0, address, resolve));

  return {
    address,
    port,
    received,
    get tcpConnections() {
      return tcpConnections;
    },
    async close() {
      // closing twice is fine: a test may stop the server itself to see what a client does
      if (stopped) return;
      stopped = true;
      for (const socket of connections) socket.destroy();
      await Promise.all([
        new Promise<void>(resolve => tcp.close(() => resolve())),
        new Promise<void>(resolve => udp.close(() => resolve())),
        new Promise<void>(resolve => otherSource.close(() => resolve())),
      ]);
    },
  };
}

// ---- responders and response edits tests are likely to want

// the query with its ID zeroed, as a lookup key
const idless = (query: Uint8Array) => Buffer.from(query.subarray(2)).toString('base64');

// answer from recorded exchanges: each is a query and the response that came back for it,
// both base64. IDs are ignored on lookup and rewritten on reply. Unknown queries are dropped
export function recordedResponder(
  exchanges: ReadonlyArray<{ query: string; response: string }>
): Responder {
  const responses = new Map<string, Uint8Array>();
  for (const exchange of exchanges) {
    responses.set(
      idless(Buffer.from(exchange.query, 'base64')),
      Uint8Array.from(Buffer.from(exchange.response, 'base64'))
    );
  }
  return ({ query }) => {
    const response = responses.get(idless(query));
    return response ? { response } : undefined;
  };
}

// a copy of the response cut down to its header and marked truncated (TC), which is what
// a server sends over UDP when the answer does not fit
export function truncated(response: Uint8Array): Uint8Array {
  const header = Uint8Array.from(response.subarray(0, 12));
  header[2] |= 0x02; // TC
  // no records follow the header any more
  header.fill(0, 4, 12);
  return header;
}

// a copy of the response with a different ID
export function withOtherId(response: Uint8Array): Uint8Array {
  const copy = Uint8Array.from(response);
  copy[0] ^= 0xff;
  copy[1] ^= 0xff;
  return copy;
}
