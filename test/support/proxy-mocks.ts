import dgram from 'node:dgram';
import net from 'node:net';
import type { AddressInfo } from 'node:net';

// two in-process proxies for tests: SOCKS5 (RFC 1928, username/password from RFC 1929)
// and HTTP CONNECT. Each really tunnels to the target, records what it was asked to do,
// and can be told to refuse, so a client's handling of every outcome can be tested.

export interface ProxyCredentials {
  username: string;
  password: string;
}

export interface ProxyRequest {
  command: 'connect' | 'udp-associate';
  host: string;
  port: number;
  // the credentials the client presented, if any
  username?: string;
  password?: string;
}

export interface ProxyMock {
  address: string;
  port: number;
  // every request the proxy was asked to make, in arrival order
  requests: ProxyRequest[];
  close(): Promise<void>;
}

const LOCALHOST = '127.0.0.1';

// read bytes off a socket on demand, until the tunnel takes the socket over
export function socketReader(socket: net.Socket) {
  let buffered = Buffer.alloc(0);
  let closed = false;
  let waiting: { resolve: () => void; reject: (error: Error) => void } | undefined;
  const onData = (chunk: Buffer) => {
    buffered = Buffer.concat([buffered, chunk]);
    waiting?.resolve();
  };
  socket.on('data', onData);
  socket.once('close', () => {
    closed = true;
    waiting?.reject(new Error('socket closed'));
  });
  const wait = () =>
    new Promise<void>((resolve, reject) => {
      if (closed) reject(new Error('socket closed'));
      else waiting = { resolve, reject };
    });
  return {
    async take(length: number): Promise<Buffer> {
      while (buffered.length < length) await wait();
      const out = buffered.subarray(0, length);
      buffered = buffered.subarray(length);
      return out;
    },
    async takeUntil(marker: string): Promise<string> {
      while (!buffered.includes(marker)) await wait();
      const end = buffered.indexOf(marker) + marker.length;
      const out = buffered.subarray(0, end).toString('latin1');
      buffered = buffered.subarray(end);
      return out;
    },
    // stop reading, and return whatever arrived after the handshake for the tunnel
    release(): Buffer {
      socket.off('data', onData);
      waiting = undefined;
      return buffered;
    },
  };
}

function listen(server: net.Server): Promise<number> {
  return new Promise(resolve =>
    server.listen(0, LOCALHOST, () => resolve((server.address() as AddressInfo).port))
  );
}

// open a connection to the target, or undefined if it cannot be reached
function dial(host: string, port: number): Promise<net.Socket | undefined> {
  return new Promise(resolve => {
    const target = net.connect({ host, port });
    target.once('error', () => resolve(undefined));
    target.once('connect', () => resolve(target));
  });
}

// join a client socket to a target, both ways
function join(client: net.Socket, target: net.Socket, early: Buffer): void {
  if (early.length) target.write(early);
  client.pipe(target);
  target.pipe(client);
  client.on('close', () => target.destroy());
  target.on('close', () => client.destroy());
  target.on('error', () => client.destroy());
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

export interface Socks5Options {
  // require these credentials; without it the proxy accepts "no authentication"
  auth?: ProxyCredentials;
  // answer UDP ASSOCIATE; when false the proxy replies "command not supported"
  udpAssociate?: boolean;
  // refuse every CONNECT with this reply code (0x05 is "connection refused")
  refuseWith?: number;
  // answer the greeting with this method whatever the client offered, the way a proxy
  // that skips authentication would
  chooseMethod?: number;
}

const SOCKS_VERSION = 0x05;
const REPLY = {
  succeeded: 0x00,
  connectionRefused: 0x05,
  commandNotSupported: 0x07,
  addressNotSupported: 0x08,
} as const;

// version, reply code, reserved, then the bound address as IPv4 + port
function socksReply(code: number, port = 0): Buffer {
  const reply = Buffer.from([SOCKS_VERSION, code, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
  reply.writeUInt16BE(port, 8);
  return reply;
}

export async function startSocks5Mock(options: Socks5Options = {}): Promise<ProxyMock> {
  const requests: ProxyRequest[] = [];
  const sockets = new Set<net.Socket>();
  const relays = new Set<dgram.Socket>();
  // a relay is closed when its control connection ends or the proxy shuts down,
  // whichever comes first
  const closeRelay = (relay: dgram.Socket) => {
    if (relays.delete(relay)) relay.close();
  };

  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    handle(socket).catch(() => socket.destroy());
  });

  async function handle(socket: net.Socket): Promise<void> {
    const input = socketReader(socket);

    // greeting: version, method count, methods
    const [version, methodCount] = await input.take(2);
    const methods = [...(await input.take(methodCount))];
    if (version !== SOCKS_VERSION) {
      socket.destroy();
      return;
    }

    const wanted = options.chooseMethod ?? (options.auth ? 0x02 : 0x00);
    if (options.chooseMethod === undefined && !methods.includes(wanted)) {
      socket.end(Buffer.from([SOCKS_VERSION, 0xff])); // no acceptable method
      return;
    }
    socket.write(Buffer.from([SOCKS_VERSION, wanted]));

    let username: string | undefined;
    let password: string | undefined;
    if (wanted === 0x02 && options.auth) {
      // RFC 1929: version 1, username, password, each length-prefixed
      const [, userLength] = await input.take(2);
      username = (await input.take(userLength)).toString('utf8');
      const [passLength] = await input.take(1);
      password = (await input.take(passLength)).toString('utf8');
      const ok = username === options.auth.username && password === options.auth.password;
      socket.write(Buffer.from([0x01, ok ? 0x00 : 0x01]));
      if (!ok) {
        socket.end();
        return;
      }
    }

    // request: version, command, reserved, address type, address, port
    const [, command, , addressType] = await input.take(4);
    let host: string;
    if (addressType === 0x01) {
      host = [...(await input.take(4))].join('.');
    } else if (addressType === 0x03) {
      const [length] = await input.take(1);
      host = (await input.take(length)).toString('latin1');
    } else {
      socket.end(socksReply(REPLY.addressNotSupported));
      return;
    }
    const port = (await input.take(2)).readUInt16BE(0);

    if (command === 0x01) {
      requests.push({ command: 'connect', host, port, username, password });
      if (options.refuseWith !== undefined) {
        socket.end(socksReply(options.refuseWith));
        return;
      }
      const target = await dial(host, port);
      if (!target) {
        socket.end(socksReply(REPLY.connectionRefused));
        return;
      }
      // the reply has to reach the client before any tunnelled bytes do
      socket.write(socksReply(REPLY.succeeded));
      join(socket, target, input.release());
      return;
    }

    if (command === 0x03 && options.udpAssociate) {
      requests.push({ command: 'udp-associate', host, port, username, password });
      const relay = dgram.createSocket('udp4');
      relays.add(relay);
      let client: { address: string; port: number } | undefined;
      relay.on('message', (message, remote) => {
        const fromClient =
          !client || (remote.address === client.address && remote.port === client.port);
        if (fromClient && message[2] === 0x00 && message[3] === 0x01) {
          // reserved (2), fragment (1), address type (1), IPv4 (4), port (2), then the datagram
          client = { address: remote.address, port: remote.port };
          relay.send(
            message.subarray(10),
            message.readUInt16BE(8),
            [...message.subarray(4, 8)].join('.')
          );
        } else if (client) {
          // a reply from the target: wrap it with the target's address and pass it back
          const header = Buffer.from([
            0,
            0,
            0,
            0x01,
            ...remote.address.split('.').map(Number),
            0,
            0,
          ]);
          header.writeUInt16BE(remote.port, 8);
          relay.send(Buffer.concat([header, message]), client.port, client.address);
        }
      });
      await new Promise<void>(resolve => relay.bind(0, LOCALHOST, resolve));
      // the association lasts as long as the control connection
      socket.on('close', () => closeRelay(relay));
      socket.write(socksReply(REPLY.succeeded, relay.address().port));
      return;
    }

    socket.end(socksReply(REPLY.commandNotSupported));
  }

  const port = await listen(server);
  return {
    address: LOCALHOST,
    port,
    requests,
    async close() {
      for (const socket of sockets) socket.destroy();
      for (const relay of [...relays]) closeRelay(relay);
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

export interface HttpConnectOptions {
  // require these credentials in Proxy-Authorization (Basic)
  auth?: ProxyCredentials;
  // refuse every CONNECT with this status, e.g. 403
  refuseWith?: number;
}

export async function startHttpConnectMock(options: HttpConnectOptions = {}): Promise<ProxyMock> {
  const requests: ProxyRequest[] = [];
  const sockets = new Set<net.Socket>();

  const respond = (socket: net.Socket, status: number, reason: string, headers = '') =>
    socket.write(`HTTP/1.1 ${status} ${reason}\r\n${headers}\r\n`);

  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    handle(socket).catch(() => socket.destroy());
  });

  async function handle(socket: net.Socket): Promise<void> {
    const input = socketReader(socket);
    const head = await input.takeUntil('\r\n\r\n');
    const [requestLine, ...headerLines] = head.split('\r\n');
    const [method, authority] = requestLine.split(' ');
    if (method !== 'CONNECT' || !authority) {
      respond(socket, 405, 'Method Not Allowed');
      socket.end();
      return;
    }
    const separator = authority.lastIndexOf(':');
    const host = authority.slice(0, separator);
    const port = Number(authority.slice(separator + 1));

    const authorization = headerLines
      .find(line => line.toLowerCase().startsWith('proxy-authorization:'))
      ?.split(':')
      .slice(1)
      .join(':')
      .trim();
    let username: string | undefined;
    let password: string | undefined;
    if (authorization?.startsWith('Basic ')) {
      const decoded = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
      username = decoded.slice(0, decoded.indexOf(':'));
      password = decoded.slice(decoded.indexOf(':') + 1);
    }
    requests.push({ command: 'connect', host, port, username, password });

    if (
      options.auth &&
      (username !== options.auth.username || password !== options.auth.password)
    ) {
      respond(socket, 407, 'Proxy Authentication Required', 'Proxy-Authenticate: Basic\r\n');
      socket.end();
      return;
    }
    if (options.refuseWith !== undefined) {
      respond(socket, options.refuseWith, 'Refused');
      socket.end();
      return;
    }

    const target = await dial(host, port);
    if (!target) {
      respond(socket, 502, 'Bad Gateway');
      socket.end();
      return;
    }
    respond(socket, 200, 'Connection Established');
    join(socket, target, input.release());
  }

  const port = await listen(server);
  return {
    address: LOCALHOST,
    port,
    requests,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}
