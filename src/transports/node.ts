import type { Socket } from 'node:net';
import { DnsError } from '../errors';
import { isIp } from './endpoint';
import type { Connect, Connection, TlsOptions } from './types';

// the Node connector: a `node:net` socket behind the `Connection` interface, for the
// paths that need one (a proxy tunnel, DoH over a tunnel). Direct TCP and DoT on Node do
// not come through here; they use the socket itself.
//
// Node's modules are imported when a connection is first opened, never at load, so
// importing the library costs nothing on a runtime that does not have them

// each of Node's modules is loaded inside a `try`. A runtime without the module gets an
// error that says so, and a bundler building for a browser leaves an import it cannot
// resolve for the runtime to make, where an import outside a `try` fails the build
export async function loadNet(): Promise<typeof import('node:net')> {
  try {
    return await import('node:net');
  } catch (cause) {
    throw new DnsError('TCP is not available in this runtime', { cause });
  }
}

export async function loadTls(): Promise<typeof import('node:tls')> {
  try {
    return await import('node:tls');
  } catch (cause) {
    throw new DnsError('TLS is not available in this runtime', { cause });
  }
}

// the options `tls.connect` takes from ours
export function nodeTlsOptions(options: TlsOptions | undefined, hostname: string) {
  return {
    host: hostname,
    // SNI carries names only; a certificate for an IP address is checked against `host`
    ...(!isIp(hostname) && { servername: hostname }),
    ...(options?.ca !== undefined && { ca: [options.ca].flat() }),
    ...(options?.rejectUnauthorized !== undefined && {
      rejectUnauthorized: options.rejectUnauthorized,
    }),
  };
}

// wait for a socket to be ready, taking back the listeners afterwards: the socket has
// listeners of its own that must stay
export function whenReady(socket: Socket, ready: 'connect' | 'secureConnect'): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      socket.off(ready, onReady).off('error', onError).off('close', onClose);
    };
    const onReady = () => {
      cleanup();
      resolve();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error('connection closed'));
    };
    socket.once(ready, onReady).once('error', onError).once('close', onClose);
  });
}

function wrapSocket(
  socket: Socket,
  tlsOptions: TlsOptions | undefined,
  under?: Socket
): Connection {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let finished = false;
  const finish = (error?: Error) => {
    if (finished) return;
    finished = true;
    if (error) controller.error(error);
    else controller.close();
  };
  // a copy: the stream's consumer may hold the chunk after the socket moves on
  const onData = (chunk: Buffer) => controller.enqueue(new Uint8Array(chunk));
  const onEnd = () => finish();
  const onClose = () => finish();
  const onError = (error: Error) => finish(error);
  const detach = () => {
    socket.off('data', onData).off('end', onEnd).off('close', onClose).off('error', onError);
  };

  const readable = new ReadableStream<Uint8Array>({
    start(streamController) {
      controller = streamController;
      socket.on('data', onData).on('end', onEnd).on('close', onClose).on('error', onError);
    },
    cancel() {
      // the reader has let go: there is no stream left to close when the socket does
      finished = true;
      socket.destroy();
    },
  });
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      return new Promise<void>((resolve, reject) => {
        socket.write(chunk, error => (error ? reject(error) : resolve()));
      });
    },
    close() {
      socket.end();
    },
    abort() {
      socket.destroy();
    },
  });

  return {
    readable,
    writable,
    close() {
      socket.destroy();
    },
    async startTls(hostname) {
      const tls = await loadTls();
      detach();
      // the TLS socket reports the raw socket's errors; this keeps one from being
      // thrown as unhandled in the moment between the two
      socket.on('error', () => undefined);
      const secure = tls.connect({ socket, ...nodeTlsOptions(tlsOptions, hostname) });
      try {
        await whenReady(secure, 'secureConnect');
      } catch (error) {
        secure.destroy();
        throw error;
      }
      return wrapSocket(secure, tlsOptions, socket);
    },
    // let the process exit while the connection sits idle
    ref() {
      socket.ref();
      under?.ref();
    },
    unref() {
      socket.unref();
      under?.unref();
    },
  };
}

export function createNodeConnect(tlsOptions?: TlsOptions): Connect {
  return async target => {
    const net = await loadNet();
    const socket = net.connect({ host: target.hostname, port: target.port });
    socket.setNoDelay(true);
    try {
      await whenReady(socket, 'connect');
    } catch (error) {
      socket.destroy();
      throw error;
    }
    return wrapSocket(socket, tlsOptions);
  };
}
