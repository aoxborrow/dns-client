import { ConnectionError, TimeoutError } from '../../src/errors';
import type { Transports } from '../../src/transports/index';
import type { Transport, TransportName } from '../../src/transports/types';

// transports that answer from recorded exchanges, for tests of code that asks many
// questions of many servers: nothing is sent anywhere, so the tests run without a network
// and wherever there are no sockets

export interface RecordedExchange {
  transport: string;
  server: string;
  // the query with its ID zeroed, base64
  query: string;
  // the response, base64, or how the query failed
  response?: string;
  failure?: 'timeout' | 'connection';
}

export interface ReplayTransports extends Transports {
  // questions that were asked and are not in the recording
  readonly misses: string[];
}

const toBase64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

// a query without its ID, which is random: what a recording is keyed by
export function queryKey(transport: string, server: string, query: Uint8Array): string {
  const copy = Uint8Array.from(query);
  copy[0] = 0;
  copy[1] = 0;
  return `${transport} ${server} ${toBase64(copy)}`;
}

export function replayTransports(exchanges: readonly RecordedExchange[]): ReplayTransports {
  const recorded = new Map<string, RecordedExchange>();
  for (const exchange of exchanges) {
    recorded.set(`${exchange.transport} ${exchange.server} ${exchange.query}`, exchange);
  }
  const misses: string[] = [];

  const transport = (name: TransportName): Transport => ({
    name,
    send(request) {
      const key = queryKey(name, request.endpoint.host, request.query);
      const exchange = recorded.get(key);
      if (!exchange) {
        misses.push(`${name} ${request.endpoint.host}`);
        return Promise.reject(
          new ConnectionError(`Not in the recording: ${name} ${request.endpoint.host}`)
        );
      }
      if (exchange.response === undefined) {
        return Promise.reject(
          exchange.failure === 'timeout'
            ? new TimeoutError(`No answer from ${request.endpoint.host} (recorded)`)
            : new ConnectionError(`Cannot reach ${request.endpoint.host} (recorded)`)
        );
      }
      const bytes = Uint8Array.from(Buffer.from(exchange.response, 'base64'));
      // the recorded response carries the ID of the query it answered
      bytes[0] = request.query[0];
      bytes[1] = request.query[1];
      return Promise.resolve({ bytes, transport: name });
    },
    close() {},
  });

  return { get: transport, close() {}, misses };
}
