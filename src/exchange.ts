import {
  DnsError,
  errorData,
  InvalidQueryError,
  InvalidResponseError,
  TimeoutError,
  TruncatedError,
} from './errors';
import { className, classCode, RECORD_CLASSES } from './protocol/classes';
import { DEFAULT_UDP_PAYLOAD_SIZE } from './protocol/edns';
import { rcodeName } from './protocol/header';
import { typeCode, typeName } from './protocol/types';
import { DEFAULT_PORTS, toEndpoint } from './transports/endpoint';
import { createTransports, defaultTransports } from './transports/index';
import type { Transports } from './transports/index';
import { isNode, now } from './transports/runtime';
import type {
  Endpoint,
  OnEvent,
  Server,
  TransportName,
  TransportOptions,
  TransportResponse,
} from './transports/types';
import { encodeQuery } from './wire/encode';
import { decodeMessage } from './wire/message';
import type { EdnsOption, Message } from './wire/message';
import { canonicalName, toAsciiName } from './wire/names';

// one question, put to one server, answered by one validated response.
//
// this is the layer every resolver is built on, and the one to use directly when the
// point is to see exactly what a particular server says. It does not follow referrals or
// aliases, it does not cache, and it does not judge the answer: a response saying
// NXDOMAIN or SERVFAIL is still a response, and is returned

export interface DnsQuestion {
  // Unicode or punycode, with or without a trailing dot
  name: string;
  // a mnemonic ('MX'), an RFC 3597 'TYPE65', or a number
  type: string | number;
  // default IN
  class?: string | number;
}

// header flags a query can set: recursion desired, checking disabled, authentic data
export type QueryFlag = 'RD' | 'CD' | 'AD';

export interface ExchangeOptions extends TransportOptions {
  // default: DoH for a server given as a URL, otherwise UDP, or TCP where there is no UDP
  transport?: TransportName;
  // default: the transport's own. A port written into the server wins
  port?: number;
  // default none: the question as an authoritative server is asked it. A recursive
  // resolver wants 'RD'
  flags?: readonly QueryFlag[];
  // set the DO bit: ask for DNSSEC records
  dnssecOk?: boolean;
  // the largest UDP response to accept. Default 1232
  udpPayloadSize?: number;
  ednsOptions?: readonly EdnsOption[];
  // false sends a plain RFC 1035 query with no OPT record
  edns?: boolean;
  // how long to wait for each attempt, in milliseconds. Default 5000
  timeout?: number;
  // how many more attempts to make after one fails in a way that may pass. Default 2
  retries?: number;
  // ask again over TCP when a UDP answer is truncated. Default true; with false the
  // truncated answer is returned as it came
  tcpFallback?: boolean;
  signal?: AbortSignal;
  onEvent?: OnEvent;
  // sockets and connections to use and leave open. Without it, a call that sets no
  // transport options shares one process-wide set, and a call that does gets a set of
  // its own, closed when the call ends
  transports?: Transports;
}

export interface ExchangeResult {
  message: Message;
  // the response exactly as it arrived
  bytes: Uint8Array;
  // what was asked, as it was sent
  query: {
    id: number;
    name: string;
    type: string;
    class: string;
    flags: QueryFlag[];
    edns: false | { udpPayloadSize: number; dnssecOk: boolean };
    bytes: Uint8Array;
  };
  server: string;
  port: number;
  // the transport that carried the answer, which is not always the one asked for
  transport: TransportName;
  // milliseconds, all attempts included
  elapsed: number;
  // how many times the query was sent
  attempts: number;
  // the `dig` command that asks the same question the same way
  toDig(): string;
}

const DEFAULT_TIMEOUT = 5000;
const DEFAULT_RETRIES = 2;

// ---- message IDs

// random IDs are drawn a block at a time: one call into the runtime's generator per 256
// queries instead of one per query
const idBlock = new Uint16Array(256);
let idsLeft = 0;

function randomId(): number {
  if (idsLeft === 0) {
    crypto.getRandomValues(idBlock);
    idsLeft = idBlock.length;
  }
  return idBlock[--idsLeft];
}

// ---- dig

export interface DigOptions {
  transport?: TransportName;
  port?: number;
  flags?: readonly QueryFlag[];
  dnssecOk?: boolean;
  udpPayloadSize?: number;
  edns?: boolean;
}

// the `dig` command for a question: the fastest way to check an answer by hand
export function digCommand(
  question: DnsQuestion,
  server: string | Server,
  options: DigOptions = {}
): string {
  const transport = options.transport ?? 'udp';
  const endpoint = toEndpoint(server, transport, options.port);
  const flags = options.flags ?? [];
  const parts = ['dig'];
  if (options.dnssecOk) parts.push('+dnssec');
  if (flags.includes('CD')) parts.push('+cd');
  if (!flags.includes('RD')) parts.push('+norecurse');
  if (flags.includes('AD')) parts.push('+adflag');
  if (transport === 'tcp') parts.push('+tcp');
  if (transport === 'tls') parts.push('+tls');
  if (transport === 'doh') {
    const path = endpoint.url ? new URL(endpoint.url).pathname : '/dns-query';
    parts.push(path === '/dns-query' ? '+https' : `+https=${path}`);
  }
  if (options.edns === false) parts.push('+noedns');
  else if ((options.udpPayloadSize ?? DEFAULT_UDP_PAYLOAD_SIZE) !== DEFAULT_UDP_PAYLOAD_SIZE) {
    parts.push(`+bufsize=${options.udpPayloadSize}`);
  }
  if (endpoint.port !== DEFAULT_PORTS[transport]) parts.push(`-p ${endpoint.port}`);
  parts.push(`@${endpoint.host}`);

  const name = toAsciiName(question.name);
  parts.push(name === '' ? '.' : name);
  parts.push(typeName(typeCode(question.type)));
  const cls = classCode(question.class ?? RECORD_CLASSES.IN);
  if (cls !== RECORD_CLASSES.IN) parts.push(className(cls));
  return parts.join(' ');
}

// ---- matching a response to its query

interface Checked {
  message?: Message;
  // why the bytes are not an acceptable answer
  problem?: string;
  // the problem is one that a stray or forged datagram would have: over UDP such a
  // datagram is dropped and the wait for the real answer goes on
  stray?: boolean;
}

function checkResponse(
  bytes: Uint8Array,
  expected: { id: number; name: string; type: number; class: number }
): Checked {
  if (bytes.length < 12) return { problem: 'shorter than a DNS header', stray: true };
  if (((bytes[0] << 8) | bytes[1]) !== expected.id) {
    return { problem: 'carries a different ID', stray: true };
  }
  let message: Message;
  try {
    message = decodeMessage(bytes);
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    return { problem: `cannot be decoded: ${why}` };
  }
  if (!message.flags.qr) return { message, problem: 'is not a response', stray: true };

  const [asked] = message.questions;
  if (!asked) {
    // a server that could not read the query may not echo it, and one cutting its answer
    // short may cut the question too; any other answer has to say what it answers
    return message.rcode === 0 && !message.flags.tc
      ? { message, problem: 'does not repeat the question', stray: true }
      : { message };
  }
  if (
    message.questions.length !== 1 ||
    asked.type !== expected.type ||
    asked.class !== expected.class ||
    canonicalName(asked.name) !== expected.name
  ) {
    return { message, problem: 'answers a different question', stray: true };
  }
  return { message };
}

// ---- the exchange

function hasTransportOptions(options: ExchangeOptions): boolean {
  return (
    options.proxy !== undefined ||
    options.fetch !== undefined ||
    options.connect !== undefined ||
    options.tls !== undefined ||
    options.udpSockets !== undefined ||
    options.idleTimeout !== undefined ||
    options.dohMethod !== undefined
  );
}

function defaultTransport(server: string | Server): TransportName {
  const url = typeof server === 'string' ? /^https?:\/\//i.test(server) : Boolean(server.url);
  if (url) return 'doh';
  return isNode() ? 'udp' : 'tcp';
}

export async function exchange(
  question: DnsQuestion,
  server: string | Server,
  options: ExchangeOptions = {}
): Promise<ExchangeResult> {
  const started = now();
  const { signal, onEvent } = options;
  const timeout = options.timeout ?? DEFAULT_TIMEOUT;
  const retries = Math.max(0, options.retries ?? DEFAULT_RETRIES);
  const flags = [...new Set(options.flags ?? [])];

  // ---- the question, checked before anything touches the network
  let name: string;
  try {
    name = toAsciiName(question.name);
  } catch (cause) {
    throw new InvalidQueryError(cause instanceof Error ? cause.message : String(cause), { cause });
  }
  const type = typeCode(question.type);
  const cls = classCode(question.class ?? RECORD_CLASSES.IN);
  const typeText = typeName(type);
  const edns: ExchangeResult['query']['edns'] =
    options.edns === false
      ? false
      : {
          udpPayloadSize: options.udpPayloadSize ?? DEFAULT_UDP_PAYLOAD_SIZE,
          dnssecOk: options.dnssecOk ?? false,
        };
  const encode = (id: number) =>
    encodeQuery({
      id,
      name,
      type,
      class: cls,
      recursionDesired: flags.includes('RD'),
      checkingDisabled: flags.includes('CD'),
      authenticData: flags.includes('AD'),
      edns: edns && { ...edns, ...(options.ednsOptions && { options: options.ednsOptions }) },
    });

  let transportName = options.transport ?? defaultTransport(server);
  let endpoint: Endpoint = toEndpoint(server, transportName, options.port);
  const context = () => ({
    server: endpoint.host,
    query: name,
    type: typeText,
    transport: transportName,
  });

  // DoH queries carry ID 0, which lets HTTP caches share answers (RFC 8484 §4.1)
  let id = transportName === 'doh' ? 0 : randomId();
  let queryBytes: Uint8Array;
  try {
    queryBytes = encode(id);
  } catch (error) {
    if (error instanceof DnsError) error.addContext(context());
    throw error;
  }
  if (signal?.aborted) throw signal.reason;

  const expected = { id, name: canonicalName(name), type, class: cls };
  const ownTransports = !options.transports && hasTransportOptions(options);
  const transports =
    options.transports ?? (ownTransports ? createTransports(options) : defaultTransports());

  // one listener for the whole exchange, pointed at whichever attempt is in flight
  let attemptAbort: AbortController | undefined;
  const onAbort = () => attemptAbort?.abort(signal?.reason);
  signal?.addEventListener('abort', onAbort, { once: true });

  let attempt = 0;
  let failures = 0;
  try {
    for (;;) {
      attempt++;
      const attemptStarted = now();
      const current = (attemptAbort = new AbortController());
      const timer = setTimeout(() => {
        current.abort(
          new TimeoutError(`No answer from ${endpoint.host} within ${timeout} ms`, context())
        );
      }, timeout);

      const report = (response?: TransportResponse, message?: Message, error?: unknown) =>
        onEvent?.({
          event: 'query',
          server: endpoint.host,
          port: endpoint.port,
          query: name,
          type: typeText,
          transport: response?.transport ?? transportName,
          attempt,
          elapsed: now() - attemptStarted,
          bytesSent: queryBytes.length,
          ...(response && { bytesReceived: response.bytes.length }),
          ...(message && {
            rcode: message.rcode,
            rcodeName: rcodeName(message.rcode),
            truncated: message.flags.tc,
          }),
          ...(error !== undefined && { error: errorData(error) }),
        });

      let response: TransportResponse;
      let checked: Checked | undefined;
      try {
        response = await transports.get(transportName).send({
          endpoint,
          query: queryBytes,
          signal: current.signal,
          onEvent,
          // over UDP anyone can send a datagram to the socket, so what does not match
          // the query is not the answer and is not allowed to end the wait
          accept(bytes) {
            const result = checkResponse(bytes, expected);
            if (result.stray) return false;
            checked = result;
            return true;
          },
        });
        // the stream transports matched on ID alone, or on nothing
        checked ??= checkResponse(response.bytes, expected);
        if (checked.problem || !checked.message) {
          throw new InvalidResponseError(
            `Response from ${endpoint.host} ${checked.problem ?? 'cannot be read'}`,
            { ...context(), transport: response.transport }
          );
        }
      } catch (error) {
        clearTimeout(timer);
        // the caller gave up: that is not a failed query, and is thrown as it was given
        if (signal?.aborted) throw signal.reason;
        if (error instanceof DnsError) error.addContext(context());
        report(undefined, undefined, error);

        const retryable = error instanceof DnsError && error.retryable;
        if (!retryable || failures >= retries) throw error;
        failures++;
        onEvent?.({
          event: 'retry',
          ...context(),
          attempt: attempt + 1,
          error: errorData(error),
        });
        // a UDP query that went unanswered is sent again as it was, so an answer to
        // either copy counts. Anything else starts over with a new ID
        if (
          !(transportName === 'udp' && error instanceof TimeoutError) &&
          transportName !== 'doh'
        ) {
          id = randomId();
          expected.id = id;
          queryBytes = encode(id);
        }
        continue;
      }
      clearTimeout(timer);
      const { message } = checked;
      report(response, message);

      if (message.flags.tc) {
        if (response.transport !== 'udp') {
          throw new TruncatedError(
            `Response from ${endpoint.host} is truncated over ${response.transport.toUpperCase()}`,
            { ...context(), transport: response.transport, rcode: message.rcode }
          );
        }
        if (options.tcpFallback !== false) {
          onEvent?.({
            event: 'tcp-fallback',
            server: endpoint.host,
            query: name,
            type: typeText,
            reason: 'truncated',
          });
          transportName = 'tcp';
          endpoint = toEndpoint(server, 'tcp', options.port);
          id = randomId();
          expected.id = id;
          queryBytes = encode(id);
          continue;
        }
      }

      const finalTransport = response.transport;
      const finalEndpoint = endpoint;
      const sent = queryBytes;
      return {
        message,
        bytes: response.bytes,
        query: {
          id,
          name,
          type: typeText,
          class: className(cls),
          flags,
          edns,
          bytes: sent,
        },
        server: finalEndpoint.host,
        port: finalEndpoint.port,
        transport: finalTransport,
        elapsed: now() - started,
        attempts: attempt,
        toDig: () =>
          digCommand({ name, type, class: cls }, server, {
            transport: finalTransport,
            port: finalEndpoint.port,
            flags,
            edns: edns !== false,
            ...(edns && { dnssecOk: edns.dnssecOk, udpPayloadSize: edns.udpPayloadSize }),
          }),
      };
    }
  } finally {
    signal?.removeEventListener('abort', onAbort);
    if (ownTransports) transports.close();
  }
}
