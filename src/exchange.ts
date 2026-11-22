import {
  DnsError,
  errorData,
  InvalidQueryError,
  InvalidResponseError,
  TimeoutError,
  TruncatedError,
} from './errors';
import type { ErrorData } from './errors';
import { className, classCode, RECORD_CLASSES } from './protocol/classes';
import { DEFAULT_UDP_PAYLOAD_SIZE } from './protocol/edns';
import { RCODES, rcodeName } from './protocol/header';
import { typeCode, typeName } from './protocol/types';
import { DEFAULT_PORTS, toEndpoint } from './transports/endpoint';
import { createTransports, defaultTransports } from './transports/set';
import type { Transports } from './transports/set';
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
import {
  canonicalName,
  comparableName,
  labelsToName,
  nameToLabels,
  toAsciiName,
} from './wire/names';

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

// the header flags a query was sent with: recursion desired, checking disabled,
// authentic data
export interface QueryFlags {
  rd: boolean;
  cd: boolean;
  ad: boolean;
}

// what was sent: the question as it went on the wire, its flags and its EDNS settings
export interface SentQuery {
  // with no trailing dot, as it was written
  name: string;
  type: string;
  class: string;
  flags: QueryFlags;
  edns: false | { udpPayloadSize: number; dnssecOk: boolean };
}

export interface ExchangeOptions extends TransportOptions {
  // default: DoH for a server given as a URL, otherwise UDP, or TCP where there is no UDP
  transport?: TransportName;
  // default: the transport's own. A port written into the server wins
  port?: number;
  // RD: ask the server to resolve the name on our behalf. Default true, the ordinary
  // question a resolver is asked and what `dig` sends. False is for putting a question
  // to an authoritative server directly
  recursionDesired?: boolean;
  // CD: ask a validating resolver for the data even if it fails validation
  checkingDisabled?: boolean;
  // AD: ask to be told whether the answer was authenticated
  authenticData?: boolean;
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
  // how long all attempts may take together, in milliseconds, retries and a TCP fallback
  // included. Each attempt is cut short to fit, and none is started once it has run
  // out. Default: no limit beyond each attempt's `timeout`
  totalTimeout?: number;
  // ask again over TCP when a UDP answer is truncated. Default true; with false the
  // truncated answer is returned as it came. When the TCP retry fails (refused, timed
  // out, no time left for it), the truncated answer is returned too, with the TCP error
  // in `tcpFallbackError`
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
  query: SentQuery & { id: number; bytes: Uint8Array };
  server: string;
  port: number;
  // DoH: the URL the query went to
  url?: string;
  // the transport that carried the answer, which is not always the one asked for
  transport: TransportName;
  // milliseconds, all attempts included
  elapsed: number;
  // how many times the query was sent
  attempts: number;
  // the answer is a truncated UDP one (TC set) because asking again over TCP failed:
  // why it did
  tcpFallbackError?: ErrorData;
}

// the TCP failure behind a result's `tcpFallbackError`, as the error that was thrown, for
// a resolver that counts it as the server's failure
const tcpFailures = new WeakMap<ExchangeResult, DnsError>();

export function tcpFallbackFailure(result: ExchangeResult): DnsError | undefined {
  return tcpFailures.get(result);
}

export const DEFAULT_TIMEOUT = 5000;
export const DEFAULT_RETRIES = 2;

// a name as the library hands it back: with no trailing dot, in the case it was written,
// spelled as a decoded message spells it, and the root as '.'. Throws for a name that
// cannot be written
export function presentName(name: string): string {
  return labelsToName(nameToLabels(name));
}

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
  // default true, as in `exchange`
  recursionDesired?: boolean;
  checkingDisabled?: boolean;
  authenticData?: boolean;
  dnssecOk?: boolean;
  udpPayloadSize?: number;
  edns?: boolean;
}

// what `toDig` needs: an answer from either resolver, or an exchange's result
export interface DigSource {
  query: SentQuery;
  server: string;
  port: number;
  url?: string;
  transport: TransportName;
}

// the `dig` command that asks the server that answered the same question the same way:
// the fastest way to check an answer by hand
export function toDig(answer: DigSource): string {
  const { query } = answer;
  return digCommand(
    { name: query.name, type: query.type, class: query.class },
    { address: answer.server, ...(answer.url && { url: answer.url }) },
    {
      transport: answer.transport,
      port: answer.port,
      recursionDesired: query.flags.rd,
      checkingDisabled: query.flags.cd,
      authenticData: query.flags.ad,
      edns: query.edns !== false,
      ...(query.edns && {
        dnssecOk: query.edns.dnssecOk,
        udpPayloadSize: query.edns.udpPayloadSize,
      }),
    }
  );
}

// the `dig` command for a question
export function digCommand(
  question: DnsQuestion,
  server: string | Server,
  options: DigOptions = {}
): string {
  const transport = options.transport ?? 'udp';
  const endpoint = toEndpoint(server, transport, options.port);
  const parts = ['dig'];
  if (options.dnssecOk) parts.push('+dnssec');
  if (options.checkingDisabled) parts.push('+cd');
  if (options.recursionDesired === false) parts.push('+norecurse');
  if (options.authenticData) parts.push('+adflag');
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

// every transport option, by name. The compiler holds this to the keys of
// `TransportOptions`, so an option added there cannot be left out here
const TRANSPORT_OPTIONS = {
  proxy: true,
  fetch: true,
  connect: true,
  tls: true,
  idleTimeout: true,
  pipeline: true,
  dohMethod: true,
} satisfies Record<keyof TransportOptions, true>;
const TRANSPORT_OPTION_NAMES = Object.keys(TRANSPORT_OPTIONS) as (keyof TransportOptions)[];

// the options without the transport ones, for handing on beside a set made from them
export function withoutTransportOptions<Options extends TransportOptions>(
  options: Options
): Omit<Options, keyof TransportOptions> {
  const rest: Partial<Options> = { ...options };
  for (const name of TRANSPORT_OPTION_NAMES) delete rest[name];
  return rest as Omit<Options, keyof TransportOptions>;
}

// the set of transports to use, and whether it is the caller's own to close: the set that
// was given, one made from the transport options that were given, or the process-wide
// one. A set that is already made takes no transport options, so both together is an error
export function transportsFor(options: TransportOptions & { transports?: Transports }): {
  transports: Transports;
  owned: boolean;
} {
  const given = TRANSPORT_OPTION_NAMES.filter(name => options[name] !== undefined);
  if (options.transports) {
    if (given.length > 0) {
      const names = given.map(name => `\`${name}\``).join(', ');
      throw new DnsError(
        `Transport options (${names}) cannot be combined with \`transports\`: a set that ` +
          'is already made does not take them. Pass them to createTransports() instead'
      );
    }
    return { transports: options.transports, owned: false };
  }
  return given.length > 0
    ? { transports: createTransports(options), owned: true }
    : { transports: defaultTransports(), owned: false };
}

// the settings that travel in a query's EDNS record
type EdnsSettings = Pick<ExchangeOptions, 'edns' | 'dnssecOk' | 'udpPayloadSize' | 'ednsOptions'>;

// a setting that only the EDNS record can carry is refused where `edns: false` leaves the
// record out: on a resolver made with both, and on a query that sets one while EDNS is
// off for it, by its own `edns` or by the resolver's (`inherited`). What a resolver set
// may still be left out by one query's own `edns: false`: that is the caller asking for
// a plain query, and nothing of that query's own is dropped
export function checkEdnsSettings(own: EdnsSettings, inherited: EdnsSettings = {}): void {
  if ((own.edns ?? inherited.edns) !== false) return;
  const names = [
    own.dnssecOk && '`dnssecOk`',
    own.udpPayloadSize !== undefined && '`udpPayloadSize`',
    own.ednsOptions?.length && '`ednsOptions`',
  ].filter(name => typeof name === 'string');
  if (names.length === 0) return;
  throw new DnsError(
    `\`edns: false\` sends no EDNS record, which is what carries ${names.join(', ')}: ` +
      'set one or the other'
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
  const deadline = options.totalTimeout === undefined ? Infinity : started + options.totalTimeout;
  const recursionDesired = options.recursionDesired ?? true;
  const checkingDisabled = options.checkingDisabled ?? false;
  const authenticData = options.authenticData ?? false;
  const flags: QueryFlags = { rd: recursionDesired, cd: checkingDisabled, ad: authenticData };

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
  let edns: ExchangeResult['query']['edns'] =
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
      recursionDesired,
      checkingDisabled,
      authenticData,
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

  // the response's question is decoded, so it is spelled without the escapes the name
  // may have been written with
  const expected = { id, name: comparableName(name), type, class: cls };
  const { transports, owned: ownTransports } = transportsFor(options);

  // over when the exchange is: a UDP socket is kept for the retransmissions until then
  const lifetime = new AbortController();
  // one listener for the whole exchange, pointed at whichever attempt is in flight
  let attemptAbort: AbortController | undefined;
  const onAbort = () => attemptAbort?.abort(signal?.reason);
  signal?.addEventListener('abort', onAbort, { once: true });

  let attempt = 0;
  let failures = 0;
  // the truncated UDP answer while it is asked again over TCP: what comes back if that
  // fails
  let truncated: ExchangeResult | undefined;
  const build = (response: TransportResponse, message: Message): ExchangeResult => ({
    message,
    bytes: response.bytes,
    query: {
      id,
      name: presentName(name),
      type: typeText,
      class: className(cls),
      flags: { ...flags },
      edns: edns && { ...edns },
      bytes: queryBytes,
    },
    server: endpoint.host,
    port: endpoint.port,
    ...(response.transport === 'doh' && endpoint.url && { url: endpoint.url }),
    transport: response.transport,
    elapsed: now() - started,
    attempts: attempt,
  });
  // TCP did not work: the truncated answer is returned as it came, saying why
  const fallbackFailed = (answer: ExchangeResult, error: DnsError): ExchangeResult => {
    const data = errorData(error);
    const result = {
      ...answer,
      elapsed: now() - started,
      attempts: attempt,
      tcpFallbackError: data,
    };
    tcpFailures.set(result, error);
    onEvent?.({
      event: 'tcp-fallback-failed',
      server: answer.server,
      query: name,
      type: typeText,
      error: data,
    });
    return result;
  };
  try {
    for (;;) {
      attempt++;
      const attemptStarted = now();
      const current = (attemptAbort = new AbortController());
      // no longer than what is left of the time for the whole exchange. A timer that runs
      // out the rest of that time has reached the deadline, whatever the clock reads: timers
      // can fire a millisecond early, and another attempt would be sent for what is left
      const left = deadline - now();
      const wait = Math.max(1, Math.min(timeout, left));
      const clamped = left <= timeout;
      let deadlineHit = false;
      const timer = setTimeout(() => {
        if (clamped) deadlineHit = true;
        // in whole milliseconds: what is left of a total timeout is rarely a round number
        current.abort(
          new TimeoutError(
            `No answer from ${endpoint.host} within ${Math.round(wait)} ms`,
            context()
          )
        );
      }, wait);

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
          lifetime: lifetime.signal,
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
        if (!retryable || failures >= retries || deadlineHit || now() >= deadline) {
          if (truncated && error instanceof DnsError) return fallbackFailed(truncated, error);
          throw error;
        }
        failures++;
        onEvent?.({
          event: 'retry',
          ...context(),
          attempt: attempt + 1,
          error: errorData(error),
        });
        // a UDP query that went unanswered is sent again as it was, from the same socket,
        // so an answer to either copy counts. Anything else starts over with a new ID
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

      // a server too old for EDNS answers FORMERR or NOTIMP to a query that carries it,
      // with no EDNS record of its own: asked once more without it (RFC 6891 §7). Not
      // when the query needs EDNS, for signatures or its options, which a plain query
      // cannot carry
      if (
        edns &&
        !message.edns &&
        (message.rcode === RCODES.FORMERR || message.rcode === RCODES.NOTIMP) &&
        !edns.dnssecOk &&
        !options.ednsOptions?.length
      ) {
        onEvent?.({
          event: 'retry',
          ...context(),
          attempt: attempt + 1,
          error: errorData(
            new InvalidResponseError(
              `${endpoint.host} answered ${rcodeName(message.rcode)} to a query with EDNS: asking again without it`,
              { ...context(), rcode: message.rcode }
            )
          ),
        });
        edns = false;
        if (transportName !== 'doh') id = randomId();
        expected.id = id;
        queryBytes = encode(id);
        continue;
      }

      if (message.flags.tc) {
        if (response.transport !== 'udp') {
          const error = new TruncatedError(
            `Response from ${endpoint.host} is truncated over ${response.transport.toUpperCase()}`,
            { ...context(), transport: response.transport, rcode: message.rcode }
          );
          if (truncated) return fallbackFailed(truncated, error);
          throw error;
        }
        if (options.tcpFallback !== false) {
          truncated = build(response, message);
          // out of time to ask again: the truncated answer is the only one there will be
          if (deadlineHit || now() >= deadline) {
            return fallbackFailed(
              truncated,
              new TimeoutError(
                `No time left to ask ${endpoint.host} again over TCP within ${Math.round(options.totalTimeout ?? 0)} ms`,
                { ...context(), transport: 'tcp' }
              )
            );
          }
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

      return build(response, message);
    }
  } finally {
    signal?.removeEventListener('abort', onAbort);
    lifetime.abort();
    if (ownTransports) transports.close();
  }
}
