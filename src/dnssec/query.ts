import { exchange } from '../exchange';
import type { Transports } from '../transports/index';
import type { OnEvent } from '../transports/types';
import type { DnssecTransport } from './types';
import { toWireMessage } from './wire';
import type { WireMessage } from './wire';

// the one way the analysis asks a question: one question to one named server, and the
// response as it came.
//
// a resolver is no use here. It follows referrals, where the referral itself is the data
// (that is how a zone cut is found); it may answer from a cache, where the answer must be
// live; and it would not set Checking Disabled, which has to be on so that a validating
// resolver upstream cannot hide the broken records the analysis exists to show

// EDNS advertised receive size. Large enough for root and TLD DNSKEY sets over UDP, small
// enough to stay under the common 1500-byte path MTU
export const EDNS_UDP_PAYLOAD_SIZE = 1232;

const DEFAULT_TIMEOUT_MS = 5000;

export interface DnssecQueryOptions {
  transport?: DnssecTransport;
  timeoutMs?: number;
  // recursion desired: off for authoritative queries, on for the resolver cross-check
  recursionDesired?: boolean;
  // checking disabled: on everywhere except the cross-check, where a resolver's own
  // verdict is the thing being asked for
  checkingDisabled?: boolean;
  dnssecOk?: boolean;
  // sockets and connections to use
  transports?: Transports;
  signal?: AbortSignal;
  onEvent?: OnEvent;
}

export interface DnssecQueryResult {
  message?: WireMessage;
  timestamp: string;
  elapsed: number;
  transport: DnssecTransport;
  flagsSent: string[];
  // set when a truncated UDP answer was re-asked over TCP
  retriedOverTcp?: boolean;
  error?: string;
}

// ask, and never throw: a failure comes back as a result with `error` set, because to
// the analysis a server that does not answer is a finding, not an exception
export async function dnssecQuery(
  server: string,
  qname: string,
  qtype: number,
  options: DnssecQueryOptions = {}
): Promise<DnssecQueryResult> {
  const transport = options.transport ?? 'tcp';
  const recursionDesired = options.recursionDesired ?? false;
  const checkingDisabled = options.checkingDisabled ?? true;
  const dnssecOk = options.dnssecOk ?? true;

  const flagsSent: string[] = [];
  if (dnssecOk) flagsSent.push('DO');
  if (checkingDisabled) flagsSent.push('CD');
  if (recursionDesired) flagsSent.push('RD');

  const started = performance.now();
  const base: DnssecQueryResult = {
    timestamp: new Date().toISOString(),
    elapsed: 0,
    transport,
    flagsSent,
  };

  try {
    const result = await exchange({ name: qname, type: qtype }, server, {
      transport,
      timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      // one attempt: a server that had to be asked twice is something the report shows
      retries: 0,
      recursionDesired,
      checkingDisabled,
      dnssecOk,
      udpPayloadSize: EDNS_UDP_PAYLOAD_SIZE,
      transports: options.transports,
      signal: options.signal,
      onEvent: options.onEvent,
    });
    const retriedOverTcp = transport === 'udp' && result.transport === 'tcp';
    return {
      ...base,
      message: toWireMessage(result.message),
      elapsed: Math.round(performance.now() - started),
      transport: retriedOverTcp ? 'tcp' : transport,
      ...(retriedOverTcp && { retriedOverTcp }),
    };
  } catch (error) {
    return {
      ...base,
      elapsed: Math.round(performance.now() - started),
      error: error instanceof Error ? error.message : 'query failed',
    };
  }
}

// the dig invocation that reproduces a query, for the debug surface
export function digCommand(
  server: string,
  qname: string,
  qtype: string,
  options: DnssecQueryOptions = {}
): string {
  const flags = ['+dnssec'];
  if (options.checkingDisabled ?? true) flags.push('+cd');
  if (!(options.recursionDesired ?? false)) flags.push('+norecurse');
  if ((options.transport ?? 'tcp') === 'tcp') flags.push('+tcp');
  return `dig ${flags.join(' ')} @${server} ${qname === '.' ? '.' : qname} ${qtype}`;
}
