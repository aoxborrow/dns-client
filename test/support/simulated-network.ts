import { ConnectionError } from '../../src/errors';
import { typeName } from '../../src/protocol/types';
import { parseIpv4, parseIpv6 } from '../../src/records/addresses';
import type { Transports } from '../../src/transports/index';
import type { Transport, TransportName } from '../../src/transports/types';
import { concatBytes, writeU16, writeU32 } from '../../src/wire/bytes';
import { decodeMessage, encodeMessage, encodeName } from '../../src/wire/index';
import type { Message, ResourceRecord } from '../../src/wire/index';
import { canonicalName, isSubdomain } from '../../src/wire/names';

// a network that exists only in memory, for testing the resolvers: servers are functions
// keyed by address, and a query to an address goes to its function. The transports have
// their own tests against real sockets; this is for everything above them, where what
// matters is which server is asked what, and in what order

// answer a query, fail it, or (undefined) never answer. A promise of one is the same,
// later: see `late`
type SimulatedReply = Uint8Array | Error | undefined;
export type SimulatedServer = (query: Message) => SimulatedReply | Promise<SimulatedReply>;

export interface SimulatedQuery {
  server: string;
  name: string;
  type: string;
  transport: TransportName;
  recursionDesired: boolean;
}

export interface SimulatedNetwork {
  transports: Transports;
  // every query sent, in order
  queries: SimulatedQuery[];
  // the queries as "server name type", for assertions
  log(): string[];
}

export function simulateNetwork(servers: Record<string, SimulatedServer>): SimulatedNetwork {
  const queries: SimulatedQuery[] = [];

  const transport = (name: TransportName): Transport => ({
    name,
    send({ endpoint, query, signal }) {
      const asked = decodeMessage(query);
      const [question] = asked.questions;
      queries.push({
        server: endpoint.host,
        name: question.name,
        type: typeName(question.type),
        transport: name,
        recursionDesired: asked.flags.rd,
      });
      const server = servers[endpoint.host];
      if (!server) {
        return Promise.reject(new ConnectionError(`Cannot reach ${endpoint.host}: no route`));
      }
      return new Promise((resolve, reject) => {
        // only the caller's timeout or abort ends the wait for a server that is silent, or
        // has not answered yet
        signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
        void Promise.resolve(server(asked)).then(reply => {
          if (signal?.aborted || reply === undefined) return;
          if (reply instanceof Error) return reject(reply);
          const bytes = Uint8Array.from(reply);
          bytes.set(query.subarray(0, 2), 0);
          resolve({ bytes, transport: name });
        });
      });
    },
    close() {},
  });

  return {
    transports: { get: transport, close() {} },
    queries,
    log: () => queries.map(query => `${query.server} ${query.name} ${query.type}`),
  };
}

// a server that answers as `server` does, `ms` milliseconds after it is asked
export function late(ms: number, server: SimulatedServer): SimulatedServer {
  return query => new Promise(resolve => setTimeout(() => resolve(server(query)), ms));
}

// ---- zones

// a record as [owner, type, value], e.g. ['www.example.com', 'A', '192.0.2.1']
export type ZoneRecord = [name: string, type: string, value: string, ttl?: number];

export interface ZoneSpec {
  zone: string;
  records?: ZoneRecord[];
  // child zone -> its nameservers, with glue addresses for the ones that have any
  delegations?: Record<string, Record<string, string[]>>;
  // answer with this rcode whatever is asked
  rcode?: number;
}

const TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28 };

function rdata(type: string, value: string): Uint8Array {
  switch (type) {
    case 'A':
      return parseIpv4(value) ?? new Uint8Array(0);
    case 'AAAA':
      return parseIpv6(value) ?? new Uint8Array(0);
    case 'NS':
    case 'CNAME':
      return encodeName(value);
    case 'MX': {
      const [preference, exchange] = value.split(' ');
      const head = new Uint8Array(2);
      writeU16(head, 0, Number(preference));
      return concatBytes([head, encodeName(exchange)]);
    }
    case 'TXT': {
      const text = new TextEncoder().encode(value);
      return concatBytes([Uint8Array.of(text.length), text]);
    }
    default:
      throw new Error(`simulated zones cannot hold ${type} records`);
  }
}

function soaRecord(zone: string, ttl: number, minimum: number): ResourceRecord {
  const suffix = zone === '.' ? '' : `.${zone}`;
  const numbers = new Uint8Array(20);
  [1, 7200, 3600, 1_209_600, minimum].forEach((value, index) =>
    writeU32(numbers, index * 4, value)
  );
  return {
    name: zone,
    type: TYPES.SOA,
    class: 1,
    ttl,
    rdata: concatBytes([encodeName(`ns1${suffix}`), encodeName(`hostmaster${suffix}`), numbers]),
    section: 'authority',
  };
}

const record = (
  [name, type, value, ttl = 300]: ZoneRecord,
  section: ResourceRecord['section']
): ResourceRecord => ({
  name,
  type: TYPES[type],
  class: 1,
  ttl,
  rdata: rdata(type, value),
  section,
});

// an authoritative server for one zone: it answers for names in the zone, refers
// questions about delegated names to the child's servers, and refuses anything else
export function zoneServer(spec: ZoneSpec): SimulatedServer {
  const zone = canonicalName(spec.zone);
  const records = spec.records ?? [];
  const at = (name: string, type?: string) =>
    records.filter(
      ([owner, recordType]) =>
        canonicalName(owner) === name && (type === undefined || recordType === type)
    );

  return query => {
    const [question] = query.questions;
    const name = canonicalName(question.name);
    const type = typeName(question.type);
    const reply = (parts: Partial<Message> & { aa?: boolean }) =>
      encodeMessage({
        id: query.id,
        flags: { qr: true, aa: parts.aa ?? false },
        questions: query.questions,
        ...parts,
      });

    if (spec.rcode !== undefined) return reply({ rcode: spec.rcode });
    if (!isSubdomain(name, zone)) return reply({ rcode: 5 });

    // a delegated name: hand the question on
    const child = Object.keys(spec.delegations ?? {})
      .map(canonicalName)
      .filter(delegated => isSubdomain(name, delegated))
      .sort((a, b) => b.length - a.length)[0];
    if (child !== undefined) {
      const nameservers = Object.entries(spec.delegations ?? {}).find(
        ([delegated]) => canonicalName(delegated) === child
      )?.[1];
      return reply({
        authorities: Object.keys(nameservers ?? {}).map(ns =>
          record([child, 'NS', ns, 172_800], 'authority')
        ),
        additionals: Object.entries(nameservers ?? {}).flatMap(([ns, addresses]) =>
          addresses.map(address =>
            record([ns, address.includes(':') ? 'AAAA' : 'A', address, 172_800], 'additional')
          )
        ),
      });
    }

    const exact = at(name, type);
    if (exact.length > 0) {
      return reply({ aa: true, answers: exact.map(entry => record(entry, 'answer')) });
    }
    const [alias] = at(name, 'CNAME');
    if (alias) {
      // the alias, and its target's records when the target is in this zone too
      const target = at(canonicalName(alias[2]), type);
      return reply({
        aa: true,
        answers: [alias, ...target].map(entry => record(entry, 'answer')),
      });
    }
    const exists = records.some(([owner]) => isSubdomain(owner, name));
    return reply({
      aa: true,
      rcode: exists || name === zone ? 0 : 3,
      authorities: [soaRecord(zone, 3600, 300)],
    });
  };
}

// a recursive resolver that knows a flat list of records, for testing `Resolver`
export function recursiveServer(records: ZoneRecord[]): SimulatedServer {
  const authority = zoneServer({ zone: '.', records });
  return query => {
    const reply = authority(query);
    if (!(reply instanceof Uint8Array)) return reply;
    // a recursive answer: recursion available, not authoritative
    reply[2] &= ~0x04;
    reply[3] |= 0x80;
    return reply;
  };
}
