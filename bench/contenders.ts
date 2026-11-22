import { execFile } from 'node:child_process';
import nodeDns from 'node:dns';
import { promisify } from 'node:util';
import packet from 'dns-packet';
import dns2 from 'dns2';
import Tangerine from 'tangerine';
import { Resolver as FacadeResolver } from '../src/promises/index';
import { Resolver } from '../src/resolvers/index';
import { createTransports } from '../src/transports/index';

// every client the benchmark measures, behind one interface: make a client for a target,
// ask it for a name's A records, close it. Each is used with its own defaults apart from
// the server it is pointed at, one try per query where it has a setting for that, and
// its cache off unless the scenario is about the cache

export interface Target {
  // a UDP/TCP server
  address: string;
  port: number;
  // the same service over DNS-over-HTTPS
  dohUrl: string;
}

export interface Client {
  // resolve a name's A records and say how many came back
  ask(name: string): Promise<number>;
  close?(): void | Promise<void>;
}

export interface Contender {
  label: string;
  // a short id for the command line
  id: string;
  // what it is and how it talks, for the tables
  transport: 'UDP' | 'TCP' | 'DoH' | 'system' | 'process';
  // whether it has a cache to measure
  caches: boolean;
  // only on the real network: it cannot be pointed at the fixture server
  networkOnly?: boolean;
  create(target: Target, options: { cache: boolean }): Client;
}

const TIMEOUT = 5000;

export const CONTENDERS: Contender[] = [
  {
    id: 'dns-udp',
    label: '@aoxborrow/dns Resolver',
    transport: 'UDP',
    caches: true,
    create(target, { cache }) {
      const resolver = new Resolver({
        servers: [{ address: target.address, port: target.port }],
        cache: cache ? undefined : false,
        timeout: TIMEOUT,
        retries: 0,
      });
      return {
        ask: async name => (await resolver.query(name, 'A')).records.length,
        close: () => resolver.close(),
      };
    },
  },
  {
    id: 'dns-tcp',
    label: '@aoxborrow/dns Resolver, TCP pipelined',
    transport: 'TCP',
    caches: true,
    create(target, { cache }) {
      // TCP connections kept open and shared, which is opt-in
      const transports = createTransports({ pipeline: true });
      const resolver = new Resolver({
        servers: [{ address: target.address, port: target.port }],
        transport: 'tcp',
        transports,
        cache: cache ? undefined : false,
        timeout: TIMEOUT,
        retries: 0,
      });
      return {
        ask: async name => (await resolver.query(name, 'A')).records.length,
        close: () => {
          resolver.close();
          transports.close();
        },
      };
    },
  },
  {
    id: 'dns-doh',
    label: '@aoxborrow/dns Resolver, DoH',
    transport: 'DoH',
    caches: true,
    create(target, { cache }) {
      const transports = createTransports();
      const resolver = new Resolver({
        servers: [{ address: target.address, url: target.dohUrl }],
        transport: 'doh',
        transports,
        cache: cache ? undefined : false,
        timeout: TIMEOUT,
        retries: 0,
      });
      return {
        ask: async name => (await resolver.query(name, 'A')).records.length,
        close: () => {
          resolver.close();
          transports.close();
        },
      };
    },
  },
  {
    id: 'dns-facade',
    label: '@aoxborrow/dns/promises resolve4',
    transport: 'UDP',
    caches: true,
    create(target, { cache }) {
      const resolver = new FacadeResolver({
        timeout: TIMEOUT,
        tries: 1,
        cache: cache ? undefined : false,
      });
      resolver.setServers([`${target.address}:${target.port}`]);
      return {
        ask: async name => (await resolver.resolve4(name)).length,
        close: () => resolver.close(),
      };
    },
  },
  {
    id: 'node',
    label: 'node:dns Resolver (c-ares)',
    transport: 'UDP',
    // c-ares has a query cache, which Node turns off; it is measured as it is
    caches: true,
    create(target) {
      const resolver = new nodeDns.promises.Resolver({ timeout: TIMEOUT, tries: 1 });
      resolver.setServers([`${target.address}:${target.port}`]);
      return {
        ask: async name => (await resolver.resolve4(name)).length,
        close: () => resolver.cancel(),
      };
    },
  },
  {
    id: 'lookup',
    label: 'node:dns lookup (getaddrinfo)',
    transport: 'system',
    caches: false,
    networkOnly: true,
    create() {
      return {
        ask: async name => (await nodeDns.promises.lookup(name, { family: 4, all: true })).length,
      };
    },
  },
  {
    id: 'dns2',
    label: 'dns2 UDPClient',
    transport: 'UDP',
    caches: false,
    create(target) {
      const resolve = dns2.UDPClient({ dns: target.address, port: target.port, timeout: TIMEOUT });
      return {
        ask: async name =>
          (await resolve(name, 'A')).answers.filter(answer => answer.type === 1).length,
      };
    },
  },
  {
    id: 'tangerine',
    label: 'tangerine (DoH)',
    transport: 'DoH',
    caches: true,
    create(target, { cache }) {
      const url = new URL(target.dohUrl);
      const resolver = new Tangerine({
        servers: new Set([url.port ? `${url.hostname}:${url.port}` : url.hostname]),
        protocol: url.protocol === 'http:' ? 'http' : 'https',
        timeout: TIMEOUT,
        tries: 1,
        cache: cache ? new Map() : false,
      });
      return { ask: async name => (await resolver.resolve4(name)).length };
    },
  },
  {
    id: 'fetch-doh',
    label: 'fetch + dns-packet (DoH)',
    transport: 'DoH',
    caches: false,
    create(target) {
      let id = 0;
      return {
        async ask(name) {
          const query = packet.encode({
            type: 'query',
            id: (id = (id + 1) & 0xffff),
            flags: packet.RECURSION_DESIRED,
            questions: [{ type: 'A', name }],
          });
          const response = await fetch(target.dohUrl, {
            method: 'POST',
            headers: {
              'content-type': 'application/dns-message',
              'accept': 'application/dns-message',
            },
            body: Uint8Array.from(query),
            signal: AbortSignal.timeout(TIMEOUT),
          });
          const decoded = packet.decode(Buffer.from(await response.arrayBuffer()));
          return (decoded.answers ?? []).filter(answer => answer.type === 'A').length;
        },
      };
    },
  },
];

const run = promisify(execFile);

// `dig`, one process per query: what a query costs from the shell. Its own `Query time`
// line is kept too, which leaves out the process start
export async function digQuery(
  target: Pick<Target, 'address' | 'port'>,
  name: string,
  extra: string[] = []
): Promise<{ wallMs: number; queryMs: number | undefined }> {
  const started = performance.now();
  const { stdout } = await run('dig', [
    `@${target.address}`,
    '-p',
    String(target.port),
    '+tries=1',
    '+time=5',
    ...extra,
    name,
    'A',
  ]);
  const wallMs = performance.now() - started;
  const times = [...stdout.matchAll(/Query time: (\d+) msec/g)].map(match => Number(match[1]));
  return { wallMs, queryMs: times.length ? times.reduce((a, b) => a + b, 0) : undefined };
}

export async function hasCommand(command: string, args = ['-v']): Promise<boolean> {
  try {
    await run(command, args);
    return true;
  } catch (error) {
    // present but unhappy with the flag still counts
    return (error as { code?: unknown }).code !== 'ENOENT';
  }
}
