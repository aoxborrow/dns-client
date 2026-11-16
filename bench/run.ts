import { execFile, spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { AuthoritativeResolver } from '../src/resolvers/index';
import { answerTo } from '../test/support/answers';
import { startFixtureServer } from '../test/support/fixture-server';
import { CONTENDERS, digQuery, hasCommand } from './contenders';
import type { Client, Contender, Target } from './contenders';
import { startDohServer } from './doh-server';
import { FEATURES } from './features';
import { TOP_100 as ALL_NAMES } from './top-100';

// the benchmark: this library against the other DNS clients for Node, on an in-process
// fixture server (no network: the cost of the client itself) and, with --network, against
// public resolvers and the root servers. Writes bench/RESULTS.md.
//
//   yarn workspace @aoxborrow/dns bench              the fixture server only
//   yarn workspace @aoxborrow/dns bench --network    and the real network
//   options: --only=dns-udp,node   --quick   --out=path
//
// each contender runs its fixture scenarios in a child process of its own, so one's
// sockets, timers and heap do not land on the next one's numbers

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const option = (name: string) =>
  args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);

const QUICK = flag('quick');
const COLD_RUNS = QUICK ? 5 : 30;
const WARMUP = QUICK ? 50 : 300;
const SEQUENTIAL = QUICK ? 200 : 1000;
const BURST_TOTAL = QUICK ? 500 : 2000;
const BURST_ROUNDS = QUICK ? 1 : 3;
const CONCURRENCIES = [10, 100, 1000];
const CACHE_HITS = QUICK ? 1000 : 10_000;
const MEMORY_QUERIES = QUICK ? 1000 : 10_000;
const NETWORK_COLD = QUICK ? 3 : 10;
const NETWORK_CONCURRENCY = 20;
// the names for the real-network runs; --quick takes the first ten
const TOP_100 = QUICK ? ALL_NAMES.slice(0, 10) : ALL_NAMES;

// the public resolvers, each over UDP and DoH. DoH URLs by address, so no client has a
// name to look up first
const RESOLVERS: Record<string, Target & { label: string }> = {
  cloudflare: {
    label: 'Cloudflare 1.1.1.1',
    address: '1.1.1.1',
    port: 53,
    dohUrl: 'https://1.1.1.1/dns-query',
  },
  google: {
    label: 'Google 8.8.8.8',
    address: '8.8.8.8',
    port: 53,
    dohUrl: 'https://8.8.8.8/dns-query',
  },
  quad9: {
    label: 'Quad9 9.9.9.9',
    address: '9.9.9.9',
    port: 53,
    dohUrl: 'https://9.9.9.9/dns-query',
  },
};

// ---- measuring

const percentile = (values: number[], p: number) => {
  if (values.length === 0) return NaN;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
};
const median = (values: number[]) => percentile(values, 0.5);

let counter = 0;
// a name no client has seen, so no cache anywhere helps
const freshName = () => `n${counter++}.bench.test`;

async function timed(run: () => Promise<unknown>): Promise<number> {
  const started = performance.now();
  await run();
  return performance.now() - started;
}

// `total` queries with at most `concurrency` in flight
async function pool(
  total: number,
  concurrency: number,
  run: (index: number) => Promise<unknown>
): Promise<{ failures: number }> {
  let next = 0;
  let failures = 0;
  const worker = async () => {
    while (next < total) {
      const index = next++;
      try {
        await run(index);
      } catch {
        failures++;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, total) }, worker));
  return { failures };
}

const gc = () => (globalThis as { gc?: () => void }).gc?.();

const socketHandles = () =>
  process
    .getActiveResourcesInfo()
    .filter(name => /UDPWrap|TCPSocketWrap|TCPWrap|TLSWrap/.test(name)).length;

// ---- the fixture scenarios, for one contender, in a child process

export interface FixtureResult {
  id: string;
  coldMs: number;
  coldP95Ms: number;
  warmP50Us: number;
  warmP95Us: number;
  sequentialMs: number;
  burst: Record<number, number>;
  cacheHitsPerSecond?: number;
  cacheServerQueries?: number;
  burstInFlight: number;
  burstSourcePorts: number;
  burstConnections: number;
  socketsLeftOpen: number;
  retainedHeapKb?: number;
  failures: number;
}

async function fixtureWorker(id: string): Promise<FixtureResult> {
  const contender = CONTENDERS.find(each => each.id === id);
  if (!contender) throw new Error(`no contender ${id}`);
  const server = await startFixtureServer(({ query }) => ({ response: answerTo(query) }));
  // the HTTP server sees connections; requests are counted here
  let dohRequests = 0;
  const doh = await startDohServer(({ query }) => {
    dohRequests++;
    return { response: answerTo(query) };
  });
  const target: Target = { address: server.address, port: server.port, dohUrl: doh.url };
  let failures = 0;
  const ask = async (client: Client, name: string) => {
    if ((await client.ask(name)) !== 1) failures++;
  };
  // over HTTP/1.1 a DoH client opens a connection per query in flight, and the local
  // server's accept queue (128 on macOS) resets the rest: DoH stops at 100 in flight
  const maxInFlight = contender.transport === 'DoH' ? 100 : 1000;

  // sockets and memory first, while the process is new: one burst at once from a new
  // client, then many more queries with the client kept alive
  const fresh = contender.create(target, { cache: false });
  const connectionsBefore = server.tcpConnections + doh.connections;
  failures += (await pool(maxInFlight, maxInFlight, () => ask(fresh, freshName()))).failures;
  const burstSourcePorts = new Set(
    server.received.filter(query => query.transport === 'udp').map(query => query.sourcePort)
  ).size;
  const burstConnections = server.tcpConnections + doh.connections - connectionsBefore;
  // the server's own record of queries is not the client's memory
  server.received.length = 0;
  await new Promise(resolve => setTimeout(resolve, 50));
  gc();
  const handlesBefore = socketHandles();
  const heapBefore = process.memoryUsage().heapUsed;
  for (let done = 0; done < MEMORY_QUERIES; done += 100) {
    failures += (await pool(100, 100, () => ask(fresh, freshName()))).failures;
  }
  server.received.length = 0;
  // give closed sockets a turn of the loop to go away
  await new Promise(resolve => setTimeout(resolve, 50));
  gc();
  const retainedHeapKb = (globalThis as { gc?: unknown }).gc
    ? Math.round((process.memoryUsage().heapUsed - heapBefore) / 1024)
    : undefined;
  const socketsLeftOpen = socketHandles() - handlesBefore;
  await fresh.close?.();

  // cold: a new client, its first query. Modules are already loaded
  const cold: number[] = [];
  for (let run = 0; run < COLD_RUNS; run++) {
    const client = contender.create(target, { cache: false });
    cold.push(await timed(() => ask(client, freshName())));
    await client.close?.();
  }

  // warm: one client, sequential queries after the sockets and the JIT have settled
  const warm: number[] = [];
  const client = contender.create(target, { cache: false });
  for (let index = 0; index < WARMUP; index++) await ask(client, freshName());
  const sequentialStarted = performance.now();
  for (let index = 0; index < SEQUENTIAL; index++) {
    warm.push(await timed(() => ask(client, freshName())));
  }
  const sequentialMs = performance.now() - sequentialStarted;

  // bursts: a fixed number of queries at several concurrencies, queries per second
  const burst: Record<number, number> = {};
  for (const concurrency of CONCURRENCIES.filter(each => each <= maxInFlight)) {
    const rounds: number[] = [];
    for (let round = 0; round < BURST_ROUNDS; round++) {
      const wall = await timed(async () => {
        failures += (await pool(BURST_TOTAL, concurrency, () => ask(client, freshName()))).failures;
      });
      rounds.push((BURST_TOTAL / wall) * 1000);
    }
    burst[concurrency] = Math.round(median(rounds));
  }
  await client.close?.();

  // cache hits: the same name, over and over, and how many queries reached the server
  let cacheHitsPerSecond: number | undefined;
  let cacheServerQueries: number | undefined;
  if (contender.caches) {
    const cached = contender.create(target, { cache: true });
    await ask(cached, 'cached.bench.test');
    const before = server.received.length + dohRequests;
    const wall = await timed(async () => {
      for (let index = 0; index < CACHE_HITS; index++) await ask(cached, 'cached.bench.test');
    });
    cacheHitsPerSecond = Math.round((CACHE_HITS / wall) * 1000);
    cacheServerQueries = server.received.length + dohRequests - before;
    await cached.close?.();
  }

  await doh.close();
  await server.close();
  return {
    id,
    coldMs: median(cold),
    coldP95Ms: percentile(cold, 0.95),
    warmP50Us: Math.round(median(warm) * 1000),
    warmP95Us: Math.round(percentile(warm, 0.95) * 1000),
    sequentialMs: Math.round(sequentialMs),
    burst,
    cacheHitsPerSecond,
    cacheServerQueries,
    burstInFlight: maxInFlight,
    burstSourcePorts,
    burstConnections,
    socketsLeftOpen,
    retainedHeapKb,
    failures,
  };
}

// ---- the network scenarios, for one contender and one resolver, in a child process

export interface NetworkResult {
  id: string;
  resolver: string;
  coldMs: number;
  p50Ms: number;
  p95Ms: number;
  sequentialMs: number;
  burstMs: number;
  failures: number;
}

async function networkWorker(id: string, resolverKey: string): Promise<NetworkResult> {
  const contender = CONTENDERS.find(each => each.id === id);
  if (!contender) throw new Error(`no contender ${id}`);
  const target = RESOLVERS[resolverKey] ?? RESOLVERS.cloudflare;
  let failures = 0;
  const ask = async (client: Client, name: string) => {
    try {
      if ((await client.ask(name)) < 1) failures++;
    } catch {
      failures++;
    }
  };

  const cold: number[] = [];
  for (let run = 0; run < NETWORK_COLD; run++) {
    const client = contender.create(target, { cache: false });
    cold.push(await timed(() => ask(client, TOP_100[run])));
    await client.close?.();
  }

  const client = contender.create(target, { cache: false });
  const latencies: number[] = [];
  const sequentialStarted = performance.now();
  for (const name of TOP_100) latencies.push(await timed(() => ask(client, name)));
  const sequentialMs = performance.now() - sequentialStarted;
  await client.close?.();

  const burstClient = contender.create(target, { cache: false });
  const burstMs = await timed(() =>
    pool(TOP_100.length, NETWORK_CONCURRENCY, index => ask(burstClient, TOP_100[index]))
  );
  await burstClient.close?.();

  return {
    id,
    resolver: resolverKey,
    coldMs: median(cold),
    p50Ms: median(latencies),
    p95Ms: percentile(latencies, 0.95),
    sequentialMs: Math.round(sequentialMs),
    burstMs: Math.round(burstMs),
    failures,
  };
}

// ---- running a worker

function inChild<T>(workerArgs: string[]): Promise<T> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        '--expose-gc',
        ...process.execArgv,
        fileURLToPath(import.meta.url),
        '--worker',
        ...workerArgs,
        ...(QUICK ? ['--quick'] : []),
      ],
      { stdio: ['ignore', 'pipe', 'inherit'] }
    );
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += String(chunk)));
    child.on('error', reject);
    child.on('close', code => {
      const line = output.trim().split('\n').pop() ?? '';
      if (code !== 0) reject(new Error(`worker ${workerArgs.join(' ')} exited with ${code}`));
      else resolve(JSON.parse(line) as T);
    });
  });
}

// ---- dig, the native baseline

async function digFixture(): Promise<{ wallMs: number; queryMs: number }> {
  const server = await startFixtureServer(({ query }) => ({ response: answerTo(query) }));
  const walls: number[] = [];
  const queries: number[] = [];
  for (let run = 0; run < COLD_RUNS; run++) {
    const result = await digQuery(server, freshName());
    walls.push(result.wallMs);
    if (result.queryMs !== undefined) queries.push(result.queryMs);
  }
  await server.close();
  return { wallMs: median(walls), queryMs: median(queries) };
}

async function digNetwork(target: Target): Promise<NetworkResult & { queryP50Ms: number }> {
  const walls: number[] = [];
  const queries: number[] = [];
  let failures = 0;
  for (const name of TOP_100) {
    try {
      const result = await digQuery(target, name);
      walls.push(result.wallMs);
      if (result.queryMs !== undefined) queries.push(result.queryMs);
    } catch {
      failures++;
    }
  }
  return {
    id: 'dig',
    resolver: '',
    coldMs: NaN,
    p50Ms: median(walls),
    p95Ms: percentile(walls, 0.95),
    sequentialMs: Math.round(walls.reduce((a, b) => a + b, 0)),
    burstMs: NaN,
    queryP50Ms: median(queries),
    failures,
  };
}

// ---- iterative resolution from the root, over the top-100 list

interface IterativeResult {
  label: string;
  totalS: number;
  p50Ms: number;
  p95Ms: number;
  queriesPerName: number;
  failures: number;
}

async function iterative(): Promise<IterativeResult[]> {
  const results: IterativeResult[] = [];
  const run = async (
    label: string,
    resolverFor: (onQuery: () => void) => { resolve(name: string): Promise<unknown>; close(): void }
  ) => {
    let queries = 0;
    let failures = 0;
    const times: number[] = [];
    const started = performance.now();
    let shared: ReturnType<typeof resolverFor> | undefined;
    for (const name of TOP_100) {
      const resolver = resolverFor(() => queries++);
      shared = resolver;
      times.push(
        await timed(async () => {
          try {
            await resolver.resolve(name);
          } catch {
            failures++;
          }
        })
      );
    }
    shared?.close();
    results.push({
      label,
      totalS: Number(((performance.now() - started) / 1000).toFixed(1)),
      p50Ms: median(times),
      p95Ms: percentile(times, 0.95),
      queriesPerName: Number((queries / TOP_100.length).toFixed(1)),
      failures,
    });
  };

  // one resolver for the whole list: its cache of zone cuts and nameserver addresses grows
  let sharedResolver: AuthoritativeResolver | undefined;
  let sharedCount: (() => void) | undefined;
  await run('@aoxborrow/dns AuthoritativeResolver, one for the list (cache shared)', onQuery => {
    sharedCount = onQuery;
    sharedResolver ??= new AuthoritativeResolver({
      addressFamily: 'ipv4',
      onEvent: event => {
        if (event.event === 'query') sharedCount?.();
      },
    });
    const resolver = sharedResolver;
    return { resolve: name => resolver.query(name, 'A'), close: () => resolver.close() };
  });

  // a new resolver per name: every walk starts at the root, as `dig +trace` does
  await run('@aoxborrow/dns AuthoritativeResolver, new for each name', onQuery => {
    const resolver = new AuthoritativeResolver({
      addressFamily: 'ipv4',
      onEvent: event => {
        if (event.event === 'query') onQuery();
      },
    });
    return {
      resolve: async name => {
        try {
          return await resolver.query(name, 'A');
        } finally {
          resolver.close();
        }
      },
      close: () => undefined,
    };
  });

  await run('dig +trace, a process per name', onQuery => ({
    resolve: async name => {
      const { stdout } = await promisify(execFile)('dig', [
        '-4',
        '+trace',
        '+tries=1',
        '+time=3',
        name,
        'A',
      ]);
      for (const _ of stdout.matchAll(/;; Received \d+ bytes/g)) onQuery();
      if (!/\sIN\s+(A|CNAME)\s/.test(stdout.split(';; Received').slice(-2).join(''))) {
        throw new Error('no answer');
      }
    },
    close: () => undefined,
  }));
  return results;
}

// ---- the report

const number = (value: number | undefined, digits = 0) =>
  value === undefined || Number.isNaN(value)
    ? 'n/a'
    : value.toLocaleString('en-US', {
        maximumFractionDigits: digits,
        minimumFractionDigits: digits,
      });

function table(headers: string[], rows: (string | number)[][]): string {
  const align = headers.map((_, index) => (index === 0 ? ':--' : '--:'));
  return [headers, align, ...rows].map(row => `| ${row.join(' | ')} |`).join('\n');
}

const labelOf = (id: string) => CONTENDERS.find(each => each.id === id)?.label ?? id;
const transportOf = (id: string) => CONTENDERS.find(each => each.id === id)?.transport ?? '';

async function environment(): Promise<string[]> {
  const cpus = os.cpus();
  let osName = `${os.type()} ${os.release()}`;
  if (process.platform === 'darwin') {
    try {
      const { stdout } = await promisify(execFile)('sw_vers', ['-productVersion']);
      osName = `macOS ${stdout.trim()} (Darwin ${os.release()})`;
    } catch {
      // the kernel name and release will do
    }
  }
  const version = (name: string) => {
    try {
      const manifest = JSON.parse(
        readFileSync(path.join(here, '../../../node_modules', name, 'package.json'), 'utf8')
      ) as { version: string };
      return manifest.version;
    } catch {
      return '?';
    }
  };
  let digVersion = 'not installed';
  try {
    const { stderr, stdout } = await promisify(execFile)('dig', ['-v']);
    digVersion = (stderr || stdout).trim();
  } catch {
    // not installed
  }
  return [
    `- **Date:** ${new Date().toISOString().slice(0, 10)}`,
    `- **CPU:** ${cpus[0]?.model ?? 'unknown'}, ${cpus.length} cores`,
    `- **OS:** ${osName}`,
    `- **Node:** ${process.version}`,
    `- **Contenders:** dns2 ${version('dns2')}, tangerine ${version('tangerine')}, dns-packet ${version('dns-packet')} (for the fetch DoH client), ${digVersion}`,
  ];
}

async function skipped(): Promise<string[]> {
  const lines: string[] = [];
  for (const [command, reason] of [
    ['bun', '`Bun.dns`'],
    ['deno', '`Deno.resolveDns`'],
    ['dnsperf', '`dnsperf`'],
  ] as const) {
    if (!(await hasCommand(command, ['--version']))) {
      lines.push(
        `- ${reason}: \`${command}\` is not installed on the machine these numbers come from.`
      );
    } else {
      lines.push(
        `- ${reason}: \`${command}\` is installed, but the harness does not drive it yet.`
      );
    }
  }
  lines.push(
    '- `dns-socket`: unmaintained. Its last release, 4.2.2, was published on 2021-05-28; it is not a contender.'
  );
  return lines;
}

async function main() {
  if (args[0] === '--worker') {
    const [, kind, id, resolver] = args;
    const result = kind === 'fixture' ? await fixtureWorker(id) : await networkWorker(id, resolver);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    // clients that leave sockets open must not keep the worker alive
    process.exit(0);
  }

  const only = option('only')?.split(',');
  const chosen = CONTENDERS.filter(each => !only || only.includes(each.id));
  const out = option('out') ?? path.join(here, 'RESULTS.md');
  const sections: string[] = [];

  // fixture
  const fixture: FixtureResult[] = [];
  for (const contender of chosen.filter(each => !each.networkOnly)) {
    console.error(`fixture: ${contender.label}`);
    fixture.push(await inChild<FixtureResult>(['fixture', contender.id]));
  }
  const hasDig = await hasCommand('dig');
  const dig = hasDig && (!only || only.includes('dig')) ? await digFixture() : undefined;

  sections.push(
    '## On the fixture server',
    '',
    'An in-process server on localhost, UDP, TCP and plain-HTTP DoH on one port each, answering every question with one A record. No network is involved, so this measures the client: building the query, the sockets, matching and decoding the answer. The server shares the thread with the client it is answering, which costs every contender the same. Every query asks a name not asked before, so no cache helps unless the scenario is about the cache.',
    '',
    '### Latency',
    '',
    `Cold: a new client and its first query, median of ${COLD_RUNS} (modules already loaded). Warm: ${SEQUENTIAL.toLocaleString('en-US')} sequential queries on one client after ${WARMUP} to settle, per query. The last column is those ${SEQUENTIAL.toLocaleString('en-US')} queries end to end.`,
    '',
    table(
      [
        'Client',
        'Transport',
        'cold ms (median)',
        'cold ms (p95)',
        'warm p50 µs',
        'warm p95 µs',
        `${SEQUENTIAL.toLocaleString('en-US')} sequential, ms`,
      ],
      [
        ...fixture.map(result => [
          labelOf(result.id),
          transportOf(result.id),
          number(result.coldMs, 2),
          number(result.coldP95Ms, 2),
          number(result.warmP50Us),
          number(result.warmP95Us),
          number(result.sequentialMs),
        ]),
        ...(dig
          ? [
              [
                '`dig`, a process per query',
                'process',
                number(dig.wallMs, 1),
                'n/a',
                `${number(dig.queryMs)} ms*`,
                'n/a',
                'n/a',
              ],
            ]
          : []),
      ]
    ),
    '',
    dig
      ? '\\* `dig`\'s own "Query time", which leaves out starting the process; it reports whole milliseconds.\n'
      : '',
    '### Throughput',
    '',
    `${BURST_TOTAL.toLocaleString('en-US')} queries with at most this many in flight, queries per second (median of ${BURST_ROUNDS}).`,
    '',
    table(
      ['Client', ...CONCURRENCIES.map(each => `${each.toLocaleString('en-US')} in flight`)],
      fixture.map(result => [
        labelOf(result.id),
        ...CONCURRENCIES.map(each => (each in result.burst ? number(result.burst[each]) : 'n/a†')),
      ])
    ),
    '',
    "† DoH over HTTP/1.1 opens a connection for each query in flight. Past about 128 at once the local server's accept queue (macOS `kern.ipc.somaxconn`) resets connections, which measures the test server, so DoH stops at 100.",
    '',
    '### Cache hits',
    '',
    `The same name ${CACHE_HITS.toLocaleString('en-US')} times in a row on a client with its cache on, and how many of those queries reached the server.`,
    '',
    table(
      ['Client', 'answers per second', 'queries that reached the server'],
      fixture.map(result =>
        result.cacheHitsPerSecond === undefined
          ? [labelOf(result.id), 'no cache', 'n/a']
          : [
              labelOf(result.id),
              number(result.cacheHitsPerSecond),
              number(result.cacheServerQueries),
            ]
      )
    ),
    '',
    '### Sockets and memory',
    '',
    `Run first, in a new process. A new client sends 1,000 queries at once (DoH: 100): the UDP source ports the server saw and the TCP connections it accepted. Then ${MEMORY_QUERIES.toLocaleString('en-US')} more in bursts of 100: the sockets still open after them, and the heap retained after a forced GC with the client still alive. Memory numbers are noisy at this size; read them as orders of magnitude.`,
    '',
    table(
      [
        'Client',
        'queries at once',
        'UDP source ports',
        'TCP connections',
        'sockets open after',
        'heap retained, KB',
      ],
      fixture.map(result => [
        labelOf(result.id),
        number(result.burstInFlight),
        number(result.burstSourcePorts),
        number(result.burstConnections),
        number(result.socketsLeftOpen),
        number(result.retainedHeapKb),
      ])
    ),
    '',
    fixture.some(result => result.failures > 0)
      ? `Failed or empty answers: ${fixture
          .filter(result => result.failures > 0)
          .map(result => `${labelOf(result.id)} ${result.failures}`)
          .join(', ')}.\n`
      : 'Every query got its answer.\n'
  );

  // network
  if (flag('network')) {
    sections.push(
      '## On the real network',
      '',
      `The ${TOP_100.length} names in \`bench/top-100.ts\`, A records, against three public resolvers over UDP and DoH (DoH URLs by IP address). Cold: a new client's first query, median of ${NETWORK_COLD}. Sequential: the ${TOP_100.length} names one after another on one client. Burst: the ${TOP_100.length} names with ${NETWORK_CONCURRENCY} in flight. Popular names are in every resolver's cache, so this is mostly round-trip time to the resolver; the differences between clients are small next to the network's own variance. One run, from one place: compare rows within a table, not across tables.`,
      ''
    );
    for (const [key, target] of Object.entries(RESOLVERS)) {
      const rows: NetworkResult[] = [];
      for (const contender of chosen.filter(each => each.id !== 'lookup')) {
        console.error(`network ${key}: ${contender.label}`);
        rows.push(await inChild<NetworkResult>(['network', contender.id, key]));
      }
      const digRow =
        hasDig && (!only || only.includes('dig')) ? await digNetwork(target) : undefined;
      sections.push(
        `### ${target.label}`,
        '',
        table(
          [
            'Client',
            'Transport',
            'cold ms',
            'p50 ms',
            'p95 ms',
            `${TOP_100.length} sequential, ms`,
            `${TOP_100.length} in a burst, ms`,
            'failed',
          ],
          [
            ...rows.map(row => [
              labelOf(row.id),
              transportOf(row.id),
              number(row.coldMs, 1),
              number(row.p50Ms, 1),
              number(row.p95Ms, 1),
              number(row.sequentialMs),
              number(row.burstMs),
              number(row.failures),
            ]),
            ...(digRow
              ? [
                  [
                    '`dig`, a process per query',
                    'process',
                    'n/a',
                    `${number(digRow.p50Ms, 1)} (query ${number(digRow.queryP50Ms)})`,
                    number(digRow.p95Ms, 1),
                    number(digRow.sequentialMs),
                    'n/a',
                    number(digRow.failures),
                  ],
                ]
              : []),
          ]
        ),
        ''
      );
      if (rows.some(row => transportOf(row.id) === 'DoH' && row.failures > 0)) {
        sections.push(
          "DoH failures here are HTTP 505s: some of this resolver's sites answer only HTTP/2, as RFC 8484 §5.2 recommends, and the clients built on Node's own `fetch` speak HTTP/1.1. tangerine brings undici 8, which negotiates HTTP/2. `@aoxborrow/dns` takes a `fetch` option for a client that does.",
          ''
        );
      }
    }
    if (chosen.some(each => each.id === 'lookup')) {
      console.error('network: dns.lookup');
      const row = await inChild<NetworkResult>(['network', 'lookup', 'system']);
      sections.push(
        "### The operating system's resolver",
        '',
        "`dns.lookup` cannot be pointed at a server: it asks getaddrinfo, which asks whatever this machine is set up to use, through the system's own cache (mDNSResponder on macOS). After the first pass that cache answers, so this row measures the system cache and the thread pool, not a DNS client.",
        '',
        table(
          [
            'Client',
            'cold ms',
            'p50 ms',
            'p95 ms',
            `${TOP_100.length} sequential, ms`,
            `${TOP_100.length} in a burst, ms`,
            'failed',
          ],
          [
            [
              labelOf(row.id),
              number(row.coldMs, 1),
              number(row.p50Ms, 2),
              number(row.p95Ms, 2),
              number(row.sequentialMs),
              number(row.burstMs),
              number(row.failures),
            ],
          ]
        ),
        ''
      );
    }
    if (!only || only.includes('iterative')) {
      console.error('network: iterative');
      const rows = await iterative();
      sections.push(
        '### Iterative resolution from the root',
        '',
        `Each of the ${TOP_100.length} names resolved from the root servers down, over IPv4 UDP, one name at a time. Only this library and \`dig +trace\` do this; the others ask a recursive resolver. \`dig +trace\` takes the root server list from the configured resolver and does not reuse anything between names, so it compares with the "new for each name" row.`,
        '',
        table(
          [
            'Resolver',
            'total, s',
            'per name p50 ms',
            'per name p95 ms',
            'queries per name',
            'failed',
          ],
          rows.map(row => [
            row.label,
            number(row.totalS, 1),
            number(row.p50Ms),
            number(row.p95Ms),
            number(row.queriesPerName, 1),
            number(row.failures),
          ])
        ),
        ''
      );
    }
  } else {
    sections.push('## On the real network', '', 'Not run. Run with `--network`.', '');
  }

  const report = [
    '# Benchmarks',
    '',
    `Written by \`bench/run.ts\`. Reproduce with \`yarn workspace @aoxborrow/dns bench${flag('network') ? ' --network' : ''}\`; see \`bench/README.md\`.`,
    '',
    ...(await environment()),
    '',
    'Not measured:',
    '',
    ...(await skipped()),
    '',
    ...sections,
    FEATURES,
  ].join('\n');
  writeFileSync(out, report);
  console.error(`wrote ${out}`);
}

void main().catch(error => {
  console.error(error);
  process.exit(1);
});
