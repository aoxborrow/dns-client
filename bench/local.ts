import { Resolver } from 'node:dns/promises';
import { exchange } from '../src/exchange';
import { Resolver as DnsClientResolver } from '../src/resolvers/index';
import { createTransports } from '../src/transports/index';
import { answerTo } from '../test/support/answers';
import { startFixtureServer } from '../test/support/fixture-server';

// a local benchmark: this library against Node's own resolver, both asking an in-process
// server on localhost. No network is involved, so what is measured is the cost of the
// client itself: building the query, the sockets, matching the answer, decoding it.
//
// the server runs in the same thread as the clients and its cost is the same for each of
// them, so the numbers compare the clients with each other; they are not what a query
// costs against a real resolver. Run with: yarn workspace @aoxborrow/dns-client bench

const SEQUENTIAL = 2000;
const BURST = 500;
const ROUNDS = 15;

// as many names as a burst has questions: a resolver that shares one query between callers
// asking the same thing would otherwise be measured on a tenth of the work
const NAMES = Array.from({ length: BURST }, (_, index) => `host${index}.example.com`);

interface Contender {
  label: string;
  // resolve one name, returning how many records came back
  ask(name: string): Promise<number>;
  close?(): void;
}

const percentile = (sorted: number[], p: number) =>
  sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];

async function measure(contender: Contender) {
  // connections, lazy imports and the JIT all settle before anything is timed
  for (let index = 0; index < 200; index++) await contender.ask(NAMES[index % NAMES.length]);

  const latencies: number[] = [];
  for (let index = 0; index < SEQUENTIAL; index++) {
    const started = performance.now();
    await contender.ask(NAMES[index % NAMES.length]);
    latencies.push(performance.now() - started);
  }
  latencies.sort((a, b) => a - b);

  // everything in flight at once
  const walls: number[] = [];
  for (let round = 0; round < ROUNDS; round++) {
    const started = performance.now();
    await Promise.all(
      Array.from({ length: BURST }, (_, index) => contender.ask(NAMES[index % NAMES.length]))
    );
    walls.push(performance.now() - started);
  }
  walls.sort((a, b) => a - b);
  const median = walls[Math.floor(walls.length / 2)];

  return {
    'client': contender.label,
    'sequential p50 µs': Math.round(percentile(latencies, 0.5) * 1000),
    'sequential p95 µs': Math.round(percentile(latencies, 0.95) * 1000),
    'burst median ms': Number(median.toFixed(1)),
    'burst queries/s': Math.round((BURST / median) * 1000),
  };
}

async function main() {
  const server = await startFixtureServer(({ query }) => ({ response: answerTo(query) }));

  const resolver = new Resolver({ timeout: 5000, tries: 1 });
  resolver.setServers([`${server.address}:${server.port}`]);

  const transports = createTransports();
  // TCP connections kept open and shared, which is opt-in
  const pooled = createTransports({ pipeline: true });
  const options = { port: server.port, transports };

  // the cache is off, so every question goes to the server
  const client = new DnsClientResolver({
    servers: [`${server.address}:${server.port}`],
    transports,
    cache: false,
  });

  const contenders: Contender[] = [
    {
      label: 'node:dns Resolver (c-ares, UDP)',
      ask: async name => (await resolver.resolve4(name)).length,
    },
    {
      label: 'dns-client Resolver, UDP',
      ask: async name => (await client.query(name, 'A')).records.length,
    },
    {
      label: 'dns-client single query, UDP',
      ask: async name =>
        (await exchange({ name, type: 'A' }, server.address, options)).message.answers.length,
    },
    {
      label: 'dns-client single query, TCP pipelined',
      ask: async name =>
        (
          await exchange({ name, type: 'A' }, server.address, {
            ...options,
            transports: pooled,
            transport: 'tcp',
          })
        ).message.answers.length,
    },
  ];

  const rows = [];
  for (const contender of contenders) rows.push(await measure(contender));
  console.table(rows);

  transports.close();
  pooled.close();
  await server.close();
}

void main();
