# Benchmarks

`@aoxborrow/dns` against the other ways to resolve names from Node. The latest numbers are
in [`RESULTS.md`](RESULTS.md), with the environment and date they were taken on and a
feature matrix.

## Running

```sh
yarn workspace @aoxborrow/dns bench              # the fixture server only, about two minutes
yarn workspace @aoxborrow/dns bench --network    # and the real network, about five more
```

Both rewrite `bench/RESULTS.md`. Other options:

- `--only=dns-udp,node,dig,iterative` runs some contenders only (ids in `contenders.ts`;
  `dig` and `iterative` name the dig baseline and the iterative table)
- `--quick` runs every scenario with far fewer queries, to check the harness works
- `--out=path` writes the report somewhere else

## What is measured

**On the fixture server** (`test/support/fixture-server.ts`, plus `doh-server.ts` for DoH),
in-process on localhost, every question answered with one A record. Nothing leaves the
machine, so this is the cost of the client: building the query, sockets, matching and
decoding. Each contender runs in a child process of its own. Every query asks a name not
asked before, so no cache helps except in the cache scenario.

- latency: a new client's first query (cold), and per-query latency on a warm client
- 1,000 sequential queries end to end
- throughput at 10, 100 and 1,000 queries in flight (DoH stops at 100, see `RESULTS.md`)
- cache hits: one name asked 10,000 times, and how many queries reached the server
- sockets and memory: UDP source ports and TCP connections in a burst, sockets left open,
  heap retained

**On the real network** (`--network`): the 100 names in `top-100.ts` against Cloudflare,
Google and Quad9 over UDP and DoH (DoH by IP address), `dns.lookup` through the operating
system, and iterative resolution from the root for the same 100 names (this library's
`AuthoritativeResolver` and `dig +trace`). About 1,800 queries to each public resolver
over the whole run, never more than 20 in flight, and a few hundred to the root and TLD
servers.

## Contenders

| Contender | How | Status |
| :-- | :-- | :-- |
| `@aoxborrow/dns` `Resolver` | UDP, TCP pipelined, DoH | this library |
| `@aoxborrow/dns/promises` | the `node:dns/promises` facade, UDP | this library |
| `node:dns` `Resolver` | c-ares, UDP | built in |
| `node:dns` `lookup` | getaddrinfo, the system resolver | built in, network runs only (it cannot be pointed at a server) |
| [dns2](https://www.npmjs.com/package/dns2) 3.1.1 | `UDPClient` | maintained, last release 2026-07 |
| [tangerine](https://www.npmjs.com/package/tangerine) 2.1.3 | DoH, `resolve4` | maintained. 2.2.0 came out on 2026-11-15, the day before these numbers; 2.1.3 is pinned until a release has been out a while |
| `fetch` + [dns-packet](https://www.npmjs.com/package/dns-packet) | a plain DoH client in twenty lines, POST | the baseline for DoH |
| `dig` | a process per query; `+trace` for the iterative table | BIND 9.10.6 here, the version macOS ships |
| [dns-socket](https://www.npmjs.com/package/dns-socket) | | **skipped**: unmaintained, last release 4.2.2 on 2021-05-28 |
| `Bun.dns` | | **skipped**: Bun is not installed on the machine the numbers come from |
| `Deno.resolveDns` | | **skipped**: Deno is not installed on the machine the numbers come from |
| `dnsperf` | | **skipped**: not installed on the machine the numbers come from |

Each client runs with its defaults apart from the server it is pointed at, one try per
query where it has that setting, and its cache off except in the cache scenario.

## Reading the numbers

- The fixture server shares a thread with the client it answers. That costs every
  contender the same, but it means the numbers compare clients with each other; they are
  not what a query costs against a real server.
- `@aoxborrow/dns` gives every UDP query its own socket and source port (#492), which is
  what the source-port column shows. c-ares sends every query from one socket. The extra
  sockets cost throughput at high concurrency; they are what makes a forged answer much
  harder to land (RFC 5452).
- The DoH clients that use Node's own `fetch` speak HTTP/1.1 and open a connection for each
  query in flight.
- Real-network numbers are one run from one place. The differences between clients there
  are mostly smaller than the network's own variance; compare rows within one table.
