# dns-client

[![npm version](https://img.shields.io/npm/v/@aoxborrow/dns-client.svg)](https://www.npmjs.com/package/@aoxborrow/dns-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org)

> A fully-typed DNS client with support for UDP, TCP, and DoH.

- **30+ Record Types** - All common DNS records parsed into strongly-typed objects
- **Multiple Transports** - UDP, TCP, and DoH support with automatic TCP fallback for truncation
- **Authoritative Mode** - Iterative resolution from root servers with hop-by-hop trace (similar to `dig +trace`)
- **DNSSEC Support** - Query and validate DNSSEC records (DNSKEY, DS, RRSIG, NSEC, NSEC3)
- **Advanced Features** - Parallel queries, concurrency control, query caching, retries with backoff

<!-- - support for 30+ DNS record types
- DNS records parsed into strongly-typed objects
- authoritative and stub modes of operation
- full resolution trace similar to `dig +trace`
- parallel query execution with concurrency control
- TCP fallback for truncated UDP responses
- configurable query and host cache
- configurable retries with exponential backoff -->

| Transport | Requirements                                                       |
| --------- | ------------------------------------------------------------------ |
| `udp`     | Node.js only (uses `dgram` module)                                 |
| `tcp`     | Node.js only (uses `net` module)                                   |
| `doh`     | Any runtime with `fetch` global (Node.js 18+, Deno, Bun, browsers) |

## Installation

```bash
npm install @aoxborrow/dns-client
```

### Basic Queries

```typescript
import { DnsClient } from '@aoxborrow/dns-client';

// create a client with default options
const client = new DnsClient();

// query multiple record types
const answers: DnsAnswer[] = await client.query({
  query: 'example.com',
  types: ['A', 'MX', 'TXT'],
});

// execute multiple queries in parallel
const answers: DnsAnswer[] = await client.queryAll([
  {
    query: 'example.com',
    types: ['A', 'AAAA', 'NS'],
  },
  {
    query: 'www.example.com',
    types: ['CNAME'],
  },
]);

// extract records from answers
const records: DnsRecord[] = answers.flatMap(answer => answer.records);
```

### Query with Options

```typescript
import { DnsClient } from '@aoxborrow/dns-client';

// configure client with default options
const client = new DnsClient({
  server: '1.1.1.1', // DNS server IP or hostname (default: '1.1.1.1' or root servers for authoritative mode)
  transport: 'udp', // transport protocol: 'udp' | 'tcp' | 'doh' (default: 'udp')
  authoritative: false, // resolution follows referrals iteratively from root (default: false)
  flags: ['RD'], // list of DNS query flags: 'RD' (Recursion Desired), 'CD' (Checking Disabled), 'DO' (DNSSEC OK) (default: ['RD'])
  tcpFallback: true, // retry over TCP if the UDP response has TC=1 (truncated) (default: true)
  timeout: 5000, // timeout in milliseconds (default: 5000)
  retries: 0, // number of retry attempts (default: 0)
  backoff: 100, // base delay for exponential backoff in ms (default: 100ms)
  signal: AbortSignal.timeout(10_000), // for cancellation/timeout
  cache: true, // enable query cache (default: true)
  cacheSize: 1000, // maximum cache entries (default: 1000)
  concurrency: 10, // maximum concurrent queries (default: 10)
});

// set/override server and flags per query
const answers: DnsAnswer[] = await client.query({
  query: 'example.com',
  types: ['A', 'AAAA'],
  server: 'ns1.example.com', // set the nameserver for this query
  flags: ['CD', 'DO'], // override the DNS flags for this query (completely replaces client flags)
});

// execute multiple queries in parallel with overrides
const answers: DnsAnswer[] = await client.queryAll([
  {
    query: 'example.com',
    types: ['NSEC3', 'DNSKEY', 'DS'],
    server: '8.8.8.8',
    flags: ['CD', 'DO', 'RD'], // override the DNS flags for this query (completely replaces client flags)
  },
  {
    query: 'www.example.com',
    types: ['CNAME'],
    server: 'ns1.example.com',
    // server and flags are optional
  },
]);
```

### Authoritative Queries + Trace

```typescript
import { DnsClient } from '@aoxborrow/dns-client';

// perform recursive resolution starting from root servers
const client = new DnsClient({
  authoritative: true,
  // flags: [], // RD flag disabled by default for authoritative mode
});
const answers: DnsAnswer[] = await client.query({
  query: 'example.com',
  types: ['NS'],
});

// each answer includes a full resolution trace of delegation hops
answers.forEach(answer => {
  console.log('Trace:', answer.trace);
});
```

### DNS-over-HTTPS (DoH)

```typescript
import { DnsClient } from '@aoxborrow/dns-client';

// use DoH with Cloudflare
const client = new DnsClient({
  server: 'https://cloudflare-dns.com/dns-query',
  transport: 'doh',
  // authoritative: false, // unavailable for DoH transport
});
const answers: DnsAnswer[] = await client.query({
  query: 'example.com',
  types: ['A'],
});
```

**Popular DoH Providers:**

| Provider   | DoH Server URL                         |
| ---------- | -------------------------------------- |
| Cloudflare | `https://cloudflare-dns.com/dns-query` |
| Google     | `https://dns.google/dns-query`         |
| Quad9      | `https://dns.quad9.net/dns-query`      |
| OpenDNS    | `https://doh.opendns.com/dns-query`    |

### DNSSEC Queries

Query and validate DNSSEC records using the `DO` (DNSSEC OK) flag. The response will include the `AD` (Authenticated Data) flag if the resolver validated the DNSSEC chain.

```typescript
import { DnsClient } from '@aoxborrow/dns-client';

// enable DNSSEC with DO flag
const client = new DnsClient({
  flags: ['DO', 'RD'], // request DNSSEC records
});

// query for DNSSEC records
const answers = await client.query({
  query: 'cloudflare.com',
  types: ['DNSKEY', 'DS', 'RRSIG'],
});

// check if the response was DNSSEC validated
answers.forEach(answer => {
  if (answer.flags.includes('AD')) {
    console.log('Response was DNSSEC validated (AD flag set)');
  }
});
```

### Reverse DNS Lookup (PTR Records)

```typescript
import { DnsClient, reverseIp } from '@aoxborrow/dns-client';

const client = new DnsClient();

// reverse lookup for IPv4/6 addresses using reverseIp utility
const answers = await client.query({
  query: reverseIp('8.8.8.8'); // returns '8.8.8.8.in-addr.arpa',
  types: ['PTR'],
});

console.log('Hostname:', answers[0].records); // [{ name: '8.8.8.8.in-addr.arpa', ttl: 69, type: 'PTR', value: 'dns.google' }]
```

### Utility Functions

```typescript
import { DnsClient, getRecords, deduplicateRecords, flattenRecords } from '@aoxborrow/dns-client';

const client = new DnsClient();
const answers: DnsAnswer[] = await client.query({
  query: 'example.com',
  types: ['A', 'AAAA', 'NS', 'MX', 'TXT'],
});

// extract all records from multiple DnsAnswers
const records: DnsRecord[] = getRecords(answers);

// deduplicate records, ignoring TTL and SOA serial numbers
const uniqueRecords: DnsRecord[] = deduplicateRecords(records);

// flatten records into simplified/stringified representations for display
const flattenedRecords: FlatDnsRecord[] = flattenRecords(uniqueRecords);

interface FlatDnsRecord {
  name: string;
  type: DnsRecordType;
  ttl?: number;
  content: string; // rdata/zonefile format
}
```

### DnsOptions

All are optional when creating a `DnsClient`. Defaults are provided for all settings.

```typescript
interface DnsOptions {
  // server and transport
  server: string; // DNS server IP or hostname (default: '1.1.1.1' or root servers for authoritative mode)
  transport: 'udp' | 'tcp' | 'doh'; // transport protocol (default: 'udp')
  authoritative: boolean; // resolution follows referrals iteratively from root (default: false)
  flags: DnsQueryFlag[]; // list of DNS query flags: 'RD' (Recursion Desired), 'CD' (Checking Disabled), 'DO' (DNSSEC OK) (default: ['RD'])

  // error handling and timeouts
  tcpFallback: boolean; // retry over TCP if the UDP response has TC=1 (truncated) (default: true)
  timeout: number; // timeout in milliseconds (default: 5000)
  retries: number; // number of retry attempts (default: 0)
  backoff: number; // base delay for exponential backoff in ms (default: 100ms)
  signal?: AbortSignal; // for cancellation/timeout

  // performance
  cache: boolean; // enable query cache (default: true)
  cacheSize: number; // maximum cache entries (default: 1000)
  concurrency: number; // maximum concurrent queries (default: 10)
}
```

### Query Cache Behavior

- Query cache keys are based on: name, type, server, and flags
- Cache entries respect DNS TTL values
- Query Caching can be disabled per client with `cache: false`

### Record Types

Supported DNS record types include:

`A`, `AAAA`, `CAA`, `CDNSKEY`, `CDS`, `CERT`, `CNAME`, `DNAME`, `DNSKEY`, `DS`, `HINFO`, `HTTPS`, `KEY`, `LOC`, `MX`, `NAPTR`, `NS`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `OPENPGPKEY`, `PTR`, `RP`, `RRSIG`, `SIG`, `SOA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TSIG`, `TXT`, `URI`

### Query Flags

DNS query flags (case-insensitive):

- `RD` - Recursion Desired (default for stub mode)
- `CD` - Checking Disabled (disables DNSSEC validation)
- `DO` - DNSSEC OK (requests extended DNSSEC records)

DNS response flags (case-insensitive):

- `AA` - Authoritative Answer (indicates the answer is authoritative)
- `TC` - Truncated Response (indicates the response is truncated)
- `RD` - Recursion Desired (indicates the request asked for recursion)
- `RA` - Recursion Available (indicates the server supports recursion)
- `AD` - Authenticated Data (indicates the response was DNSSEC authenticated)
- `CD` - Checking Disabled (indicates the server disabled DNSSEC validation)

### DnsAnswer

The response object returned by `query()` and `queryAll()`:

```typescript
interface DnsAnswer {
  query: string; // the domain name queried, e.g. 'example.com'
  type: DnsRecordType; // the record type queried, e.g. 'A'
  server: string; // the server that answered the query, e.g. '1.1.1.1'
  serverHost: string | null; // the hostname of the server if resolved, e.g. 'one.one.one.one'
  elapsed: number | null; // query duration in milliseconds
  bytes: number | null; // the number of bytes in the response
  rcode: number | null; // the DNS response code, e.g. 0 (NOERROR), 2 (SERVFAIL), 3 (NXDOMAIN)
  rcodeName: string | null; // the DNS response code name, e.g. 'NOERROR', 'SERVFAIL', 'NXDOMAIN'
  extendedErrors: DnsExtendedErrors | null; // extended DNS error codes, e.g. { 'DNSSEC_BOGUS': 'signature validation failed' }
  ednsOptions: EdnsOption[] | null; // EDNS options, e.g. [{ code: 3, nsid: '4m847' }]
  flags: DnsFlag[]; // DNS flags from the response, e.g. ['RD', 'RA', 'AD']
  records: DnsRecord[]; // the DNS records returned in the answer section
  authorities: DnsRecord[]; // the DNS records returned in the authority section
  additionals: DnsRecord[]; // the DNS records returned in the additional section
  trace: DnsResolutionHop[]; // delegation trace showing each nameserver hop, e.g. [{ server: 'g.root-servers.net', elapsed: 66 }]
  error: DnsError | null; // DnsError object if query failed
}
```

### DnsRecord Examples

Some example DNS record interfaces:

```typescript
// SOA (Start of Authority) - zone information
interface SoaRecord {
  name: string; // the domain name, e.g. 'example.com'
  ttl: number; // time to live in seconds, e.g. 3600
  type: 'SOA'; // record type
  class: 'IN'; // DNS class, almost always 'IN' (Internet)
  nsname: string; // primary nameserver, e.g. 'a.iana-servers.net'
  hostmaster: string; // responsible party email, e.g. 'hostmaster.example.com'
  serial: number; // zone serial number, e.g. 2024110501
  refresh: number; // refresh interval in seconds, e.g. 7200
  retry: number; // retry interval in seconds, e.g. 3600
  expire: number; // expiration time in seconds, e.g. 1209600
  minimum: number; // negative caching TTL in seconds, e.g. 3600
}

// A (Address) - IPv4 address record
interface ARecord {
  name: string; // the domain name, e.g. 'example.com'
  ttl: number; // time to live in seconds, e.g. 300
  type: 'A'; // record type
  class: 'IN'; // DNS class, almost always 'IN' (Internet)
  address: string; // IPv4 address, e.g. '93.184.216.34'
}

// MX (Mail Exchange) - mail server records
interface MxRecord {
  name: string; // the domain name, e.g. 'example.com'
  ttl: number; // time to live in seconds, e.g. 3600
  type: 'MX'; // record type
  class: 'IN'; // DNS class, almost always 'IN' (Internet)
  exchange: string; // mail server hostname, e.g. 'mail.example.com'
  priority: number; // preference value (lower is higher priority), e.g. 10
}

// DS (Delegation Signer) - DNSSEC delegation information
interface DsRecord {
  name: string; // the domain name, e.g. 'example.com'
  ttl: number; // time to live in seconds, e.g. 3600
  type: 'DS'; // record type
  class: 'IN'; // DNS class, almost always 'IN' (Internet)
  key_tag: number; // key tag identifier, e.g. 12345
  algorithm: number; // cryptographic algorithm number, e.g. 8 (RSA/SHA-256)
  digest_type: number; // digest algorithm, e.g. 2 (SHA-256)
  digest: string; // hexadecimal digest hash, e.g. 'A1B2C3D4E5F6...'
}
```

### DnsResolutionHop

Each entry in the `trace` array represents a single DNS query hop during authoritative resolution.

```typescript
interface DnsResolutionHop {
  server: string; // the IP address or hostname of the nameserver queried
  serverHost: string | null; // the hostname of the nameserver if resolved
  timestamp: Date; // when this query was made
  elapsed: number | null; // query duration in milliseconds
  bytes: number | null; // size of the response in bytes
  rcode: number | null; // DNS response code (0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN)
  rcodeName: string | null; // DNS response code name ('NOERROR', 'SERVFAIL', 'NXDOMAIN')
  flags: DnsFlag[]; // DNS flags from the response (e.g., ['AA', 'RD', 'RA'])
}
```

## Modes of Operation

### Stub Mode (default)

Talk to a normal recursive resolver and rely on its caching and DNS policies. This is the standard mode used by most applications. This is usually what you want.

```typescript
const client = new DnsClient({
  authoritative: false, // this is the default
  flags: ['RD'], // this is the default
});
```

- Sends queries with the RD (Recursion Desired) flag set
- Specify a server to use, or use the default public server (Cloudflare's `1.1.1.1`)
- The upstream server performs recursive resolution and caching and returns the final answer

### Authoritative Mode

Perform iterative resolution following delegation referrals starting from root servers.

```typescript
const client = new DnsClient({
  authoritative: true,
  // flags: [], // no RD flag (no recursion requested)
});
```

- Sends queries without RD (Recursion Desired) flag (no recursion requested)
- Starts from root servers (or configured server if provided) and follows NS referrals iteratively until reaching authoritative nameservers
- Returns full delegation trace in `answer.trace` (similar to `dig +trace`)

## API

### `DnsClient`

#### `constructor(options?: Partial<DnsOptions>)`

Create a new DNS client with optional default options.

#### `query(query: DnsQuery): Promise<DnsAnswer[]>`

Execute a DNS query for one or more record types.

- `query` - A `DnsQuery` object with the following properties:
  - `query` (required) - The domain name to query
  - `types` (optional) - Array of record types to query (default: `['A']`). Case-insensitive.
  - `server` (optional) - Override the nameserver for this query
  - `flags` (optional) - Override the DNS flags for this query. Case-insensitive.

Returns an array of `DnsAnswer` objects, one per record type.

#### `queryAll(queries: DnsQuery[]): Promise<DnsAnswer[]>`

Execute multiple DNS queries in parallel. Each query can optionally specify multiple record types and override the `server` and `flags` from the client defaults.

```typescript
// the DnsQuery object used by query() and queryAll()
interface DnsQuery {
  query: string; // the domain name to query, e.g. 'example.com'
  types?: RecordType[]; // array of record types to query (default: ['A']), e.g. ['A', 'AAAA', 'MX']
  server?: string; // override the nameserver for this query, e.g. '8.8.8.8'
  flags?: QueryFlag[]; // override the DNS flags for this query, e.g. ['RD', 'DO']
}
```

## Generate Test Fixtures

Generate DNS test fixtures for integration testing, based on the list in `DNS_TEST_DOMAINS`. Fixtures are transport-agnostic and are used to test UDP, TCP, and DoH clients.

**Usage:** `npm run generate-fixtures [cloudflare|google]`
