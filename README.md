# dns-client

A DNS client for TypeScript with nothing underneath it: its own wire codec, typed records,
resolvers that ask a recursive resolver or walk from the root, record validation, and DNSSEC
validation with the primitives it is built from. No runtime dependencies.

```bash
npm install @aoxborrow/dns
```

**Status:** 1.0 is a rewrite and is in pre-release. It is not compatible with 0.x; see
[UPGRADING.md](UPGRADING.md) for what changed and what replaces what.

## Asking a question

```ts
import { Resolver } from '@aoxborrow/dns';

// an ordinary recursive query, like dig or node:dns, to the resolvers this machine uses
const resolver = new Resolver();
const answer = await resolver.query('example.com', 'MX');

answer.rcodeName; // 'NOERROR'
answer.records; // MxRecord[]: [{ name, type: 'MX', class: 'IN', ttl: 300, preference: 0, exchange: '.' }]
answer.server; // '192.0.2.53', whichever resolver answered
answer.toDig(); // 'dig @192.0.2.53 example.com MX'
```

Name the resolvers to use, or ask one particular server for one query:

```ts
const resolver = new Resolver({ servers: ['1.1.1.1', '8.8.8.8'] });

// this server and no other, over TCP, outside the cache
const txt = await resolver.query('example.com', 'TXT', { server: '9.9.9.9', transport: 'tcp' });
txt.records.map(record => record.strings); // [['v=spf1 -all'], …]
```

A server is an address, a name, `host:port`, or an `https://` URL, which is asked over DNS
over HTTPS (`https://cloudflare-dns.com/dns-query`). For DNS over TLS, name the server and
set `transport: 'tls'`.

On Node, DNS over HTTPS goes over HTTP/2 with `node:http2`, one session per server shared
by every query to it (RFC 8484 recommends HTTP/2 at least, and some servers refuse
HTTP/1.1). A session idle for `idleTimeout` milliseconds (5000 by default) is closed, and
`tls` (`ca`, `rejectUnauthorized`) applies to it as to DNS over TLS. A server that does not
offer HTTP/2, an `http://` URL, and every other runtime go through `fetch`; pass your own
`fetch` to use it everywhere.

`Resolver` caches by TTL, shares one query between callers asking the same thing at the
same moment, and moves to the next server when one fails or answers SERVFAIL, NOTIMP or
REFUSED.

### From the root

```ts
import { AuthoritativeResolver } from '@aoxborrow/dns';

const resolver = new AuthoritativeResolver();
const answer = await resolver.query('example.com', 'A');

answer.flags.aa; // true: this is what the zone's own server says
answer.trace; // every server asked on the way
// [ { zone: '.',           serverName: 'a.root-servers.net',        referral: 'com' },
//   { zone: 'com',         serverName: 'a.gtld-servers.net',        referral: 'example.com' },
//   { zone: 'example.com', serverName: 'elliott.ns.cloudflare.com', rcodeName: 'NOERROR' } ]
```

It asks no resolver. It starts at the root servers and follows referrals to the zone's own
nameservers, remembers delegations for as long as their TTLs allow, looks up nameservers
that come without an address, and moves on from a server that refuses, fails or stays
silent. It stops at an alias into another zone unless `followCnames` is set.

### The answer

Both resolvers have one method, `query(name, type, options?)`, and return the same thing:

| Field | |
| --- | --- |
| `rcode`, `rcodeName`, `flags` | what the server said about the question |
| `records` | the records that answer it, typed by the type you asked for |
| `answers`, `authorities`, `additionals` | every record in each section, typed |
| `extendedErrors` | extended DNS errors (RFC 8914), when the server sent any |
| `message`, `bytes` | the response decoded from the wire, and exactly as it arrived |
| `server`, `serverName`, `port`, `transport` | who answered, and how |
| `elapsed`, `attempts`, `timestamp`, `cached` | how long it took, how many tries, when, and whether it came from the cache |
| `trace` | `AuthoritativeResolver` only: every hop from the root |
| `toDig()` | the `dig` command that asks the same question |

A name that does not exist is an answer (`rcodeName: 'NXDOMAIN'`, no records), not an
error.

### Options

These can be set on a resolver for every query, or passed to one `query()`:

| Option | Default | |
| --- | --- | --- |
| `transport` | `'udp'` | `'udp'`, `'tcp'`, `'tls'` or `'doh'`. TCP where there is no UDP; DoH for a server given as a URL |
| `timeout` | `5000` | milliseconds of patience with one server |
| `retries` | `2` | further attempts at a server that fails in a way worth retrying. One, when there are other servers to turn to |
| `tcpFallback` | `true` | ask again over TCP when a UDP answer is truncated |
| `recursionDesired` | `true` | the RD flag. `AuthoritativeResolver` never sets it |
| `dnssecOk` | `false` | the DO bit: ask for signatures with the answer |
| `checkingDisabled` | `false` | the CD flag: ask a validating resolver not to hold an answer back |
| `authenticData` | `false` | the AD flag in the query: ask to be told whether the answer validated |
| `udpPayloadSize` | `1232` | the largest UDP answer this client will accept |
| `ednsOptions` | none | EDNS options to send: `nsidOption()`, `clientSubnetOption()`, `cookieOption()`, `paddingOption()` |
| `edns` | on | `false` sends a plain RFC 1035 query |
| `signal` | none | an `AbortSignal`, per query |

`Resolver` also takes `servers`, `cache` (false, your own, or settings for the built-in
one), `maxTtl`, `concurrency` and `strict`. `AuthoritativeResolver` also takes
`rootServers`, `addressFamily` (`'ipv4'` by default), `followCnames`, `hosts`,
`nameserverOrder`, `addressOrder`, `resolveNameserver`, `cache`, `serverDelay`,
`concurrency`, `maxHops`, and `totalTimeout`: the time one answer may take altogether (30
seconds by default), since a zone whose servers all stay silent would otherwise cost a
timeout for each of them. Retries and a TCP fallback count against it, and the last server
a zone has left to ask gets the rest of it, shared among its attempts, rather than
`timeout`. `exchange` takes a `totalTimeout` of its own, for all its attempts together,
and has none by default.

Both take `onEvent`, which is told about every query sent, every retry, every fallback to
TCP and every proxy connection. That is where logging and metrics attach; the library
itself prints nothing.

### Errors

An error means no usable response arrived. Every one is a `DnsError` subclass:

```ts
import { DnsError } from '@aoxborrow/dns';

try {
  await resolver.query('example.com', 'A');
} catch (error) {
  if (error instanceof DnsError) {
    error.name; // 'TimeoutError'
    error.retryable; // true: asking again could work
    error.server; // '192.0.2.1'
    error.message; // 'No answer from 192.0.2.1 within 5000 ms'
  }
}
```

| Error | Retryable | |
| --- | --- | --- |
| `TimeoutError` | yes | the server said nothing in time |
| `ConnectionError` | yes | the server could not be reached |
| `ProxyError` | yes | the proxy refused or failed |
| `EmptyResponseError` | yes | a connection closed without an answer |
| `TruncatedError` | no | a truncated answer, with `tcpFallback` off |
| `InvalidResponseError` | no | an answer that does not match the question, or a walk that leads nowhere |
| `ParseError`, `RecordSyntaxError` | no | bytes or text that are not valid DNS |
| `InvalidQueryError` | no | a question that cannot be asked |
| `NoServerError` | no | no resolver to ask |

An error from `AuthoritativeResolver` carries `trace`, the servers asked before it failed.

## Records

Every record type has its own interface, with fields named as the RFCs name them. A value
inside a record stays as it was on the wire: names keep their case, binary data is hex or
base64, times are numbers.

```ts
import { formatRecord, flattenRecords, reverseIp, typeCode, typeName } from '@aoxborrow/dns/records';

formatRecord(answer.records[0]); // 'example.com.\t300\tIN\tMX\t0 .', a zone-file line
flattenRecords(answer.records); // [{ name: 'example.com', type: 'MX', ttl: 300, data: '0 .' }]

reverseIp('8.8.8.8'); // '8.8.8.8.in-addr.arpa'
typeCode('HTTPS'); // 65
typeName(65280); // 'TYPE65280': a type with no name comes back in the RFC 3597 form
```

Supported: A, AAAA, CAA, CDNSKEY, CDS, CERT, CNAME, DNAME, DNSKEY, DS, HINFO, HTTPS, KEY,
LOC, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, PTR, RP, RRSIG, SIG, SOA, SRV,
SSHFP, SVCB, TLSA, TSIG, TXT and URI. A record of any other type, or one whose data is
malformed, comes back in a generic form with its data in hex; `strict: true` makes
malformed data an error.

### Checking records before saving them

The same package checks records written by a person or held by a DNS provider. These are
pure functions and touch no network:

```ts
import { canonicalRecord, diffRecords, findCnameConflicts, parseRecord } from '@aoxborrow/dns/records';

// text to a typed record, or a RecordSyntaxError saying what is wrong
parseRecord({ name: 'example.com', type: 'MX', ttl: 300, data: '10 mail.example.com.' });
// { name: 'example.com', type: 'MX', class: 'IN', ttl: 300, preference: 10, exchange: 'mail.example.com' }

parseRecord({ name: 'example.com', type: 'A', ttl: 300, data: '300.1.2.3' });
// RecordSyntaxError: "300.1.2.3" is not an IPv4 address

// one spelling for records that mean the same thing
canonicalRecord({ name: 'Example.COM.', type: 'txt', ttl: 300, data: 'v=spf1 -all' });
// { name: 'example.com', type: 'TXT', ttl: 300, data: '"v=spf1 -all"' }

// what a zone should hold against what it does
diffRecords(intended, actual); // { missing: […], unexpected: […] }

// a name with a CNAME and anything else
findCnameConflicts(records); // [{ name: 'www.example.com', type: 'CNAME', detail: '…' }]
```

Names are full names. `qualify()` and `relativize()` convert to and from names written
relative to a zone, `@` included.

## DNSSEC

### Validating answers

```ts
import { AuthoritativeResolver, Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({ servers: ['1.1.1.1'], validate: true });
const answer = await resolver.query('example.com', 'A');

answer.security?.status; // 'secure', 'insecure', 'bogus' or 'indeterminate'
answer.security?.reason; // { code: 'verified', zone: 'example.com', keyTag: 370 }

const iterative = new AuthoritativeResolver({ validate: true });
const broken = await iterative.query('dnssec-failed.org', 'A');
broken.security?.status; // 'bogus'
broken.security?.reason; // { code: 'no-matching-dnskey', zone: 'dnssec-failed.org', keyTag: …, ede: 9 }
broken.security?.failure; // the first link that broke: { kind: 'keys', zone: 'dnssec-failed.org', … }
```

With `validate: true`, both resolvers check every answer's chain of trust and say what came
of it in `answer.security`. The data is asked for with DO set (and CD, for `Resolver`, so a
validating resolver upstream hands over broken records instead of a SERVFAIL); then each
zone between the root and the data has its DS and DNSKEY records fetched the same way, and
the judging core decides. The answer itself is unchanged apart from carrying its
signatures in `answers`; nothing is withheld, whatever the verdict. Without `validate`,
nothing changes.

| Status | Meaning |
| --- | --- |
| `secure` | a chain of valid signatures runs from a trust anchor to the data |
| `insecure` | the data is proven to sit below a delegation with no DS (or an opt-out range, or a DS set naming only algorithms this runtime cannot verify, RFC 6840 §5.2), so nothing could sign it |
| `bogus` | a chain should be there and is broken: an expired or invalid signature, a DS that matches no key, a missing proof |
| `indeterminate` | it could not be told: a response missing, or every signature in an algorithm this runtime cannot check |

`reason` is a code and the values it is about (zone, name, type, key tag, algorithm), never
English, with `ede` set to the extended DNS error (RFC 8914) a validating resolver would send
for it, where one fits: 7 for an expired signature, 9 for a missing DNSKEY, 10 for missing
RRSIGs, 12 for a missing NSEC proof, 1 for an unsupported algorithm, 27 for an NSEC3
iteration count past 100. `chain` lists every link judged, each zone's key set from the root
down and then each RRset and denial proof of the data, each with its own status and reason;
`failure` is the first bogus or indeterminate one. CNAME and DNAME chains are judged link by
link (a CNAME synthesized from a signed DNAME needs no signature of its own), answers from a
wildcard need the proof that the name itself does not exist, and NXDOMAIN and NODATA need
their NSEC or NSEC3 proofs, a NODATA from a wildcard or at an empty non-terminal included.
An opt-out range makes an answer insecure only where the NSEC3 covering the next closer name
sets it (RFC 5155 §9.2).

One answer may cost at most 128 signature verifications, 4 keys tried per signature and 8
signatures per RRset; past that it is `bogus` with the code `validation-limit`, as
validators have done since KeyTrap (CVE-2023-50387). `judgeChain` takes other `limits`.
NSEC3 names are hashed once per parameter set, and not at all past 100 iterations.

What each zone's key set came to is kept for as long as the TTLs and signatures it rests on
allow (with `cache: false`, not at all), and `clearCache()` forgets it. Validation starts
from `trustAnchors`, IANA's root anchors by default (`ROOT_TRUST_ANCHORS`, with
`ROOT_TRUST_ANCHORS_DATA_VERSION` and `ROOT_TRUST_ANCHORS_REFRESHED`). A key published with the
RFC 5011 revoke bit anchors nothing and signs nothing.

### The judging core

```ts
import { judgeChain } from '@aoxborrow/dns/dnssec';

const judgement = await judgeChain(
  { anchored, names, responses }, // the records fetched, as DnssecResponse objects
  { mode: 'all', now: new Date() }
);
judgement.links; // every link, with a status and a reason
```

The resolvers fetch, and `judgeChain` judges: given the root's DNSKEY response, each name's
DS response (and DNSKEY response, where it is a zone of its own), the responses holding the
data, the trust anchors and a time, it returns the status and reason of every link. It
fetches nothing and keeps nothing, so the same records and time always give the same
judgement. `mode: 'first'` (what the resolvers use) stops at the first link that settles the
outcome; `mode: 'all'` judges every link and every signature. The checks it is made of are
exported one by one, each returning codes: `checkAnchors`, `checkDsSet`, `checkKeySet`,
`checkSignature`, `checkRrset`, and `judgeKeys` for a zone's key set as a whole.

### The primitives

```ts
import { Resolver } from '@aoxborrow/dns';
import {
  buildSignedData,
  computeKeyTag,
  groupRrsets,
  toWireMessage,
  verifySignature,
} from '@aoxborrow/dns/dnssec';
import { decodeDnskey, decodeRrsig } from '@aoxborrow/dns/records';

// a zone's keys and the signatures over them, from a resolver asked not to validate
const resolver = new Resolver({ servers: ['1.1.1.1'] });
const answer = await resolver.query('example.com', 'DNSKEY', {
  dnssecOk: true,
  checkingDisabled: true,
});
const { answers } = toWireMessage(answer.message);
const [keys] = groupRrsets(answers);

for (const record of answers.filter(rr => rr.typeName === 'RRSIG')) {
  const rrsig = decodeRrsig(record.rdata); // throws ParseError for malformed data
  const key = keys.records.find(rr => computeKeyTag(rr.rdata) === rrsig.keyTag);
  const signed = buildSignedData(rrsig, keys);
  if (!key || !signed) continue;

  const { publicKey } = decodeDnskey(key.rdata);
  const outcome = await verifySignature(rrsig.algorithm, publicKey, signed.data, rrsig.signature);
  outcome.verified; // true, false, or undefined when this runtime cannot check the algorithm
}
```

These are the pieces the judging core is built from, each checking one thing.
`verifySignature` checks RSA, ECDSA and EdDSA signatures through WebCrypto; an algorithm
the runtime cannot verify comes back not checked, never as a pass, and
`isAlgorithmSupported` says beforehand whether it can (a WebCrypto may lack Ed25519 or
Ed448). `computeDsDigest` and `computeKeyTag` match a DS record to the key it names. `verifyNoDsProof`,
`verifyNxdomainProof`, `verifyNodataProof` and `verifyWildcardProof` check NSEC and NSEC3
denial proofs and return the reasoning step by step; `verifyWildcardProof` takes the
wildcard an answer was synthesised from, which `wildcardOwner` rebuilds from the RRSIG's
labels field. `isAnchorCurrent` says whether a trust anchor is valid at a given time.
Digests and NSEC3 hashes use the library's own SHA-1, SHA-256 and SHA-384. Owner names in
`toWireMessage`'s records keep the case the server wrote them in; record data is in the
canonical form signatures are computed over.

## The wire format

```ts
import { decodeMessage, encodeQuery } from '@aoxborrow/dns/wire';

const bytes = encodeQuery({ id: 1234, name: 'example.com', type: 'A', recursionDesired: true });
const message = decodeMessage(response); // header, flags, question, three record sections, EDNS
```

`Uint8Array` in and out, no `Buffer`. Names are accepted in Unicode or punycode and
returned in ASCII.

## Where it runs

| Entry | Contents | Runs on |
| --- | --- | --- |
| `@aoxborrow/dns` | everything below | Node |
| `@aoxborrow/dns/records` | typed records, protocol tables, parsing, formatting, validation | anywhere |
| `@aoxborrow/dns/wire` | encoding queries and decoding messages | anywhere |
| `@aoxborrow/dns/transports/udp` | DNS over UDP, a fresh port per query | Node |
| `@aoxborrow/dns/transports/tcp` | DNS over TCP | Node, Cloudflare Workers |
| `@aoxborrow/dns/transports/tls` | DNS over TLS | Node, Cloudflare Workers |
| `@aoxborrow/dns/transports/doh` | DNS over HTTPS: HTTP/2 on Node, `fetch` elsewhere | anywhere with `fetch` |
| `@aoxborrow/dns/dnssec` | the judging core, signature verification, DS digests, NSEC/NSEC3 proofs, trust anchors | anywhere |

Node 20 or later. The package ships ES modules and CommonJS, with type declarations for
both. Node built-ins are imported only by the transports, and only when a query needs
them, so the entries marked "anywhere" bundle for a browser with none.

On Cloudflare Workers there is no UDP, and Ed448 signatures cannot be verified. The codec,
the records, both resolvers and the DNSSEC primitives pass their tests inside the Workers
runtime, and the TCP, TLS and HTTPS transports have been run on a deployed Worker. A whole
lookup, resolver and transport together, has not yet been run on a deployed Worker.

## Proxies

Every transport can go through a SOCKS5 or HTTP CONNECT proxy. With `proxy` set nothing
goes around it: a query that cannot go through the proxy fails.

```ts
const resolver = new Resolver({ servers: ['1.1.1.1'], proxy: 'socks5://user:pass@proxy.example:1080' });
```

| Transport | Through the proxy |
| --- | --- |
| TCP, DNS over TLS | a tunnel to the server; TLS starts inside it |
| UDP | a SOCKS5 UDP association where the proxy offers one, otherwise TCP through the tunnel. The answer's `transport` says which |
| DNS over HTTPS | on Node, HTTP/2 through a tunnel to the server; a server that does not offer HTTP/2 fails. Elsewhere, pass a `fetch` that uses the proxy. Without one the query fails |

`proxy` can be a function that picks a proxy per server, or returns nothing to leave a
server unproxied. An explicit `connect` wins over `proxy` for TCP and TLS. Credentials
never appear in an error or an event.

On a deployed Cloudflare Worker TLS cannot start inside a tunnel, so the built-in tunnel
carries plain TCP there and nothing else. For DNS over HTTPS through a proxy on Workers,
pass a `fetch` that does its own TLS, such as
[`tunnelfetch`](https://github.com/latentharbor/tunnelfetch); that combination has not
been run with this library.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
