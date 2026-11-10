import { ROOT_HINTS } from '../resolvers/root-hints';
import type { Transports } from '../transports/index';
import type { OnEvent } from '../transports/types';
import { concatBytes, fromBase64, toBase64, toHex, readU16, writeU16 } from '../wire/bytes';
import type { DnssecTransport } from './types';
import {
  DnssecFinding,
  DnssecZone,
  DnssecDnskey,
  DnssecDs,
  DnssecRrsig,
  DnssecRrset,
  DnssecDelegation,
  DnssecNameserver,
  DnssecQueryLogEntry,
  DnssecStatus,
  DnskeyStatus,
  TrustAnchorState,
  DenialProof,
  ResolverCrossCheck,
  ServerMatrixCell,
  FindingSubject,
  Nsec3Params,
  DigestCheck,
  SignatureCheck,
} from './types';
import {
  DNSSEC_STATUSES,
  VERIFICATION_RESULTS,
  DNSSEC_KEY_TYPES,
  DNSKEY_STATUSES,
  DS_STATUSES,
  RRSIG_STATUSES,
  RRSET_STATUSES,
  PROOF_STATUSES,
  SERVER_STATUSES,
  DNSKEY_FLAGS,
  DNSKEY_PROTOCOL,
  DS_DIGEST_TYPES,
  DNSSEC_ALGORITHMS,
  ALGORITHM_STANDINGS,
  SIGNATURE_EXPIRY_WARNING_MS,
  SIGNATURE_EXPIRY_WARNING_FRACTION,
  CLOCK_SKEW_MS,
  CROSS_CHECK_RESOLVERS,
  CROSS_CHECK_TIMEOUT_MS,
  DEEP_SERVERS_PER_ZONE,
  STANDARD_SERVERS_PER_ZONE,
  MAX_RUN_MS,
} from './constants';
import { FindingSlug, FINDING_CATALOG } from './findings';
import {
  ROOT_TRUST_ANCHORS,
  ROOT_TRUST_ANCHOR_SOURCE,
  KSK_2024_SIGNING_DATE,
  KSK_2017_REVOCATION_DATE,
  isAnchorCurrent,
} from './anchors';
import { dnssecQuery, digCommand, EDNS_UDP_PAYLOAD_SIZE } from './query';
import {
  WireRecord,
  WireMessage,
  Rrset,
  groupRrsets,
  decodeDnskey,
  decodeDs,
  decodeRrsig,
  decodeNsec3Param,
  computeKeyTag,
  computeDsDigest,
  buildSignedData,
  canonicalName,
  countLabels,
  parentName,
  presentRecord,
  responseFingerprint,
  recordTypeName,
  recordTypeCode,
  TYPE_A,
  TYPE_AAAA,
  TYPE_NS,
  TYPE_SOA,
  TYPE_MX,
  TYPE_TXT,
  TYPE_DS,
  TYPE_DNSKEY,
  TYPE_RRSIG,
  TYPE_NSEC3PARAM,
} from './wire';
import { verifySignature, isAlgorithmVerifiable, algorithmName, keySizeBits } from './crypto';
import {
  verifyNoDsProof,
  verifyNodataProof,
  verifyNxdomainProof,
  verifyWildcardProof,
  assessNsec3Params,
} from './nsec';

const { SECURE, INSECURE, BOGUS, INDETERMINATE } = DNSSEC_STATUSES;
const { VERIFIED, FAILED, UNCHECKED } = VERIFICATION_RESULTS;

const RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

function rcodeName(code: number): string {
  return RCODE_NAMES[code] ?? `RCODE${code}`;
}

const DNS_TRANSPORT_TCP = 'tcp';
type DnsTransportType = DnssecTransport;
type DnsRecordType = string;
const utcTimestamp = () => new Date().toISOString();
// the root servers by name, each with its IPv4 address first
const ROOT_SERVERS: Record<string, string[]> = Object.fromEntries(
  ROOT_HINTS.filter(hint => hint.name && hint.ipv4).map(hint => [
    hint.name as string,
    [hint.ipv4 as string],
  ])
);

export interface EngineOptions {
  transport?: DnsTransportType;
  timeout?: number;
  // consult every authoritative server per zone and build the per-server matrix
  deep?: boolean;
  // query the public validating resolvers for corroboration
  crossCheck?: boolean;
  // the time signatures and trust anchors are judged against. Defaults to the moment the
  // engine is built; a replay of recorded responses passes the time they were recorded
  now?: Date;
  // sockets and connections to ask over. Default: the process-wide set. A replay hands in
  // a set that answers from recordings
  transports?: Transports;
  // told about every query the analysis sends
  onEvent?: OnEvent;
}

export interface EngineOutput {
  overallStatus: DnssecStatus;
  chain: DnssecZone[];
  trustAnchor: TrustAnchorState;
  findings: DnssecFinding[];
  queries: DnssecQueryLogEntry[];
  digCommands: string[];
  crossCheck: ResolverCrossCheck[];
  serverMatrix: ServerMatrixCell[];
}

// one response, with the records already grouped
interface Fetched {
  message?: WireMessage;
  queryIndex: number;
  server: string;
  serverHost?: string;
  error?: string;
  answers: WireRecord[];
  authorities: WireRecord[];
  rrsigs: WireRecord[];
  // the name/type THIS engine actually asked for. the response's own question section is unsigned
  // and attacker-mutable, so denial proofs must be checked against these, never against the echo
  qname?: string;
  qtype?: number;
}

// a zone under construction, before it becomes a DnssecZone
interface ZoneBuild {
  name: string;
  parent?: string;
  nameservers: DnssecNameserver[];
  serverIps: string[];
  fetched: Map<string, Fetched>;
  dnskeyRecords: WireRecord[];
  started: number;
}

// ---------------------------------------------------------------------------

export class DnssecEngine {
  private queries: DnssecQueryLogEntry[] = [];
  private digCommands: string[] = [];
  private serverMatrix: ServerMatrixCell[] = [];
  private findings: DnssecFinding[] = [];
  private transport: DnsTransportType;
  private timeoutMs: number;
  private deep: boolean;
  private crossCheckEnabled: boolean;
  private now: Date;
  // a hard wall-clock ceiling for the whole run — past it, ask() stops issuing queries so a hostile
  // zone cannot drag one lookup into minutes of outbound port-53 work
  private deadline = Date.now() + MAX_RUN_MS;
  // hostname -> IP, resolved once per run
  private hostCache = new Map<string, string | undefined>();

  private readonly transports: Transports | undefined;
  private readonly onEvent: OnEvent | undefined;

  constructor(options: EngineOptions = {}) {
    this.transport = options.transport ?? DNS_TRANSPORT_TCP;
    this.timeoutMs = options.timeout ?? 5000;
    this.deep = options.deep ?? false;
    this.crossCheckEnabled = options.crossCheck ?? true;
    this.now = options.now ?? new Date();
    this.transports = options.transports;
    this.onEvent = options.onEvent;
  }

  // -------------------------------------------------------------------------
  // querying
  // -------------------------------------------------------------------------

  private async ask(
    zone: string,
    servers: string[],
    qname: string,
    qtype: number,
    serverHosts: Record<string, string> = {}
  ): Promise<Fetched> {
    const pool = servers.slice(0, this.deep ? DEEP_SERVERS_PER_ZONE : STANDARD_SERVERS_PER_ZONE);
    if (pool.length === 0) return noServerFetched();

    // stop once the run has spent its wall-clock budget: a hostile zone chaining delegations to dead
    // servers must not be able to hold shared backend sockets open for minutes
    if (Date.now() > this.deadline) return noServerFetched();

    // the standard scan walks the set in order and stops at the first server that answers, so
    // a dead server costs one round trip rather than the zone. the deep scan asks every server
    // — and asks them concurrently, because they are independent and serialising them made
    // `deep=true` 20x the wall clock for 6.5x the queries
    const results = this.deep
      ? await Promise.all(pool.map(server => this.querySingle(server, qname, qtype)))
      : await this.queryUntilAnswered(pool, qname, qtype);

    // log after the fact, in server order: with a concurrent fan-out the completion order is
    // nondeterministic, and query indices are referenced by every provenance record
    const fetched = results.map((result, i) =>
      this.recordQuery(zone, pool[i], qname, qtype, result, serverHosts)
    );

    // the answer the validation actually uses is the first good one in server order — never
    // whichever server happened to finish last
    const firstGood = fetched.find(f => f.message);

    if (this.deep) this.recordServerMatrix(zone, qname, qtype, pool, fetched);

    // no server in the pool produced a response at all. that is not the same as an empty
    // answer, and it must not pass silently — an unretrievable RRset is a gap in what the
    // verdict rests on, so it goes in the findings even when the chain above it verified
    if (!firstGood) {
      const last = fetched[fetched.length - 1];
      this.finding(
        'server-timeout',
        `No authoritative server for ${zone} answered the ${recordTypeName(qtype)} query for ${qname}${
          last?.error ? ` (${last.error})` : ''
        }.`,
        { zone, name: qname, recordType: recordTypeName(qtype), server: last?.server }
      );
    }

    return firstGood ?? fetched[fetched.length - 1] ?? noServerFetched();
  }

  private querySingle(server: string, qname: string, qtype: number) {
    return dnssecQuery(server, qname, qtype, {
      transport: this.transport,
      timeoutMs: this.timeoutMs,
      recursionDesired: false,
      checkingDisabled: true,
      dnssecOk: true,
      transports: this.transports,
      onEvent: this.onEvent,
    });
  }

  // walk the pool in order, stopping at the first server that answers. returns one entry per
  // server actually tried, so the caller's log stays aligned with `pool`
  private async queryUntilAnswered(
    pool: string[],
    qname: string,
    qtype: number
  ): Promise<Awaited<ReturnType<typeof this.querySingle>>[]> {
    const out: Awaited<ReturnType<typeof this.querySingle>>[] = [];
    for (const server of pool) {
      const result = await this.querySingle(server, qname, qtype);
      out.push(result);
      if (result.message) break;
    }
    return out;
  }

  // append one transaction to the query log and turn it into a Fetched
  private recordQuery(
    zone: string,
    server: string,
    qname: string,
    qtype: number,
    result: Awaited<ReturnType<typeof this.querySingle>>,
    serverHosts: Record<string, string>
  ): Fetched {
    const index = this.queries.length;
    this.queries.push({
      index,
      timestamp: result.timestamp,
      zone,
      qname,
      qtype: recordTypeName(qtype),
      server,
      serverHost: serverHosts[server],
      transport: result.transport,
      flagsSent: result.flagsSent,
      flagsReceived: describeFlags(result.message),
      ednsBufferSize: EDNS_UDP_PAYLOAD_SIZE,
      rcode: result.message ? rcodeName(result.message.rcode) : 'NO RESPONSE',
      extendedError: describeExtendedError(result.message),
      bytes: result.message?.bytes,
      elapsed: result.elapsed,
      retriedOverTcp: result.retriedOverTcp,
      error: result.error,
    });
    this.digCommands.push(
      digCommand(server, qname, recordTypeName(qtype), { transport: this.transport })
    );
    const fetched = toFetched(result.message, index, server, serverHosts[server], result.error);
    fetched.qname = qname;
    fetched.qtype = qtype;
    return fetched;
  }

  // compare what each server actually served, not merely whether it answered. a single stale
  // nameserver in a set of four is a common failure mode that a reachability-only matrix
  // averages away — it is the reason the deep scan exists
  private recordServerMatrix(
    zone: string,
    qname: string,
    qtype: number,
    pool: string[],
    fetched: Fetched[]
  ): void {
    const rrset = `${qname} ${recordTypeName(qtype)}`;

    // fingerprint every good NOERROR answer; the largest identical group is the consensus
    const prints = new Map<string, string[]>();
    for (let i = 0; i < fetched.length; i++) {
      const message = fetched[i].message;
      if (!message || message.rcode !== 0) continue;
      const print = responseFingerprint(message.answers, message.authorities);
      prints.set(print, [...(prints.get(print) ?? []), pool[i]]);
    }

    const groups = [...prints.entries()].sort((a, b) => b[1].length - a[1].length);
    const consensus = groups[0]?.[0];
    const divergentServers = groups.slice(1).flatMap(([, servers]) => servers);

    for (let i = 0; i < fetched.length; i++) {
      const server = pool[i];
      const message = fetched[i].message;

      if (!message) {
        this.serverMatrix.push({
          server,
          zone,
          rrset,
          status: FAILED,
          note: fetched[i].error ?? 'no response',
        });
        continue;
      }
      if (message.rcode !== 0) {
        this.serverMatrix.push({
          server,
          zone,
          rrset,
          status: FAILED,
          note: rcodeName(message.rcode),
        });
        continue;
      }

      const print = responseFingerprint(message.answers, message.authorities);
      const divergent = consensus !== undefined && print !== consensus;
      this.serverMatrix.push({
        server,
        zone,
        rrset,
        status: divergent ? FAILED : VERIFIED,
        note: divergent ? 'serves different data from the other nameservers' : undefined,
      });
    }

    if (divergentServers.length > 0) {
      this.finding(
        'server-divergent',
        `The nameservers for ${zone} do not agree on ${rrset}. ${divergentServers.join(', ')} ` +
          `${divergentServers.length === 1 ? 'serves' : 'serve'} different data from ${groups[0][1].join(', ')}. ` +
          'Resolvers will get different answers depending on which server they reach, and a stale signature on one of them makes the domain intermittently bogus.',
        { zone, name: qname, recordType: recordTypeName(qtype), server: divergentServers[0] },
        { alsoAffects: divergentServers.map(server => ({ zone, server })) }
      );
    }
  }

  // resolve a nameserver hostname to an address, preferring glue already in hand
  private async resolveHost(
    host: string,
    glue: Map<string, string[]>,
    glue6: Map<string, string[]>
  ): Promise<string | undefined> {
    const name = canonicalName(host);
    // prefer IPv4 glue, then IPv6 glue: an A address is used whenever one exists, so a dual-stack
    // nameserver is never reached over IPv6 in an environment that may lack IPv6 egress
    const gluedV4 = glue.get(name);
    if (gluedV4 && gluedV4.length) return gluedV4[0];
    const gluedV6 = glue6.get(name);
    if (gluedV6 && gluedV6.length) return gluedV6[0];

    if (this.hostCache.has(name)) return this.hostCache.get(name);

    // fall back to a public recursive resolver — this lookup is plumbing, not evidence, so it is
    // not part of the validation path and is not logged as one. try A first, then AAAA, so an
    // IPv6-only nameserver still resolves rather than being reported unreachable
    const ip =
      (await this.recursiveAddress(name, TYPE_A)) ?? (await this.recursiveAddress(name, TYPE_AAAA));
    this.hostCache.set(name, ip);
    return ip;
  }

  private async recursiveAddress(name: string, qtype: number): Promise<string | undefined> {
    const result = await dnssecQuery(CROSS_CHECK_RESOLVERS[0].address, name, qtype, {
      transport: this.transport,
      timeoutMs: this.timeoutMs,
      recursionDesired: true,
      checkingDisabled: true,
      dnssecOk: false,
      transports: this.transports,
      onEvent: this.onEvent,
    });
    if (qtype === TYPE_A) {
      const a = result.message?.answers.find(r => r.type === TYPE_A && r.rdata.length === 4);
      return a ? a.rdata.join('.') : undefined;
    }
    const aaaa = result.message?.answers.find(r => r.type === TYPE_AAAA && r.rdata.length === 16);
    return aaaa ? formatIpv6(aaaa.rdata) : undefined;
  }

  // -------------------------------------------------------------------------
  // findings
  // -------------------------------------------------------------------------

  private finding(
    slug: FindingSlug,
    message: string,
    subject: FindingSubject,
    extra: Partial<DnssecFinding> = {}
  ): DnssecFinding {
    const def = FINDING_CATALOG[slug];
    const finding: DnssecFinding = {
      slug,
      severity: def.severity,
      title: def.title,
      message,
      subject,
      rfc: 'rfc' in def ? def.rfc : undefined,
      fix: 'fix' in def ? def.fix : undefined,
      ...extra,
    };
    this.findings.push(finding);
    return finding;
  }

  // -------------------------------------------------------------------------
  // the walk
  // -------------------------------------------------------------------------

  async run(query: string): Promise<EngineOutput> {
    const target = canonicalName(query);

    // the root, anchored on the IANA trust anchors
    const rootServers = Object.entries(ROOT_SERVERS).map(([host, ips]) => ({ host, ip: ips[0] }));
    const rootHosts = Object.fromEntries(rootServers.map(s => [s.ip, s.host]));
    const rootBuild: ZoneBuild = {
      name: '.',
      nameservers: rootServers.map(s => ({
        name: s.host,
        addresses: [s.ip],
        status: SERVER_STATUSES.RESPONDED,
      })),
      serverIps: rootServers.map(s => s.ip),
      fetched: new Map(),
      dnskeyRecords: [],
      started: performance.now(),
    };

    const dnskeyFetch = await this.ask('.', rootBuild.serverIps, '.', TYPE_DNSKEY, rootHosts);
    rootBuild.fetched.set('./DNSKEY', dnskeyFetch);
    rootBuild.dnskeyRecords = dnskeyFetch.answers.filter(r => r.type === TYPE_DNSKEY);

    const trustAnchor = this.anchorRoot(rootBuild.dnskeyRecords);

    const chain: DnssecZone[] = [];
    const rootZone = await this.buildZone(rootBuild, undefined, trustAnchor);
    chain.push(rootZone);

    // both root KSKs are anchored and published, but only one of them signs the DNSKEY RRset
    // at a time. name the anchor that actually validated rather than whichever matched last
    const signingAnchor = ROOT_TRUST_ANCHORS.find(a =>
      rootZone.rrsigs.some(
        s => s.typeCovered === 'DNSKEY' && s.keyTag === a.keyTag && s.check.result === VERIFIED
      )
    );
    if (signingAnchor) {
      trustAnchor.validatedBy = signingAnchor.id;
      trustAnchor.validatedKeyTag = signingAnchor.keyTag;
    }

    // walk down the labels, discovering real zone cuts rather than assuming one per dot
    let parentZone = rootZone;
    let parentBuild = rootBuild;
    let parentServerHosts = rootHosts;

    const labels = target === '.' ? [] : target.split('.');
    for (let i = labels.length - 1; i >= 0; i--) {
      const candidate = labels.slice(i).join('.');
      const cut = await this.discoverZoneCut(candidate, parentBuild, parentServerHosts);
      if (!cut) continue;

      const delegation = await this.buildDelegation(
        parentBuild,
        parentZone,
        candidate,
        parentServerHosts
      );

      const build: ZoneBuild = {
        name: candidate,
        parent: parentBuild.name,
        nameservers: cut.nameservers,
        serverIps: cut.serverIps,
        fetched: new Map(),
        dnskeyRecords: [],
        started: performance.now(),
      };

      if (build.serverIps.length === 0) {
        this.finding(
          'zone-unreachable',
          `No authoritative nameserver address could be resolved for ${candidate}.`,
          { zone: candidate }
        );
      } else {
        const keys = await this.ask(
          candidate,
          build.serverIps,
          candidate,
          TYPE_DNSKEY,
          cut.serverHosts
        );
        build.fetched.set(`${candidate}/DNSKEY`, keys);
        build.dnskeyRecords = keys.answers.filter(r => r.type === TYPE_DNSKEY);

        // the SOA that proved this is a zone cut is the same RRset the zone detail wants —
        // reuse it rather than asking twice
        build.fetched.set(`${candidate}/SOA`, cut.soa);

        const nsec3param = await this.ask(
          candidate,
          build.serverIps,
          candidate,
          TYPE_NSEC3PARAM,
          cut.serverHosts
        );
        build.fetched.set(`${candidate}/NSEC3PARAM`, nsec3param);
      }

      const zone = await this.buildZone(build, delegation, undefined, parentZone.status);
      chain.push(zone);
      parentZone = zone;
      parentBuild = build;
      parentServerHosts = cut.serverHosts;
    }

    // the query name's own RRsets, retrieved from the deepest zone. these are a sample of the
    // zone, never an enumeration — the coverage block says so explicitly
    if (parentBuild.serverIps.length > 0 && target !== '.') {
      const before = this.findings.length;
      await this.fetchTargetRrsets(target, parentBuild, parentServerHosts, parentZone);
      // the target's own records arrive after the zone's verdict was first settled, so the
      // verdict has to be taken again — a corrupt signature on the queried name is exactly
      // the case a one-shot rollup would miss
      parentZone.findings.push(...this.findings.slice(before));
      this.finalizeZoneStatus(parentZone);
    }

    const crossCheck = this.crossCheckEnabled ? await this.runCrossCheck(target) : [];

    return {
      overallStatus: this.rollup(chain),
      chain,
      trustAnchor,
      findings: dedupeFindings(this.findings),
      queries: this.queries,
      digCommands: [...new Set(this.digCommands)],
      crossCheck,
      serverMatrix: this.serverMatrix,
    };
  }

  // -------------------------------------------------------------------------
  // zone cuts
  // -------------------------------------------------------------------------

  // a zone cut exists where the parent returns a delegation for the name — not wherever there
  // is a dot. `www.example.com` usually contributes no zone
  private async discoverZoneCut(
    candidate: string,
    parent: ZoneBuild,
    parentHosts: Record<string, string>
  ): Promise<{
    nameservers: DnssecNameserver[];
    serverIps: string[];
    serverHosts: Record<string, string>;
    soa: Fetched;
  } | null> {
    const answer = await this.ask(parent.name, parent.serverIps, candidate, TYPE_NS, parentHosts);
    if (!answer.message) return null;

    // a referral puts the child's NS RRset in the authority section with AA unset; a server
    // authoritative for both sides answers directly instead. both are candidates
    const nsRecords = [...answer.answers, ...answer.authorities].filter(
      r => r.type === TYPE_NS && canonicalName(r.name) === canonicalName(candidate)
    );
    if (nsRecords.length === 0) return null;

    // glue from the additional section saves a resolution round trip. keep A and AAAA glue apart
    // so IPv4 stays preferred, while an IPv6-only nameserver still contributes an address
    const glue = new Map<string, string[]>();
    const glue6 = new Map<string, string[]>();
    for (const rr of answer.message.additionals) {
      const name = canonicalName(rr.name);
      if (rr.type === TYPE_A && rr.rdata.length === 4) {
        glue.set(name, [...(glue.get(name) ?? []), rr.rdata.join('.')]);
      } else if (rr.type === TYPE_AAAA && rr.rdata.length === 16) {
        glue6.set(name, [...(glue6.get(name) ?? []), formatIpv6(rr.rdata)]);
      }
    }

    const nameservers: DnssecNameserver[] = [];
    const serverIps: string[] = [];
    const serverHosts: Record<string, string> = {};

    for (const rr of nsRecords) {
      const host = presentRecord(rr).split('\t').pop()!.replace(/\.$/, '');
      const ip = await this.resolveHost(host, glue, glue6);
      const entry: DnssecNameserver = {
        name: host,
        addresses: ip ? [ip] : [],
        consulted: ip,
        status: ip ? SERVER_STATUSES.RESPONDED : SERVER_STATUSES.TIMEOUT,
        note: ip ? undefined : 'address could not be resolved',
      };
      nameservers.push(entry);
      if (ip) {
        serverIps.push(ip);
        serverHosts[ip] = host;
      }
    }

    if (serverIps.length === 0) return null;

    // an NS RRset at the name is not by itself a zone cut. `www.cloudflare.com` publishes a
    // signed NS RRset inside its parent zone, and treating that as a delegation reintroduces
    // the every-label-is-a-zone bug from the other direction. the discriminator is the SOA: a
    // zone apex has one, a name inside a zone does not
    const soa = await this.ask(candidate, serverIps, candidate, TYPE_SOA, serverHosts);
    const hasApexSoa = soa.answers.some(
      r => r.type === TYPE_SOA && canonicalName(r.name) === canonicalName(candidate)
    );

    // a clean NOERROR that simply lacks an apex SOA means the name lives inside the parent zone —
    // not a cut. but if the delegated servers timed out or answered with an error, the parent has
    // already handed us a real referral for a child that is lame or unreachable. discarding that
    // as "no cut" would let the target queries fall back to the parent and report its (secure)
    // verdict for a delegation that in fact resolves to nothing, so keep the cut and let the walk
    // mark the child indeterminate/unreachable
    if (!hasApexSoa) {
      const childAnswered = soa.message?.rcode === 0;
      if (childAnswered) return null;
    }

    return { nameservers, serverIps, serverHosts, soa };
  }

  // -------------------------------------------------------------------------
  // delegation (parent side)
  // -------------------------------------------------------------------------

  private async buildDelegation(
    parentBuild: ZoneBuild,
    parentZone: DnssecZone,
    child: string,
    parentHosts: Record<string, string>
  ): Promise<DnssecDelegation> {
    // DS is authoritative in the parent — asking the child for its own DS is the wrong answer
    const fetched = await this.ask(
      parentBuild.name,
      parentBuild.serverIps,
      child,
      TYPE_DS,
      parentHosts
    );
    const delegation: DnssecDelegation = {
      parent: parentBuild.name,
      child,
      dsRecords: [],
      status: INDETERMINATE,
    };

    if (!fetched.message) {
      delegation.reason = fetched.error ?? 'the parent did not answer the DS query';
      this.finding(
        'zone-unreachable',
        `The ${parentBuild.name} servers did not answer the DS query for ${child}.`,
        {
          zone: child,
        }
      );
      return delegation;
    }

    // the parent must answer a DS query itself; a referral means it is answering below the cut
    const referred =
      !fetched.message.aa &&
      fetched.answers.length === 0 &&
      fetched.authorities.some(
        r => r.type === TYPE_NS && canonicalName(r.name) === canonicalName(child)
      );
    if (referred) {
      this.finding(
        'referral-for-ds-query',
        `The ${parentBuild.name} servers answered the DS query for ${child} with a referral instead of the DS RRset.`,
        { zone: child }
      );
    }

    const dsRecords = fetched.answers.filter(r => r.type === TYPE_DS);

    // verify the parent's signature over whatever it returned, before trusting either the DS
    // RRset or the proof of its absence. record whether it actually verified: a secure parent
    // that serves an unsigned or badly signed DS response cannot anchor or exclude the child, and
    // the digest match or denial structure alone must not be allowed to declare the child secure
    // or insecure (RFC 4035 §5)
    if (parentZone.status === SECURE) {
      const dsRrsets = groupRrsets([...fetched.answers, ...fetched.authorities]);
      await this.verifyRrsetsInZone(parentZone, dsRrsets, fetched.rrsigs, fetched, {
        delegationOf: child,
      });
      delegation.parentResponseVerified = dsRecords.length
        ? this.rrsetVerifiedIn(parentZone, child, 'DS')
        : this.denialRecordsVerified(parentZone, fetched.authorities);
    }

    if (dsRecords.length === 0) {
      // no DS: the delegation is insecure, but only if the absence is both proven (the NSEC/NSEC3
      // covers the name) and authenticated (those records carry a valid signature)
      const proof = verifyNoDsProof(child, [...fetched.authorities]);
      delegation.proofOfNoDs = proof;

      const provenUnsigned =
        proof.result === VERIFIED && delegation.parentResponseVerified !== false;

      // opt-out asserts the absence rather than proving it, but the covering NSEC3 must still be
      // validly signed by the parent. a signed opt-out is the ordinary insecure delegation; an
      // unsigned or forged one is spoofable — an attacker strips a real DS and injects opt-out
      // NSEC3 — and is handled as an unauthenticated denial below
      const signedOptOut =
        proof.status === PROOF_STATUSES.OPT_OUT && delegation.parentResponseVerified !== false;

      if (provenUnsigned) {
        delegation.status = INSECURE;
      } else if (signedOptOut) {
        delegation.status = INSECURE;
        this.finding(
          'opt-out-not-authenticated',
          `${child} has no DS record. The covering NSEC3 in ${parentBuild.name} sets opt-out, so the absence is asserted but not cryptographically authenticated.`,
          { zone: child }
        );
      } else if (parentZone.status === SECURE) {
        // a secure parent that cannot prove the absence leaves the child unprovable, whether the
        // proof was missing/incomplete, structurally valid but unsigned, or an unsigned opt-out
        const unsignedDenial =
          delegation.parentResponseVerified === false &&
          (proof.result === VERIFIED || proof.status === PROOF_STATUSES.OPT_OUT);
        delegation.status = INDETERMINATE;
        delegation.reason = unsignedDenial
          ? 'the parent’s NSEC/NSEC3 proof of no DS was not validly signed'
          : proof.reason;
        this.finding(
          'no-ds-proof-missing',
          unsignedDenial
            ? `${parentBuild.name} returned an NSEC/NSEC3 proof that ${child} has no DS record, but those records were not signed by a key ${parentBuild.name} vouches for, so the absence cannot be authenticated.`
            : `${parentBuild.name} returned no DS record for ${child} and no valid NSEC/NSEC3 proof of its absence, so the zone cannot be proven unsigned.`,
          { zone: child }
        );
      } else {
        // the parent is not secure, so there is nothing to prove anything with
        delegation.status = parentZone.status === BOGUS ? BOGUS : INSECURE;
      }
      return delegation;
    }

    // DS present — check every digest, then let the strongest supported type decide
    const childKeys = new Map<number, WireRecord[]>();
    delegation.dsRecords = dsRecords.map(rr => this.describeDs(rr, child, fetched, childKeys));
    return delegation;
  }

  // did the named authoritative RRset verify cryptographically in this zone? used to gate whether a
  // delegation may trust the parent's DS response at all
  private rrsetVerifiedIn(zone: DnssecZone, name: string, type: string): boolean {
    return zone.rrsets.some(
      r =>
        r.authoritative &&
        r.type === type &&
        canonicalName(r.name) === canonicalName(name) &&
        r.status === RRSET_STATUSES.SIGNED_VERIFIED
    );
  }

  // did every NSEC/NSEC3 record backing a proof verify? an unauthenticated denial of a DS cannot be
  // trusted to classify a child as insecure
  private denialRecordsVerified(zone: DnssecZone, authority: WireRecord[]): boolean {
    const denial = authority.filter(r => r.typeName === 'NSEC' || r.typeName === 'NSEC3');
    if (denial.length === 0) return false;
    return denial.every(r => this.rrsetVerifiedIn(zone, r.name, r.typeName));
  }

  private describeDs(
    rr: WireRecord,
    child: string,
    fetched: Fetched,
    _keys: Map<number, WireRecord[]>
  ): DnssecDs {
    const ds = decodeDs(rr.rdata)!;
    const digestInfo = DS_DIGEST_TYPES[ds.digestType as keyof typeof DS_DIGEST_TYPES];
    const check: DigestCheck = {
      result: UNCHECKED,
      digestType: ds.digestType,
      digestTypeName: digestInfo?.name ?? `Unknown (${ds.digestType})`,
      published: toHex(ds.digest),
    };

    return {
      name: rr.name,
      ttl: rr.ttl,
      keyTag: ds.keyTag,
      algorithm: ds.algorithm,
      algorithmName: algorithmName(ds.algorithm),
      digestType: ds.digestType,
      digestTypeName: check.digestTypeName,
      digest: toHex(ds.digest),
      status: DS_STATUSES.NO_MATCHING_DNSKEY,
      check,
      selected: false,
      provenance: {
        zone: canonicalName(parentName(child)),
        server: fetched.server,
        serverHost: fetched.serverHost,
        transport: this.transport,
        section: 'answer',
        queryIndex: fetched.queryIndex,
      },
    };
  }

  // -------------------------------------------------------------------------
  // zone assembly and validation
  // -------------------------------------------------------------------------

  private async buildZone(
    build: ZoneBuild,
    delegation?: DnssecDelegation,
    trustAnchor?: TrustAnchorState,
    parentStatus?: DnssecStatus
  ): Promise<DnssecZone> {
    const zone: DnssecZone = {
      zone: build.name,
      status: INDETERMINATE,
      parent: build.parent,
      isZoneCut: true,
      nameservers: build.nameservers,
      delegation,
      dnskeys: [],
      rrsets: [],
      rrsigs: [],
      denialOfExistence: [],
      algorithms: [],
      findings: [],
      elapsed: Math.round(performance.now() - build.started),
    };

    const before = this.findings.length;

    // an unsigned or broken parent stops the chain here — nothing below an unanchored link
    // can be proven, whatever it publishes
    if (delegation && parentStatus && parentStatus !== SECURE) {
      zone.status = parentStatus === BOGUS ? BOGUS : parentStatus;
      zone.reason =
        parentStatus === INSECURE
          ? `The ${build.parent} zone is unsigned, so ${build.name} cannot be part of a chain of trust.`
          : `Validation stopped at ${build.parent}.`;
      zone.findings = this.findings.slice(before);
      return zone;
    }

    // if the parent proved there is no DS, this zone is provably unsigned regardless of what
    // it publishes — a resolver would stop validating here
    if (delegation && delegation.status === INSECURE) {
      zone.status = INSECURE;
      zone.denialOfExistence = delegation.proofOfNoDs ? [delegation.proofOfNoDs] : [];
      zone.reason = `${build.parent} publishes no DS record for ${build.name}.`;
      zone.findings = this.findings.slice(before);
      return zone;
    }

    if (delegation && delegation.status === INDETERMINATE && delegation.dsRecords.length === 0) {
      zone.status = INDETERMINATE;
      zone.denialOfExistence = delegation.proofOfNoDs ? [delegation.proofOfNoDs] : [];
      zone.reason = delegation.reason;
      zone.findings = this.findings.slice(before);
      return zone;
    }

    // parse the key set
    const keyRecords = build.dnskeyRecords;
    const dnskeys = keyRecords
      .map(rr => this.describeDnskey(rr, build))
      .filter((k): k is DnssecDnskey => Boolean(k));
    zone.dnskeys = dnskeys;
    zone.algorithms = [...new Set(dnskeys.map(k => k.algorithm))].sort((a, b) => a - b);

    if (dnskeys.length === 0) {
      // a DS in the parent with no DNSKEY in the child is the canonical broken delegation,
      // and the single most common real-world DNSSEC outage
      if (delegation && delegation.dsRecords.length > 0) {
        zone.status = BOGUS;
        delegation.status = BOGUS;
        delegation.reason = 'the parent publishes a DS but this zone serves no DNSKEY records';
        zone.reason = `${build.parent} publishes a DS record for ${build.name}, but ${build.name}'s nameservers serve no DNSKEY records.`;
        this.finding(
          'ds-present-child-unsigned',
          `${build.parent} publishes a DS record for ${build.name}, but the zone's nameservers return no DNSKEY records. Every validating resolver returns SERVFAIL for this domain.`,
          { zone: build.name, keyTag: delegation.dsRecords[0]?.keyTag }
        );
      } else if (build.serverIps.length === 0) {
        zone.status = INDETERMINATE;
        zone.reason = `No authoritative server for ${build.name} could be reached.`;
      } else {
        zone.status = INSECURE;
        zone.reason = `${build.name} publishes no DNSKEY records.`;
      }
      zone.findings = this.findings.slice(before);
      return zone;
    }

    // authenticate the key set: against the IANA anchors at the root, against the parent's DS
    // everywhere else. track the specific KEY MATERIAL each entry point vouches for, not the 16-bit
    // tag — tags collide, so a tag alone cannot decide which key the DNSKEY RRset must be signed by
    const authenticatedKeys: DnssecDnskey[] = [];
    if (trustAnchor) {
      // a published key is an entry point only if its own MATERIAL hashes to a current IANA anchor,
      // never merely because it shares a tag with one — otherwise a colliding-tag key added to a
      // poisoned root DNSKEY RRset could sign that RRset and vouch for it. bind by material here,
      // exactly as the DS path does; which anchor is currently signing is decided by the RRSIG check
      for (const key of dnskeys) {
        if (this.keyMatchesAnchor(key)) authenticatedKeys.push(key);
      }
    } else if (delegation) {
      // the DS authenticates the child only if the parent's own response was validly signed. a
      // secure parent serving an unsigned or tampered DS RRset anchors nothing, so a digest match
      // against it must not be enough to call the child secure
      if (delegation.parentResponseVerified === false) {
        this.finding(
          'ds-response-unauthenticated',
          `${build.parent} is secure but its DS response for ${build.name} carries no valid signature, so the DS cannot be trusted to anchor the zone.`,
          { zone: build.name, keyTag: delegation.dsRecords[0]?.keyTag }
        );
      } else {
        authenticatedKeys.push(...this.checkDelegationDigests(delegation, dnskeys, build.name));
      }
    }

    // the DNSKEY RRset must itself be signed by a key the parent (or the anchor) vouches for
    const dnskeyFetch = build.fetched.get(`${build.name}/DNSKEY`);
    const keySetVerified = await this.verifyKeySet(
      zone,
      build,
      dnskeys,
      authenticatedKeys,
      dnskeyFetch
    );

    if (delegation) {
      if (keySetVerified.keyTag !== undefined) {
        delegation.status = SECURE;
        delegation.authenticatedKeyTag = keySetVerified.keyTag;
      } else if (delegation.parentResponseVerified === false) {
        // the DS response itself was never authenticated, so the digests were not even consulted
        delegation.status = BOGUS;
      } else if (delegation.dsRecords.some(d => d.check.result === FAILED)) {
        delegation.status = BOGUS;
      } else if (delegation.dsRecords.every(d => d.check.result === UNCHECKED)) {
        delegation.status = INDETERMINATE;
      } else {
        delegation.status = BOGUS;
      }
    }

    if (!keySetVerified.verified) {
      zone.status = keySetVerified.indeterminate ? INDETERMINATE : BOGUS;
      zone.reason = keySetVerified.reason;
      this.assessKeyHygiene(zone, dnskeys, delegation);
      zone.findings = this.findings.slice(before);
      return zone;
    }

    zone.status = SECURE;

    // every other RRset this zone served
    for (const [key, fetched] of build.fetched) {
      if (key.endsWith('/DNSKEY')) continue;
      await this.absorbFetched(zone, fetched, dnskeys);
    }

    // NSEC3 parameters, for the RFC 9276 assessment
    zone.nsec3Params = this.readNsec3Params(build);

    this.assessKeyHygiene(zone, dnskeys, delegation);
    this.assessNsec3Hygiene(zone);

    this.finalizeZoneStatus(zone);

    zone.findings = this.findings.slice(before);
    return zone;
  }

  // any authoritative RRset a validating resolver cannot authenticate makes the zone bogus even
  // though its key set is fine. this only ever DOWNGRADES: it runs a second time after the queried
  // name's own records arrive, and an upgrade there would silently undo a verdict reached earlier
  // for a reason this function cannot see (a broken delegation leaves no failed signature to find).
  //
  // the judgement is per-RRset, not per-signature. an RRset that carries one good RRSIG alongside a
  // stale or foreign one still validates (RFC 4035 §5.3.3), so a lone FAILED signature must not
  // condemn a zone a resolver would accept — the RRset's own status already folds that in.
  private finalizeZoneStatus(zone: DnssecZone): void {
    if (zone.status !== SECURE) return;

    // unsigned or algorithm-incomplete authoritative data cannot be authenticated at all; an RRset
    // whose signatures were all merely unsupported is indeterminate rather than bogus, so only a
    // signature that was actually checked and failed downgrades a SIGNED_UNVERIFIED RRset
    const brokenRrset = zone.rrsets.find(
      r =>
        r.authoritative &&
        (r.status === RRSET_STATUSES.UNSIGNED ||
          r.status === RRSET_STATUSES.MISSING_ALGORITHM_COVERAGE ||
          (r.status === RRSET_STATUSES.SIGNED_UNVERIFIED && this.rrsetHasFailedSignature(zone, r)))
    );

    // a NODATA/NXDOMAIN answer in a secure zone has to arrive with a proof that actually verifies;
    // a failed or incomplete NSEC/NSEC3 proof means the non-existence cannot be authenticated
    const failedProof = zone.denialOfExistence.find(p => p.result === FAILED);

    if (brokenRrset || failedProof) {
      zone.status = BOGUS;
      if (!zone.reason) {
        const failing = zone.rrsigs.find(s => s.check.result === FAILED && !s.fromParent);
        if (brokenRrset?.status === RRSET_STATUSES.MISSING_ALGORITHM_COVERAGE) {
          zone.reason = `The ${brokenRrset.type} RRset at ${brokenRrset.name} in ${zone.zone} is not signed by every algorithm in the zone's key set.`;
        } else if (brokenRrset?.status === RRSET_STATUSES.UNSIGNED) {
          zone.reason = `The authoritative ${brokenRrset.type} RRset at ${brokenRrset.name} in ${zone.zone} came back with no signature.`;
        } else if (failing) {
          zone.reason = `The ${failing.typeCovered} signature at ${failing.name} failed to validate: ${failing.check.reason ?? 'the signature does not match the data it covers'}.`;
        } else if (failedProof) {
          zone.reason = `The proof of non-existence for ${failedProof.qname} could not be authenticated.`;
        } else {
          zone.reason = `An authoritative RRset in ${zone.zone} could not be authenticated.`;
        }
      }
      return;
    }

    // a SIGNED_UNVERIFIED authoritative RRset that reaches here has in-zone signatures none of which
    // verified and none of which FAILED — so they are all in an algorithm this tool cannot check. a
    // secure zone means a supported algorithm authenticated the key set, so per RFC 4035 §2.2 this
    // RRset should also carry a supported-algorithm signature; it does not (stripped, or genuinely
    // unverifiable), and we must not call unchecked data secure. report it honestly as indeterminate
    const uncheckable = zone.rrsets.find(
      r => r.authoritative && r.status === RRSET_STATUSES.SIGNED_UNVERIFIED
    );
    if (uncheckable) {
      zone.status = INDETERMINATE;
      if (!zone.reason) {
        zone.reason = `The ${uncheckable.type} RRset at ${uncheckable.name} in ${zone.zone} is signed only with an algorithm this tool cannot verify, so its authenticity cannot be confirmed.`;
      }
    }
  }

  // does this RRset carry a signature that was actually checked and failed, as opposed to one that
  // was only unsupported? a zone signing with an algorithm this tool cannot verify is indeterminate,
  // not bogus, so an all-unchecked RRset must not trigger a downgrade
  private rrsetHasFailedSignature(zone: DnssecZone, rrset: DnssecRrset): boolean {
    return zone.rrsigs.some(
      s =>
        !s.fromParent &&
        s.typeCovered === rrset.type &&
        canonicalName(s.name) === canonicalName(rrset.name) &&
        s.check.result === FAILED
    );
  }

  private describeDnskey(rr: WireRecord, build: ZoneBuild): DnssecDnskey | null {
    const key = decodeDnskey(rr.rdata);
    if (!key) return null;

    const keyTag = computeKeyTag(rr.rdata);
    const sep = Boolean(key.flags & DNSKEY_FLAGS.SEP);
    const revoked = Boolean(key.flags & DNSKEY_FLAGS.REVOKE);
    const zoneFlag = Boolean(key.flags & DNSKEY_FLAGS.ZONE);
    const info = DNSSEC_ALGORITHMS[key.algorithm as keyof typeof DNSSEC_ALGORITHMS];

    let status: DnskeyStatus = sep ? DNSKEY_STATUSES.ACTIVE_KSK : DNSKEY_STATUSES.ACTIVE_ZSK;
    if (revoked) status = DNSKEY_STATUSES.REVOKED;
    else if (!zoneFlag) status = DNSKEY_STATUSES.ZONE_FLAG_UNSET;
    else if (key.protocol !== DNSKEY_PROTOCOL) status = DNSKEY_STATUSES.PROTOCOL_NOT_3;
    else if (!info?.verify) status = DNSKEY_STATUSES.UNSUPPORTED_ALGORITHM;
    else if (info.standing === ALGORITHM_STANDINGS.DEPRECATED) {
      status = DNSKEY_STATUSES.DEPRECATED_ALGORITHM;
    }

    return {
      name: rr.name,
      ttl: rr.ttl,
      keyTag,
      flags: key.flags,
      protocol: key.protocol,
      algorithm: key.algorithm,
      algorithmName: algorithmName(key.algorithm),
      keyType: sep ? DNSSEC_KEY_TYPES.KSK : DNSSEC_KEY_TYPES.ZSK,
      sep,
      revoked,
      zoneFlag,
      keySize: keySizeBits(key.algorithm, key.publicKey),
      publicKey: toBase64(key.publicKey),
      status,
      signs: [],
      provenance: {
        zone: build.name,
        server: build.fetched.get(`${build.name}/DNSKEY`)?.server ?? '',
        transport: this.transport,
        section: 'answer',
        queryIndex: build.fetched.get(`${build.name}/DNSKEY`)?.queryIndex,
      },
    };
  }

  // does this published root key's own material hash to a current IANA trust anchor? the entry point
  // at the root is specific key material, not a 16-bit tag, so this is checked per key rather than
  // by tag membership (the DS path binds to material the same way)
  private keyMatchesAnchor(key: DnssecDnskey): boolean {
    const flags = new Uint8Array(4);
    writeU16(flags, 0, key.flags);
    flags[2] = key.protocol;
    flags[3] = key.algorithm;
    const rdata = concatBytes([flags, fromBase64(key.publicKey)]);
    return ROOT_TRUST_ANCHORS.some(anchor => {
      if (!isAnchorCurrent(anchor, this.now)) return false;
      const digest = computeDsDigest('.', rdata, anchor.digestType);
      return Boolean(digest) && toHex(digest!) === anchor.digest;
    });
  }

  // RFC 4034 §5.1.4 digest verification, with the RFC 4509 §3 selection rule on top:
  // the strongest supported digest type present decides, and a weaker type cannot rescue it
  private checkDelegationDigests(
    delegation: DnssecDelegation,
    dnskeys: DnssecDnskey[],
    child: string
  ): DnssecDnskey[] {
    // key tags are a 16-bit checksum and are NOT unique, so index every key by tag as a list and
    // rebuild each key's canonical RDATA. the DS authenticates specific key MATERIAL — a lying
    // child can publish a second key with a colliding tag, so every candidate must be checked
    const keysByTag = new Map<number, DnssecDnskey[]>();
    const rdataFor = new Map<DnssecDnskey, Uint8Array>();
    for (const key of dnskeys) {
      keysByTag.set(key.keyTag, [...(keysByTag.get(key.keyTag) ?? []), key]);
      const flags = new Uint8Array(4);
      writeU16(flags, 0, key.flags);
      flags[2] = key.protocol;
      flags[3] = key.algorithm;
      rdataFor.set(key, concatBytes([flags, fromBase64(key.publicKey)]));
    }

    // pick the strongest supported digest type actually published
    const supported = delegation.dsRecords.filter(
      d => DS_DIGEST_TYPES[d.digestType as keyof typeof DS_DIGEST_TYPES]?.verify
    );
    const selectedType = supported.length
      ? supported.reduce((best, d) => {
          const a = DS_DIGEST_TYPES[d.digestType as keyof typeof DS_DIGEST_TYPES].strength;
          const b = DS_DIGEST_TYPES[best.digestType as keyof typeof DS_DIGEST_TYPES].strength;
          return a > b ? d : best;
        }, supported[0]).digestType
      : undefined;
    delegation.selectedDigestType = selectedType;

    const authenticated: DnssecDnskey[] = [];

    for (const ds of delegation.dsRecords) {
      const info = DS_DIGEST_TYPES[ds.digestType as keyof typeof DS_DIGEST_TYPES];
      const candidates = keysByTag.get(ds.keyTag) ?? [];

      if (!info?.verify) {
        ds.status = DS_STATUSES.UNSUPPORTED_DIGEST;
        ds.check.result = UNCHECKED;
        ds.check.reason = `Digest type ${ds.digestType} (${ds.digestTypeName}) cannot be computed by this tool.`;
        this.finding(
          'ds-digest-unsupported',
          `The DS for ${child} uses digest type ${ds.digestType} (${ds.digestTypeName}), which this tool cannot verify.`,
          { zone: child, keyTag: ds.keyTag, digestType: ds.digestType }
        );
        continue;
      }

      if (selectedType !== undefined && ds.digestType !== selectedType) {
        // RFC 4509 §3: a weaker digest type is ignored outright when a stronger supported one
        // is published. treating "any DS matched" as sufficient would be a downgrade hole
        ds.status = DS_STATUSES.IGNORED_WEAKER_DIGEST;
        ds.check.result = UNCHECKED;
        ds.check.reason = `A stronger supported digest type (${DS_DIGEST_TYPES[selectedType as keyof typeof DS_DIGEST_TYPES].name}) is published, so this record is ignored.`;
        this.finding(
          'ds-digest-ignored',
          `The digest type ${ds.digestType} (${ds.digestTypeName}) DS for ${child} is ignored because a stronger supported digest type is also published.`,
          { zone: child, keyTag: ds.keyTag, digestType: ds.digestType }
        );
        continue;
      }

      ds.selected = true;

      if (candidates.length === 0) {
        ds.status = DS_STATUSES.NO_MATCHING_DNSKEY;
        ds.check.result = FAILED;
        ds.check.reason = `This zone publishes keys ${dnskeys.map(k => k.keyTag).join(', ') || '(none)'}; none has key tag ${ds.keyTag}.`;
        this.finding(
          'ds-no-matching-dnskey',
          `The DS record in ${delegation.parent} commits to key tag ${ds.keyTag}, which ${child} does not publish. The zone publishes ${dnskeys.map(k => k.keyTag).join(', ') || 'no keys'}.`,
          { zone: child, keyTag: ds.keyTag }
        );
        continue;
      }

      const algoMatches = candidates.filter(k => k.algorithm === ds.algorithm);
      if (algoMatches.length === 0) {
        ds.status = DS_STATUSES.DIGEST_MISMATCH;
        ds.check.result = FAILED;
        ds.check.reason = `The DS names algorithm ${ds.algorithm}, but key ${ds.keyTag} uses algorithm ${candidates[0].algorithm}.`;
        this.finding(
          'ds-algorithm-not-in-child',
          `The DS record for ${child} names algorithm ${ds.algorithm} (${ds.algorithmName}), but key ${ds.keyTag} in the zone uses algorithm ${candidates[0].algorithm} (${candidates[0].algorithmName}).`,
          { zone: child, keyTag: ds.keyTag, algorithm: ds.algorithm }
        );
        continue;
      }

      // the DS authenticates whichever published key of the right algorithm hashes to its digest.
      // check every candidate sharing the tag, so a colliding key can neither mask the real key nor
      // stand in for it
      ds.check.input = `${ds.digestTypeName}( canonical("${child}.") || DNSKEY RDATA )`;
      let matched: DnssecDnskey | undefined;
      for (const key of algoMatches) {
        const computed = computeDsDigest(child, rdataFor.get(key)!, ds.digestType);
        ds.check.computed = computed ? toHex(computed) : undefined;
        if (computed && toHex(computed) === ds.digest) {
          matched = key;
          break;
        }
      }

      if (matched) {
        ds.status = DS_STATUSES.VERIFIED;
        ds.check.result = VERIFIED;
        ds.check.matchedKeyTag = ds.keyTag;
        authenticated.push(matched);
        matched.validatedBy = `DS ${ds.keyTag} in ${delegation.parent}`;

        if (info.standing === ALGORITHM_STANDINGS.DEPRECATED) {
          this.finding(
            'ds-digest-deprecated',
            `The DS for ${child} uses digest type ${ds.digestType} (${ds.digestTypeName}), which is deprecated.`,
            { zone: child, keyTag: ds.keyTag, digestType: ds.digestType }
          );
        }
      } else {
        ds.status = DS_STATUSES.DIGEST_MISMATCH;
        ds.check.result = FAILED;
        ds.check.reason = 'The computed digest does not match the published digest.';
        this.finding(
          'ds-digest-invalid',
          `The DS record for ${child} does not match key ${ds.keyTag} as published. The computed ${ds.digestTypeName} digest differs from the one in ${delegation.parent}.`,
          { zone: child, keyTag: ds.keyTag, digestType: ds.digestType }
        );
      }
    }

    return authenticated;
  }

  // the DNSKEY RRset must carry a signature from a key the parent vouches for. this is the
  // link that makes the chain a chain
  private async verifyKeySet(
    zone: DnssecZone,
    build: ZoneBuild,
    dnskeys: DnssecDnskey[],
    authenticatedKeys: DnssecDnskey[],
    fetched?: Fetched
  ): Promise<{ verified: boolean; indeterminate?: boolean; reason?: string; keyTag?: number }> {
    if (!fetched?.message) {
      return {
        verified: false,
        indeterminate: true,
        reason: `No DNSKEY response for ${build.name}.`,
      };
    }

    const rrset = groupRrsets(fetched.answers).find(r => r.type === TYPE_DNSKEY);
    if (!rrset) {
      return {
        verified: false,
        indeterminate: true,
        reason: `No DNSKEY RRset in the answer for ${build.name}.`,
      };
    }

    const sigs = fetched.rrsigs.filter(rr => {
      const sig = decodeRrsig(rr.rdata);
      return (
        sig?.typeCovered === TYPE_DNSKEY && canonicalName(rr.name) === canonicalName(build.name)
      );
    });

    if (sigs.length === 0) {
      this.finding(
        'rrset-unsigned',
        `${build.name} returned a DNSKEY RRset with no RRSIG covering it.`,
        {
          zone: build.name,
          recordType: 'DNSKEY',
        }
      );
      return {
        verified: false,
        reason: `The DNSKEY RRset for ${build.name} carries no signature.`,
      };
    }

    let verifiedTag: number | undefined;
    let sawUnsupported = false;

    for (const rr of sigs) {
      const described = await this.verifyOneSignature(zone, rr, rrset, dnskeys, fetched, false);
      zone.rrsigs.push(described);
      if (described.check.result === UNCHECKED) sawUnsupported = true;
      // authenticate against the key MATERIAL the parent's DS (or the anchor) actually vouched for,
      // never the 16-bit tag: tags collide, and a lying child can publish a colliding key and sign
      // the DNSKEY RRset with it. verify the signature directly against a vouched key (RFC 4035 §5.2)
      if (
        verifiedTag === undefined &&
        (await this.dnskeySigVouched(rr, rrset, authenticatedKeys))
      ) {
        verifiedTag = decodeRrsig(rr.rdata)!.keyTag;
      }
    }

    zone.rrsets.push({
      name: rrset.name,
      type: 'DNSKEY',
      ttl: rrset.ttl,
      records: rrset.records.map(presentRecord),
      rrsigKeyTags: zone.rrsigs.filter(s => s.typeCovered === 'DNSKEY').map(s => s.keyTag),
      status:
        verifiedTag !== undefined
          ? RRSET_STATUSES.SIGNED_VERIFIED
          : RRSET_STATUSES.SIGNED_UNVERIFIED,
      authoritative: true,
    });

    if (verifiedTag !== undefined) {
      // every key in a verified DNSKEY RRset is now trusted, not just the one the DS names
      for (const key of dnskeys) {
        if (!key.validatedBy && key.keyTag !== verifiedTag) {
          key.validatedBy = `KSK ${verifiedTag}`;
        }
      }
      return { verified: true, keyTag: verifiedTag };
    }

    if (authenticatedKeys.length === 0) {
      return {
        verified: false,
        indeterminate: sawUnsupported,
        reason: sawUnsupported
          ? `No supported algorithm links ${build.name} to its parent.`
          : `No key in ${build.name}'s DNSKEY RRset is authenticated by its parent.`,
      };
    }

    return {
      verified: false,
      reason: `The DNSKEY RRset for ${build.name} is not signed by any key its parent vouches for.`,
    };
  }

  // does a DNSKEY RRSIG verify under the specific key MATERIAL an entry point vouched for? binds the
  // DS→DNSKEY link to the hashed key, not its tag, so a colliding key cannot stand in for the real
  // one. temporal validity and the key's own flags are enforced too — an expired signature, or one
  // by a revoked or non-zone key, authenticates nothing
  private async dnskeySigVouched(
    rr: WireRecord,
    rrset: Rrset,
    authenticatedKeys: DnssecDnskey[]
  ): Promise<boolean> {
    const sig = decodeRrsig(rr.rdata);
    if (!sig) return false;
    const now = this.now.getTime();
    if (now > sig.expiration * 1000 || now < sig.inception * 1000) return false;
    const signedData = buildSignedData(sig, rrset);
    if (!signedData) return false;
    // in order, stopping at the first key that vouches, as `some` did
    for (const key of authenticatedKeys) {
      if (key.keyTag !== sig.keyTag || key.algorithm !== sig.algorithm) continue;
      if (!key.zoneFlag || key.revoked || key.protocol !== DNSKEY_PROTOCOL) continue;
      const outcome = await verifySignature(
        key.algorithm,
        fromBase64(key.publicKey),
        signedData.data,
        sig.signature
      );
      if (outcome.verified === true) return true;
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // signatures
  // -------------------------------------------------------------------------

  private async verifyOneSignature(
    zone: DnssecZone,
    rr: WireRecord,
    rrset: Rrset,
    dnskeys: DnssecDnskey[],
    fetched: Fetched,
    fromParent: boolean
  ): Promise<DnssecRrsig> {
    const sig = decodeRrsig(rr.rdata)!;
    const inception = new Date(sig.inception * 1000);
    const expiration = new Date(sig.expiration * 1000);
    const remainingMs = expiration.getTime() - this.now.getTime();

    const described: DnssecRrsig = {
      name: rr.name,
      ttl: rr.ttl,
      typeCovered: recordTypeName(sig.typeCovered),
      algorithm: sig.algorithm,
      algorithmName: algorithmName(sig.algorithm),
      labels: sig.labels,
      originalTtl: sig.originalTtl,
      inception: inception.toISOString(),
      expiration: expiration.toISOString(),
      remainingMs,
      keyTag: sig.keyTag,
      signerName: sig.signerName,
      signature: toBase64(sig.signature),
      status: RRSIG_STATUSES.VERIFIED,
      check: { result: UNCHECKED },
      fromParent,
      provenance: {
        zone: zone.zone,
        server: fetched.server,
        serverHost: fetched.serverHost,
        transport: this.transport,
        section: rr.section,
        queryIndex: fetched.queryIndex,
      },
    };

    const subject: FindingSubject = {
      zone: zone.zone,
      name: rr.name,
      recordType: described.typeCovered,
      keyTag: sig.keyTag,
      algorithm: sig.algorithm,
    };

    // RFC 4035 §5.3.1 preconditions, all of them before any crypto runs
    if (canonicalName(sig.signerName) !== canonicalName(zone.zone)) {
      described.status = RRSIG_STATUSES.SIGNER_MISMATCH;
      described.check = {
        result: FAILED,
        reason: `Signer name ${sig.signerName} is not ${zone.zone}.`,
      };
      this.finding(
        'signer-not-zone',
        `The signature over ${described.typeCovered} at ${rr.name} names signer ${sig.signerName}, which is not the ${zone.zone} zone.`,
        subject
      );
      return described;
    }

    if (sig.labels > countLabels(rr.name)) {
      described.status = RRSIG_STATUSES.LABELS_EXCEED_OWNER;
      described.check = {
        result: FAILED,
        reason: `Labels field ${sig.labels} exceeds the ${countLabels(rr.name)} labels in ${rr.name}.`,
      };
      this.finding(
        'rrsig-labels-exceed-owner',
        `The signature over ${described.typeCovered} at ${rr.name} claims ${sig.labels} labels, but the owner name has only ${countLabels(rr.name)}.`,
        subject
      );
      return described;
    }

    const key = dnskeys.find(k => k.keyTag === sig.keyTag && k.algorithm === sig.algorithm);
    if (!key) {
      described.status = RRSIG_STATUSES.NO_MATCHING_KEY;
      described.check = {
        result: FAILED,
        reason: `This zone publishes no key with tag ${sig.keyTag} and algorithm ${sig.algorithm}.`,
      };
      this.finding(
        'no-matching-dnskey',
        `The signature over ${described.typeCovered} at ${rr.name} references key ${sig.keyTag}, which ${zone.zone} does not publish.`,
        subject
      );
      return described;
    }

    if (!key.zoneFlag) {
      described.status = RRSIG_STATUSES.SIGNATURE_INVALID;
      described.check = {
        result: FAILED,
        reason: `Key ${key.keyTag} does not have the Zone flag set.`,
      };
      this.finding(
        'zone-flag-unset',
        `Key ${key.keyTag} signed ${described.typeCovered} at ${rr.name} but does not have the Zone flag set, so it is not permitted to sign zone data.`,
        subject
      );
      return described;
    }

    if (key.protocol !== DNSKEY_PROTOCOL) {
      described.status = RRSIG_STATUSES.SIGNATURE_INVALID;
      described.check = {
        result: FAILED,
        reason: `Key ${key.keyTag} has protocol ${key.protocol}, not 3.`,
      };
      this.finding(
        'protocol-not-3',
        `Key ${key.keyTag} in ${zone.zone} has protocol ${key.protocol}; DNSSEC requires 3.`,
        subject
      );
      return described;
    }

    if (key.revoked) {
      described.status = RRSIG_STATUSES.REVOKED_KEY;
      described.check = {
        result: FAILED,
        reason: `Key ${key.keyTag} carries the RFC 5011 revoke bit.`,
      };
      this.finding(
        'revoked-key-signing',
        `Key ${key.keyTag} is published as revoked but was used to sign ${described.typeCovered} at ${rr.name}.`,
        subject
      );
      return described;
    }

    // temporal validity — checked before the crypto so an expired signature is reported as
    // expired rather than as a generic failure
    if (this.now.getTime() > expiration.getTime()) {
      const withinSkew = this.now.getTime() - expiration.getTime() <= CLOCK_SKEW_MS;
      described.status = RRSIG_STATUSES.EXPIRED;
      described.check = {
        result: FAILED,
        reason: `Expired ${describeAge(this.now.getTime() - expiration.getTime())} ago.`,
      };
      if (withinSkew) {
        this.finding(
          'signature-within-clock-skew',
          `The signature over ${described.typeCovered} at ${rr.name} expired within the clock-skew tolerance, which may be a timing artefact rather than a real outage.`,
          subject
        );
      } else {
        this.finding(
          'signature-expired',
          `The signature covering ${described.typeCovered} at ${rr.name} expired ${describeAge(this.now.getTime() - expiration.getTime())} ago (${expiration.toISOString()}). Validating resolvers reject expired signatures outright, so this record cannot be resolved.`,
          subject
        );
      }
      return described;
    }

    if (this.now.getTime() < inception.getTime()) {
      described.status = RRSIG_STATUSES.NOT_YET_VALID;
      described.check = {
        result: FAILED,
        reason: `Inception is ${describeAge(inception.getTime() - this.now.getTime())} in the future.`,
      };
      this.finding(
        'signature-not-yet-valid',
        `The signature covering ${described.typeCovered} at ${rr.name} does not become valid until ${inception.toISOString()}, which is ${describeAge(inception.getTime() - this.now.getTime())} from now.`,
        subject
      );
      return described;
    }

    if (rrset.ttl > sig.originalTtl) {
      this.finding(
        'original-ttl-exceeded',
        `The ${described.typeCovered} RRset at ${rr.name} has TTL ${rrset.ttl}, which exceeds the original TTL of ${sig.originalTtl} recorded in its signature.`,
        subject
      );
    }

    // the actual cryptographic check
    const signedData = buildSignedData(sig, rrset);
    if (!signedData) {
      described.check = { result: FAILED, reason: 'The RRset could not be canonicalised.' };
      described.status = RRSIG_STATUSES.SIGNATURE_INVALID;
      return described;
    }

    // fewer labels in the RRSIG than in the owner means the answer was synthesised from a wildcard;
    // the caller must then confirm the queried name has no exact match (RFC 4035 §5.3.4)
    described.wildcard = signedData.wildcard;

    const outcome = await verifySignature(
      sig.algorithm,
      fromBase64(key.publicKey),
      signedData.data,
      sig.signature
    );

    const check: SignatureCheck = {
      result: outcome.verified === undefined ? UNCHECKED : outcome.verified ? VERIFIED : FAILED,
      rrsetSize: rrset.records.length,
      signedDataLength: signedData.data.length,
      signatureLength: sig.signature.length,
      expectedSignatureLength: outcome.expectedSignatureLength,
      publicKeyDescription: outcome.publicKeyDescription,
      reason: outcome.reason,
    };
    described.check = check;

    if (check.result === VERIFIED) {
      described.status = RRSIG_STATUSES.VERIFIED;
      if (!key.signs.includes(described.typeCovered)) key.signs.push(described.typeCovered);

      const windowMs = expiration.getTime() - inception.getTime();
      const nearEndOfWindow = remainingMs <= windowMs * SIGNATURE_EXPIRY_WARNING_FRACTION;
      if (remainingMs <= SIGNATURE_EXPIRY_WARNING_MS && nearEndOfWindow) {
        described.status = RRSIG_STATUSES.EXPIRING_SOON;
        this.finding(
          'signature-expiring-soon',
          `The signature covering ${described.typeCovered} at ${rr.name} expires in ${describeAge(remainingMs)} (${expiration.toISOString()}), which is the last quarter of its ${describeAge(windowMs)} validity window.`,
          subject
        );
      }

      const info = DNSSEC_ALGORITHMS[sig.algorithm as keyof typeof DNSSEC_ALGORITHMS];
      if (info?.standing === ALGORITHM_STANDINGS.DEPRECATED) {
        this.finding(
          'algorithm-deprecated',
          `${zone.zone} signs with ${info.name} (algorithm ${sig.algorithm}), which is deprecated.`,
          subject
        );
      }
    } else if (check.result === UNCHECKED) {
      described.status = RRSIG_STATUSES.UNSUPPORTED_ALGORITHM;
      this.finding(
        'algorithm-not-supported',
        `The signature covering ${described.typeCovered} at ${rr.name} uses ${algorithmName(sig.algorithm)} (algorithm ${sig.algorithm}), which this tool cannot verify. Its status is indeterminate, not valid.`,
        subject
      );
    } else if (
      outcome.expectedSignatureLength &&
      sig.signature.length !== outcome.expectedSignatureLength
    ) {
      described.status = RRSIG_STATUSES.BAD_LENGTH;
      this.finding(
        'signature-bad-length',
        `The signature covering ${described.typeCovered} at ${rr.name} is ${sig.signature.length} bytes; algorithm ${sig.algorithm} (${algorithmName(sig.algorithm)}) requires ${outcome.expectedSignatureLength}.`,
        subject
      );
    } else {
      described.status = RRSIG_STATUSES.SIGNATURE_INVALID;
      this.finding(
        'signature-invalid',
        `The signature covering ${described.typeCovered} at ${rr.name} was checked against key ${sig.keyTag} and failed. The published signature does not match the data it covers.`,
        subject
      );
    }

    return described;
  }

  // fold one response's RRsets into a zone, verifying each
  private async absorbFetched(
    zone: DnssecZone,
    fetched: Fetched,
    dnskeys: DnssecDnskey[]
  ): Promise<void> {
    if (!fetched.message) return;

    const rrsets = groupRrsets(fetched.answers);
    await this.verifyRrsetsInZone(zone, rrsets, fetched.rrsigs, fetched, {});

    // check every proof against the name/type THIS engine asked for, never the response's own
    // question section: that section is unsigned and attacker-mutable, so a server could answer the
    // real query with an empty/NXDOMAIN body but echo a different question that already has a valid
    // signed NSEC/NSEC3, and the proof would verify for the wrong name (RFC 4035 — the proof must
    // cover the queried name). fetched.qname/qtype are what we sent
    const qname = fetched.qname;
    const qtype = fetched.qtype;

    // RFC 4035 §5.3.4: a positive answer synthesised from a wildcard (a verified RRSIG with fewer
    // labels than its owner) is only valid alongside an authenticated NSEC/NSEC3 proof that the
    // queried name has no exact match. without it, a wildcard RRset the zone really signed could be
    // replayed for a name that holds different records or should not exist
    if (fetched.answers.length > 0 && zone.status === SECURE && qname !== undefined) {
      const wildcardAnswer = zone.rrsigs.some(
        s =>
          s.check.result === VERIFIED &&
          s.wildcard &&
          !s.fromParent &&
          canonicalName(s.name) === canonicalName(qname)
      );
      if (wildcardAnswer) {
        await this.verifyDenialRecords(zone, fetched.authorities, fetched);
        const proof = verifyWildcardProof(qname, fetched.authorities);
        zone.denialOfExistence.push(proof);
        if (proof.result !== VERIFIED) {
          this.finding(
            'wildcard-not-covered',
            `${qname} was answered from a wildcard in ${zone.zone}, but the response carries no authenticated NSEC/NSEC3 proof that ${qname} has no records of its own, so the wildcard answer cannot be trusted.`,
            { zone: zone.zone, name: qname }
          );
        }
      }
    }

    // an empty answer in a signed zone should come with a proof
    if (fetched.answers.length === 0 && fetched.message.rcode === 0) {
      const denial = [...fetched.authorities];
      const hasDenial = denial.some(r => r.typeName === 'NSEC' || r.typeName === 'NSEC3');
      // the NSEC/NSEC3 records that carry the proof are authoritative data in their own right:
      // verify their signatures, not only the denial's structure, so a corrupt or unsigned proof
      // downgrades the zone through finalizeZoneStatus rather than passing as secure
      if (hasDenial) await this.verifyDenialRecords(zone, denial, fetched);
      // record the proof whether or not any NSEC/NSEC3 is present: a NODATA answer in a secure zone
      // with no denial records at all yields a FAILED proof, which is exactly the missing-proof case
      // a validator SERVFAILs. without this, an empty answer stripped of its proof passes as secure
      if (qname !== undefined && qtype !== undefined && (hasDenial || zone.status === SECURE)) {
        zone.denialOfExistence.push(verifyNodataProof(qname, qtype, denial));
      }
    } else if (fetched.message.rcode === 3) {
      await this.verifyDenialRecords(zone, fetched.authorities, fetched);
      if (qname !== undefined)
        zone.denialOfExistence.push(verifyNxdomainProof(qname, fetched.authorities));
    }
  }

  // fold the NSEC/NSEC3 records that make up a denial into the zone as authoritative RRsets and
  // verify their signatures. their status then feeds finalizeZoneStatus, so an unsigned or badly
  // signed proof of non-existence cannot leave a secure zone secure
  private async verifyDenialRecords(
    zone: DnssecZone,
    authority: WireRecord[],
    fetched: Fetched
  ): Promise<void> {
    const denialRrsets = groupRrsets(
      authority.filter(r => r.typeName === 'NSEC' || r.typeName === 'NSEC3')
    );
    if (denialRrsets.length === 0) return;
    await this.verifyRrsetsInZone(zone, denialRrsets, fetched.rrsigs, fetched, {});
  }

  private async verifyRrsetsInZone(
    zone: DnssecZone,
    rrsets: Rrset[],
    rrsigs: WireRecord[],
    fetched: Fetched,
    context: { delegationOf?: string }
  ): Promise<void> {
    for (const rrset of rrsets) {
      // several queries can return the same RRset — a CNAME answers A, AAAA, MX and TXT alike
      // — and verifying it once per query would inflate every count in the summary
      if (
        zone.rrsets.some(
          r => canonicalName(r.name) === canonicalName(rrset.name) && r.type === rrset.typeName
        )
      ) {
        continue;
      }

      const covering = rrsigs.filter(rr => {
        const sig = decodeRrsig(rr.rdata);
        return (
          sig?.typeCovered === rrset.type && canonicalName(rr.name) === canonicalName(rrset.name)
        );
      });

      // the parent signs the DS at a zone cut and nothing else: the delegation NS RRset and
      // any glue are non-authoritative and carry no RRSIG by design (RFC 4035 §2.2). flagging
      // them would be teaching the bug as the model
      const isDelegationNs =
        rrset.type === TYPE_NS &&
        Boolean(context.delegationOf) &&
        canonicalName(rrset.name) === canonicalName(context.delegationOf!);
      const isGlue =
        (rrset.type === TYPE_A || rrset.type === TYPE_AAAA) &&
        !isInZoneApexScope(rrset.name, zone.zone);
      const authoritative = !isDelegationNs && !isGlue;

      const described: DnssecRrset = {
        name: rrset.name,
        type: rrset.typeName,
        ttl: rrset.ttl,
        records: rrset.records.map(presentRecord),
        rrsigKeyTags: [],
        status: RRSET_STATUSES.UNSIGNED,
        authoritative,
      };

      if (covering.length === 0) {
        if (authoritative && zone.status === SECURE) {
          this.finding(
            'rrset-unsigned',
            `The ${rrset.typeName} RRset at ${rrset.name} came back with no RRSIG. ${zone.zone} is secure, so an unsigned authoritative RRset cannot be authenticated and validating resolvers return SERVFAIL for it.`,
            { zone: zone.zone, name: rrset.name, recordType: rrset.typeName }
          );
        }
        zone.rrsets.push(described);
        continue;
      }

      let anyVerified = false;
      let hasInZoneSig = false;
      // the algorithms that actually authenticated this RRset with an in-zone signature. RFC 4035
      // §2.2 coverage must rest on these, never on the raw covering set: a foreign-signer or
      // garbage-signature RRSIG naming an algorithm proves no coverage for it
      const verifiedAlgorithms = new Set<number>();
      for (const rr of covering) {
        const sig = decodeRrsig(rr.rdata)!;
        const fromParent = canonicalName(sig.signerName) !== canonicalName(zone.zone);
        const signingZone = fromParent ? { ...zone, zone: canonicalName(sig.signerName) } : zone;
        const keys = fromParent ? [] : zone.dnskeys.length ? zone.dnskeys : [];

        // a parent-signed RRSIG belongs to the parent's bucket, not this zone's — record it
        // with its true provenance rather than filing it under the child
        if (fromParent) {
          const described = this.describeForeignSignature(zone, rr, sig, fetched);
          zone.rrsigs.push(described);
          continue;
        }

        hasInZoneSig = true;
        const verified = await this.verifyOneSignature(
          signingZone,
          rr,
          rrset,
          keys,
          fetched,
          false
        );
        zone.rrsigs.push(verified);
        described.rrsigKeyTags.push(verified.keyTag);
        if (verified.check.result === VERIFIED) {
          anyVerified = true;
          verifiedAlgorithms.add(sig.algorithm);
        }
      }

      // an authoritative RRset can only be authenticated by a signature FROM this zone (RFC 4035
      // §5.3.1). a covering RRSIG that names a foreign signer proves nothing here, so an RRset whose
      // only signatures are foreign is effectively unsigned — otherwise a lying server could strip
      // the real RRSIG and attach a dummy off-zone one to dodge the unsigned→bogus path and pass as
      // secure. the same guard protects the NSEC/NSEC3 denial records, which flow through here too
      if (authoritative && !hasInZoneSig) {
        described.status = RRSET_STATUSES.UNSIGNED;
        if (zone.status === SECURE) {
          this.finding(
            'rrset-unsigned',
            `The ${rrset.typeName} RRset at ${rrset.name} carries no signature from ${zone.zone}; its only RRSIGs name a different signer. ${zone.zone} is secure, so it cannot be authenticated and validating resolvers return SERVFAIL for it.`,
            { zone: zone.zone, name: rrset.name, recordType: rrset.typeName }
          );
        }
        zone.rrsets.push(described);
        continue;
      }

      described.status = anyVerified
        ? RRSET_STATUSES.SIGNED_VERIFIED
        : RRSET_STATUSES.SIGNED_UNVERIFIED;

      // RFC 4035 §2.2: every RRset must carry a signature from each algorithm in the apex
      // DNSKEY RRset. missing coverage for one algorithm in a multi-algorithm zone is a real
      // break that per-signature checking alone misses
      if (authoritative && zone.algorithms.length > 1 && anyVerified) {
        const missing = zone.algorithms.filter(a => !verifiedAlgorithms.has(a));
        if (missing.length) {
          described.status = RRSET_STATUSES.MISSING_ALGORITHM_COVERAGE;
          this.finding(
            'missing-algorithm-coverage',
            `The ${rrset.typeName} RRset at ${rrset.name} is not signed by every algorithm in the ${zone.zone} key set. Missing: ${missing.map(a => `${a} (${algorithmName(a)})`).join(', ')}.`,
            { zone: zone.zone, name: rrset.name, recordType: rrset.typeName }
          );
        }
      }

      zone.rrsets.push(described);
    }
  }

  // an RRSIG made by another zone's key: recorded with its real signer, never verified against
  // this zone's key set
  private describeForeignSignature(
    zone: DnssecZone,
    rr: WireRecord,
    sig: NonNullable<ReturnType<typeof decodeRrsig>>,
    fetched: Fetched
  ): DnssecRrsig {
    const inception = new Date(sig.inception * 1000);
    const expiration = new Date(sig.expiration * 1000);
    return {
      name: rr.name,
      ttl: rr.ttl,
      typeCovered: recordTypeName(sig.typeCovered),
      algorithm: sig.algorithm,
      algorithmName: algorithmName(sig.algorithm),
      labels: sig.labels,
      originalTtl: sig.originalTtl,
      inception: inception.toISOString(),
      expiration: expiration.toISOString(),
      remainingMs: expiration.getTime() - this.now.getTime(),
      keyTag: sig.keyTag,
      signerName: sig.signerName,
      signature: toBase64(sig.signature),
      status: RRSIG_STATUSES.VERIFIED,
      check: { result: UNCHECKED, reason: `Signed by ${sig.signerName}, verified in that zone.` },
      fromParent: true,
      provenance: {
        zone: canonicalName(sig.signerName),
        server: fetched.server,
        serverHost: fetched.serverHost,
        transport: this.transport,
        section: rr.section,
        queryIndex: fetched.queryIndex,
      },
    };
  }

  // -------------------------------------------------------------------------
  // hygiene
  // -------------------------------------------------------------------------

  private assessKeyHygiene(
    zone: DnssecZone,
    dnskeys: DnssecDnskey[],
    delegation?: DnssecDelegation
  ): void {
    const ksks = dnskeys.filter(k => k.sep && !k.revoked);
    const zsks = dnskeys.filter(k => !k.sep && !k.revoked);

    for (const key of dnskeys) {
      if (key.revoked) {
        this.finding(
          'key-revoked',
          `Key ${key.keyTag} in ${zone.zone} carries the RFC 5011 revoke bit.`,
          {
            zone: zone.zone,
            keyTag: key.keyTag,
          }
        );
        continue;
      }
      if (key.signs.length === 0 && key.status !== DNSKEY_STATUSES.ZONE_FLAG_UNSET) {
        key.status = DNSKEY_STATUSES.PUBLISHED_NOT_SIGNING;
      }
      if (
        key.sep &&
        delegation &&
        delegation.dsRecords.length > 0 &&
        !delegation.dsRecords.some(d => d.keyTag === key.keyTag)
      ) {
        key.status = DNSKEY_STATUSES.SEP_WITHOUT_DS;
      }
      if (
        (key.algorithm === 5 ||
          key.algorithm === 7 ||
          key.algorithm === 8 ||
          key.algorithm === 10) &&
        (key.keySize ?? 0) < 2048
      ) {
        this.finding(
          'weak-key-size',
          `Key ${key.keyTag} in ${zone.zone} is ${key.keySize} bits; 2048 is the recommended minimum for RSA.`,
          { zone: zone.zone, keyTag: key.keyTag }
        );
      }
    }

    // rollovers are normal operations, not anomalies
    if (ksks.length > 1) {
      this.finding(
        zone.zone === '.' ? 'root-ksk-rollover' : 'ksk-rollover-in-progress',
        zone.zone === '.'
          ? `The root zone publishes ${ksks.length} KSKs (${ksks.map(k => k.keyTag).join(', ')}). KSK-2024 (38696) begins signing on ${KSK_2024_SIGNING_DATE}; KSK-2017 (20326) is revoked on ${KSK_2017_REVOCATION_DATE}. This is expected and is not a problem with this domain.`
          : `${zone.zone} publishes ${ksks.length} key-signing keys (${ksks.map(k => k.keyTag).join(', ')}), which normally means a rollover is under way.`,
        { zone: zone.zone },
        { alsoAffects: ksks.map(k => ({ zone: zone.zone, keyTag: k.keyTag })) }
      );
      for (const key of ksks) {
        if (key.signs.length === 0) key.status = DNSKEY_STATUSES.PUBLISHED_NOT_SIGNING;
      }
    }

    if (zsks.length > 1) {
      this.finding(
        'zsk-rollover-in-progress',
        `${zone.zone} publishes ${zsks.length} zone-signing keys (${zsks.map(k => k.keyTag).join(', ')}), which normally means a rollover is under way.`,
        { zone: zone.zone },
        { alsoAffects: zsks.map(k => ({ zone: zone.zone, keyTag: k.keyTag })) }
      );
    }

    if (dnskeys.length === 1) {
      this.finding(
        'single-key-zone',
        `${zone.zone} signs with a single key (${dnskeys[0].keyTag}), so a key compromise or loss has no standby.`,
        { zone: zone.zone, keyTag: dnskeys[0].keyTag }
      );
    }

    // every algorithm the zone signs with needs a secure entry point (RFC 4035 §2.2)
    if (delegation && delegation.dsRecords.length > 0) {
      const dsAlgorithms = new Set(delegation.dsRecords.map(d => d.algorithm));
      for (const algorithm of zone.algorithms) {
        if (!dsAlgorithms.has(algorithm)) {
          this.finding(
            'no-sep-for-algorithm',
            `${zone.zone} signs with algorithm ${algorithm} (${algorithmName(algorithm)}), but ${delegation.parent} publishes no DS for a key of that algorithm.`,
            { zone: zone.zone, algorithm }
          );
        }
      }
    }
  }

  private readNsec3Params(build: ZoneBuild): Nsec3Params | undefined {
    const fetched = build.fetched.get(`${build.name}/NSEC3PARAM`);
    const record = fetched?.answers.find(r => r.type === TYPE_NSEC3PARAM);
    if (!record) return undefined;
    const decoded = decodeNsec3Param(record.rdata);
    if (!decoded) return undefined;
    return assessNsec3Params(decoded.hashAlgorithm, decoded.iterations, decoded.salt, false);
  }

  private assessNsec3Hygiene(zone: DnssecZone): void {
    const params = zone.nsec3Params ?? zone.denialOfExistence.find(p => p.nsec3Params)?.nsec3Params;
    if (!params) return;

    if (params.iterations > 0) {
      this.finding(
        'nsec3-iterations-nonzero',
        `${zone.zone} uses ${params.iterations} NSEC3 iterations. RFC 9276 requires 0; validators commonly treat counts above 100 as insecure and above 500 as SERVFAIL.`,
        { zone: zone.zone }
      );
    }
    if (params.salt && params.salt !== '') {
      this.finding(
        'nsec3-salt-nonempty',
        `${zone.zone} uses an NSEC3 salt (${params.salt}). RFC 9276 recommends none — a salt adds no protection against zone enumeration.`,
        { zone: zone.zone }
      );
    }
    if (!params.hashAlgorithmName.startsWith('SHA')) {
      this.finding(
        'nsec3-unsupported-algorithm',
        `${zone.zone} uses NSEC3 hash algorithm ${params.hashAlgorithm}, which this tool cannot compute.`,
        { zone: zone.zone }
      );
    }
  }

  // -------------------------------------------------------------------------
  // target RRsets
  // -------------------------------------------------------------------------

  private async fetchTargetRrsets(
    target: string,
    build: ZoneBuild,
    hosts: Record<string, string>,
    zone: DnssecZone
  ): Promise<void> {
    // the query name's own records, so a name that is not a zone cut still gets checked.
    // these are independent of each other, so a slow or dead type does not serialise behind
    // the rest — the queried name is where an unreachable server hurts most
    const types = [TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_TXT];
    const targets = types.map(type => [target, type] as const);
    // the apex NS, which every signed zone holds
    if (canonicalName(target) === canonicalName(zone.zone)) {
      targets.push([zone.zone, TYPE_NS] as const);
    }

    const fetchedAll = await Promise.all(
      targets.map(([name, type]) => this.ask(zone.zone, build.serverIps, name, type, hosts))
    );

    for (const fetched of fetchedAll) {
      if (fetched.message && zone.status === SECURE)
        await this.absorbFetched(zone, fetched, zone.dnskeys);
    }
  }

  // -------------------------------------------------------------------------
  // corroboration
  // -------------------------------------------------------------------------

  // this is corroboration, not validation — but "our validator says bogus and all three
  // public resolvers SERVFAIL" is the sentence that ends an argument with a registrar
  private async runCrossCheck(target: string): Promise<ResolverCrossCheck[]> {
    const out = await Promise.all(
      CROSS_CHECK_RESOLVERS.map(async resolver => {
        const result = await dnssecQuery(resolver.address, target, TYPE_A, {
          transport: this.transport,
          // deliberately not this.timeoutMs: the verdict does not depend on this answer, so
          // it gets a deadline sized to keep it off the critical path
          timeoutMs: CROSS_CHECK_TIMEOUT_MS,
          recursionDesired: true,
          // the one place CD is left clear — the resolver's own verdict is what is being asked
          checkingDisabled: false,
          dnssecOk: true,
          transports: this.transports,
          onEvent: this.onEvent,
        });
        return {
          resolver: resolver.name,
          address: resolver.address,
          rcode: result.message ? rcodeName(result.message.rcode) : 'NO RESPONSE',
          adBit: Boolean(result.message?.ad),
          extendedError: describeExtendedError(result.message),
          elapsed: result.elapsed,
          error: result.error,
        };
      })
    );
    return out;
  }

  // -------------------------------------------------------------------------
  // rollup
  // -------------------------------------------------------------------------

  // aggregate by validation path, not by worst object: a zone is secure when at least one
  // complete verified path runs from the trust anchor to it. objects that could not be checked
  // stay visible as their own status and in the findings, but do not veto a verdict another
  // path already established
  private rollup(chain: DnssecZone[]): DnssecStatus {
    if (chain.length === 0) return INDETERMINATE;
    return chain[chain.length - 1].status;
  }

  // -------------------------------------------------------------------------
  // trust anchor
  // -------------------------------------------------------------------------

  // verify the fetched root DNSKEY RRset against the embedded IANA anchors. without this the
  // chain bottoms out on data the tool itself fetched over the network
  private anchorRoot(dnskeyRecords: WireRecord[]): TrustAnchorState {
    const state: TrustAnchorState = {
      source: ROOT_TRUST_ANCHOR_SOURCE,
      anchors: ROOT_TRUST_ANCHORS,
      matchedKeyTags: [],
      revokedKeyTags: [],
      result: FAILED,
    };

    if (dnskeyRecords.length === 0) {
      state.reason = 'The root zone DNSKEY RRset could not be retrieved.';
      this.finding('zone-unreachable', 'The root zone DNSKEY RRset could not be retrieved.', {
        zone: '.',
      });
      return state;
    }

    for (const rr of dnskeyRecords) {
      const key = decodeDnskey(rr.rdata);
      if (!key) continue;
      if (key.flags & DNSKEY_FLAGS.REVOKE) state.revokedKeyTags.push(computeKeyTag(rr.rdata));

      for (const anchor of ROOT_TRUST_ANCHORS) {
        if (!isAnchorCurrent(anchor, this.now)) continue;
        const digest = computeDsDigest('.', rr.rdata, anchor.digestType);
        if (digest && toHex(digest) === anchor.digest) {
          state.result = VERIFIED;
          if (!state.matchedKeyTags.includes(anchor.keyTag))
            state.matchedKeyTags.push(anchor.keyTag);
          state.validatedBy ??= anchor.id;
          state.validatedKeyTag ??= anchor.keyTag;
        }
      }
    }

    if (state.result !== VERIFIED) {
      state.reason = 'No published root DNSKEY matched an IANA trust anchor.';
      this.finding(
        'trust-anchor-mismatch',
        'None of the DNSKEY records published by the root zone matched an IANA trust anchor. The chain of trust cannot be anchored.',
        { zone: '.' }
      );
    }

    if (state.revokedKeyTags.length) {
      this.finding(
        'trust-anchor-revoked',
        `The root zone publishes key ${state.revokedKeyTags.join(', ')} with the RFC 5011 revoke bit set.`,
        { zone: '.' }
      );
    }

    return state;
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function toFetched(
  message: WireMessage | undefined,
  queryIndex: number,
  server: string,
  serverHost: string | undefined,
  error?: string
): Fetched {
  if (!message) {
    return { queryIndex, server, serverHost, error, answers: [], authorities: [], rrsigs: [] };
  }
  const rrsigs = [...message.answers, ...message.authorities].filter(r => r.type === TYPE_RRSIG);
  return {
    message,
    queryIndex,
    server,
    serverHost,
    answers: message.answers,
    authorities: message.authorities,
    rrsigs,
  };
}

// the sentinel for "there was nobody to ask" — distinct from "everyone was asked and nobody
// answered", which produces a server-timeout finding
function noServerFetched(): Fetched {
  return {
    queryIndex: -1,
    server: '',
    answers: [],
    authorities: [],
    rrsigs: [],
    error: 'no server to query',
  };
}

function describeFlags(message?: WireMessage): string[] {
  if (!message) return [];
  const flags: string[] = [];
  if (message.aa) flags.push('AA');
  if (message.ad) flags.push('AD');
  if (message.tc) flags.push('TC');
  if (message.ra) flags.push('RA');
  if (message.cd) flags.push('CD');
  if (message.doBit) flags.push('DO');
  return flags;
}

function describeExtendedError(message?: WireMessage): string | undefined {
  if (!message || message.extendedErrorCode === undefined) return undefined;
  return message.extendedErrorText
    ? `${message.extendedErrorCode} (${message.extendedErrorText})`
    : String(message.extendedErrorCode);
}

// 16 bytes of AAAA rdata as a plain (uncompressed) IPv6 literal — the socket layer accepts it, and
// glue only needs an address to dial, not a canonical presentation form
function formatIpv6(rdata: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(readU16(rdata, i).toString(16));
  return groups.join(':');
}

// glue and out-of-zone addresses are not this zone's authoritative data
function isInZoneApexScope(name: string, zone: string): boolean {
  const n = canonicalName(name);
  const z = canonicalName(zone);
  return z === '.' ? true : n === z || n.endsWith(`.${z}`);
}

function describeAge(ms: number): string {
  const abs = Math.abs(ms);
  const days = Math.floor(abs / 86_400_000);
  const hours = Math.floor((abs % 86_400_000) / 3_600_000);
  const minutes = Math.floor((abs % 3_600_000) / 60_000);
  if (days >= 1)
    return hours
      ? `${days} day${days === 1 ? '' : 's'} ${hours} hour${hours === 1 ? '' : 's'}`
      : `${days} day${days === 1 ? '' : 's'}`;
  if (hours >= 1) return `${hours} hour${hours === 1 ? '' : 's'}`;
  if (minutes >= 1) return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  return 'less than a minute';
}

// ten expired RRsets are one finding affecting ten objects, not ten findings
function dedupeFindings(findings: DnssecFinding[]): DnssecFinding[] {
  const byKey = new Map<string, DnssecFinding>();
  for (const finding of findings) {
    const key = `${finding.slug}/${finding.subject.zone ?? ''}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, {
        ...finding,
        alsoAffects: finding.alsoAffects ? [...finding.alsoAffects] : undefined,
      });
      continue;
    }
    existing.alsoAffects = [...(existing.alsoAffects ?? []), finding.subject];
  }

  const order = { error: 0, warning: 1, info: 2 } as const;
  return [...byKey.values()].sort((a, b) => order[a.severity] - order[b.severity]);
}

export { recordTypeCode };
