import { NameserverCache } from './caches/nameservers';
import { QueryCache } from './caches/queries';
import {
  A_RECORD,
  AAAA_RECORD,
  CNAME_RECORD,
  DEFAULT_PUBLIC_DNS_SERVER,
  DEFAULT_PUBLIC_DOH_SERVER,
  DNAME_RECORD,
  DNS_FLAGS,
  DNS_RECORD_TYPES,
  DNS_RESPONSE_CODES,
  DNS_TRANSPORT_DOH,
  DNS_TRANSPORT_TCP,
  DNS_TRANSPORT_UDP,
  FLAG_RECURSION_DESIRED,
  FLAG_TRUNCATED_RESPONSE,
  NS_RECORD,
} from './constants';
import { parsePacketOptions, parseExtendedDnsErrors, parseEdnsOptions } from './edns';
import {
  ConfigurationError,
  ServerNotFoundError,
  toDnsError,
  TruncatedResponseError,
  type DnsError,
} from './errors';
import { parsePacketAnswer } from './packets';
import type {
  ARecord,
  DnsAnswer,
  DnsFlag,
  DnsOptions,
  DnsPacket,
  DnsQuery,
  DnsQueryFlag,
  DnsQuestion,
  DnsRecord,
  DnsRecordType,
  DnsResolutionHop,
  DnsResponseType,
  PacketAnswer,
} from './types';
import {
  deduplicateRecords,
  detectDohServer,
  getRandomRootServer,
  isValidIp,
  normalizeHost,
  sortRecordsCanonical,
} from './utils';

// default options for DnsClient
export const DEFAULT_OPTIONS: DnsOptions = {
  server: DEFAULT_PUBLIC_DNS_SERVER, // nameserver IP or hostname. starts from root if not provided
  transport: DNS_TRANSPORT_UDP, // 'udp' | 'tcp' | 'doh'
  authoritative: false, // perform recursive resolution following referrals
  flags: [FLAG_RECURSION_DESIRED], // list of DNS query flags to send to the server (default: [RD] when not authoritative)
  tcpFallback: true, // retry over TCP if the UDP response has TC=1 (truncated)
  timeout: 5_000, // timeout in ms
  retries: 0, // retry attempts
  backoff: 100, // base delay for exponential backoff in ms
  cache: true, // enable query cache
  cacheSize: 1000, // max query cache entries
  concurrency: 10, // max concurrent queries
};

export class DnsClient {
  // the client-level options
  options: DnsOptions;

  // in-memory cache for resolved nameserver hostnames
  nsCache: NameserverCache;

  // in-memory query cache for DNS answers
  queryCache: QueryCache;

  // setup client-level options and resolver
  constructor(opts?: Partial<DnsOptions>) {
    this.options = this.getOptions(opts);
    this.nsCache = new NameserverCache();
    this.queryCache = new QueryCache(this.options.cacheSize);
  }

  // process partial options into full DnsOptions with all defaults
  protected getOptions(opts: Partial<DnsOptions> = {}): DnsOptions {
    // merge client-level options (if initialized) or defaults
    const options: DnsOptions = {
      ...(this.options ?? DEFAULT_OPTIONS),
      ...opts,
    };

    // detect DoH server from server string
    if (detectDohServer(options.server)) {
      options.transport = DNS_TRANSPORT_DOH;
    }

    if (options.transport === DNS_TRANSPORT_DOH) {
      // always enable recursive flag for DoH servers
      if (!options.flags.includes(FLAG_RECURSION_DESIRED)) {
        options.flags = [...options.flags, FLAG_RECURSION_DESIRED];
      }
      // if server was not explicitly provided in opts, use default public DoH server (Cloudflare)
      if (!opts.server) {
        options.server = DEFAULT_PUBLIC_DOH_SERVER;
      } else if (!detectDohServer(options.server)) {
        throw new ServerNotFoundError(`Invalid DoH server configured: ${options.server}`);
      }
    } else if (options.authoritative) {
      // disable recursive flag for authoritative/tracing queries
      options.flags = options.flags.filter(f => f !== FLAG_RECURSION_DESIRED);
      // if server was not explicitly provided in opts, use random root server
      if (!opts.server) {
        options.server = getRandomRootServer();
      }
    } else if (!options.server) {
      // default to public server (Cloudflare)
      options.server = DEFAULT_PUBLIC_DNS_SERVER;
    }
    return options;
  }

  // execute a DNS query
  public async query(query: DnsQuery): Promise<DnsAnswer[]> {
    // extract types (default to A record)
    const types = query.types ?? [A_RECORD];

    // ensure valid record type(s) are provided
    const recordTypes = types.map(type => type.toUpperCase() as DnsRecordType);
    for (const recordType of recordTypes) {
      if (!DNS_RECORD_TYPES.includes(recordType)) {
        throw new ConfigurationError(`Invalid record type: ${recordType}`);
      }
    }

    // set options (merges defaults, client-level, and query-level options)
    const opts = this.getOptions({
      ...(query.server && { server: query.server }),
      ...(query.flags && { flags: query.flags.map(flag => flag.toUpperCase() as DnsQueryFlag) }),
    });

    // normalize the hostname
    const normalizedQuery = normalizeHost(query.query);

    // create DnsQuestion objects for each record type
    const questions = recordTypes.map((type: DnsRecordType) => ({
      query: normalizedQuery,
      type,
      server: opts.server,
      flags: opts.flags,
    }));

    // resolve all questions
    return await this.resolveAll(questions, opts);
  }

  // execute multiple queries in parallel
  public async queryAll(queries: DnsQuery[]): Promise<DnsAnswer[]> {
    // expand each DnsQuery into multiple DnsQuestion objects (one per type)
    const questions = queries.flatMap(q => {
      // normalize hostname once per DnsQuery
      const normalizedQuery = normalizeHost(q.query);

      // extract types (default to A record)
      const types = q.types ?? [A_RECORD];

      // ensure valid record type(s) are provided
      const recordTypes = types.map(type => type.toUpperCase() as DnsRecordType);
      for (const recordType of recordTypes) {
        if (!DNS_RECORD_TYPES.includes(recordType)) {
          throw new ConfigurationError(`Invalid record type: ${recordType}`);
        }
      }

      // map each type to a DnsQuestion
      return recordTypes.map(type => ({
        query: normalizedQuery,
        type,
        server: q.server ?? this.options.server,
        flags: q.flags
          ? q.flags.map(flag => flag.toUpperCase() as DnsQueryFlag)
          : this.options.flags,
      }));
    });

    // resolve all questions using the client's resolver
    return await this.resolveAll(questions, this.options);
  }

  // transport-specific methods to send a DNS query
  // uses dynamic imports for UDP/TCP to avoid bundling server-code in browser environments
  protected async transportQuery(question: DnsQuestion, options: DnsOptions): Promise<DnsPacket> {
    switch (options.transport) {
      case DNS_TRANSPORT_UDP: {
        const { udpQuery } = await import('./transports/udp');
        return await udpQuery(question, options);
      }
      case DNS_TRANSPORT_TCP: {
        const { tcpQuery } = await import('./transports/tcp');
        return await tcpQuery(question, options);
      }
      case DNS_TRANSPORT_DOH: {
        const { dohQuery } = await import('./transports/doh');
        return await dohQuery(question, options);
      }
    }
  }

  // resolve multiple queries in parallel up to concurrency limit
  protected async resolveAll(questions: DnsQuestion[], options: DnsOptions): Promise<DnsAnswer[]> {
    // gather all answers from the questions
    const answers: DnsAnswer[] = [];

    // batch questions to respect concurrency limit
    for (let i = 0; i < questions.length; i += options.concurrency) {
      const batch = questions.slice(i, i + options.concurrency);

      // resolve batch queries into answers in parallel
      answers.push(...(await Promise.all(batch.map(q => this.recursiveResolve(q, options)))));
    }
    return answers;
  }

  // resolve a DNS question with optional recursive resolution
  protected async recursiveResolve(
    question: DnsQuestion,
    options: DnsOptions,
    trace: DnsResolutionHop[] = []
  ): Promise<DnsAnswer> {
    // try to resolve the question with retries
    const answer = await this.resolveWithRetries(question, options);

    // build trace step/hop
    trace.push({
      server: answer.server,
      serverHost: answer.serverHost,
      timestamp: new Date(),
      elapsed: answer.elapsed ?? null,
      bytes: answer.bytes ?? null,
      rcode: answer.rcode ?? null,
      rcodeName: answer.rcodeName ?? null,
      flags: answer.flags ?? [],
    });

    // attach the trace to the answer
    answer.trace = trace;

    // check if we got an error answer before proceeding with recursion
    if (answer.error) {
      return answer;
    }

    // do iterative recursion if authoritative is enabled and we have nameserver referrals
    if (
      options.authoritative &&
      answer.records.length === 0 &&
      answer.authorities &&
      answer.authorities.length > 0
    ) {
      // get the next nameserver from the authorities section
      // this should always return a nameserver hostname, not an IP address
      // if the IP is available in the additionals section, it is cached into nameserverCache
      const nextNameserver = this.getNextNameserver(answer);
      if (nextNameserver) {
        // check if we've already queried this server in the trace chain to avoid loops
        const traceServers = trace.map(t => t.server);
        const traceHosts = trace.map(t => t.serverHost).filter((h): h is string => h !== null);

        // check if this is a loop (same server as any in trace or current server)
        if (
          traceServers.includes(nextNameserver) ||
          traceHosts.includes(nextNameserver) ||
          nextNameserver === question.server ||
          nextNameserver === answer.serverHost
        ) {
          // loop detected, return the answer without further recursion
          return answer;
        }

        // recursively resolve against the next nameserver, appending to the trace
        return await this.recursiveResolve(
          {
            ...question,
            server: nextNameserver,
          },
          options,
          trace
        );
      }
    }
    // return the answer with completed resolution + trace
    return answer;
  }

  // try to get the next nameserver from the authorities section
  protected getNextNameserver(answer: DnsAnswer): string | null {
    // get the first NS record from authorities
    const nsRecord = answer.authorities?.find(auth => auth.type === NS_RECORD);
    if (!nsRecord) {
      return null;
    }

    // found a referral nameserver
    const nameserver = nsRecord.value;

    // check additional records for IP addresses to cache
    // prefer A record
    const aRecord = answer.additionals.find(r => r.name === nameserver && r.type === A_RECORD);
    if (aRecord && 'address' in aRecord) {
      // cache the IP address into nameserverCache to avoid a lookup during resolve
      this.nsCache.set(nameserver, aRecord.address);
    } else {
      // fall back to AAAA record
      const aaaaRecord = answer.additionals.find(
        r => r.name === nameserver && r.type === AAAA_RECORD
      );
      if (aaaaRecord && 'address' in aaaaRecord) {
        // just cache the IP address into nameserverCache to avoid a lookup during resolve
        this.nsCache.set(nameserver, aaaaRecord.address);
      }
    }
    // return the next nameserver hostname
    return nameserver;
  }

  // resolve a question with retries
  protected async resolveWithRetries(
    question: DnsQuestion,
    options: DnsOptions
  ): Promise<DnsAnswer> {
    let lastError: DnsError;
    let currentOpts = options;
    for (let attempt = 0; attempt <= options.retries; attempt++) {
      try {
        // try to resolve the question
        return await this.resolve(question, currentOpts);
      } catch (error) {
        // convert to DnsError if needed
        lastError = toDnsError(error);

        // special case: TCP fallback for truncated UDP responses
        if (
          lastError instanceof TruncatedResponseError &&
          currentOpts.transport === DNS_TRANSPORT_UDP &&
          options.tcpFallback
        ) {
          // switch to TCP and retry immediately (doesn't count as a retry)
          currentOpts = { ...currentOpts, transport: DNS_TRANSPORT_TCP };
          continue;
        }

        // should not retry or out of retries, return answer with error attached
        if (attempt >= options.retries || !lastError.shouldRetry?.()) {
          // return answer with error attached
          return this.createAnswer(question, { error: lastError });
        }

        // exponential backoff: backoff * 2^attempt
        // e.g., with default 100ms: 100ms, 200ms, 400ms, 800ms, etc.
        const backoffDelay = options.backoff * Math.pow(2, attempt);
        await this.sleep(backoffDelay);

        // reset to original transport for next retry attempt
        currentOpts = options;
      }
    }

    // this should never be reached (loop always executes at least once)
    throw lastError!;
  }

  // execute a single DNS query
  protected async resolve(question: DnsQuestion, options: DnsOptions): Promise<DnsAnswer> {
    // check cache first if enabled
    if (options.cache) {
      const cached = this.queryCache.get(question);
      if (cached) return cached;
    }

    // for non-DoH servers, resolve server to get both IP and hostname
    // this uses in-memory cache to avoid repeated DNS lookups
    const { server, serverHost } = await this.resolveServer(question.server, options);

    // start building the DnsAnswer object
    const answer = this.createAnswer(question, { serverHost });

    // track query elapsed time
    const startTime = performance.now();

    // make the query using the preferred transport
    const response = await this.transportQuery({ ...question, server }, options);

    // add elapsed time in ms
    answer.elapsed = Math.round(performance.now() - startTime);

    // add the bytes to the answer
    answer.bytes = response.bytes ?? null;

    // get response code from type, e.g. 'SERVFAIL' => 2, 'NOERROR' => 0, etc
    const rcodeUpper = response.rcode
      ? (String(response.rcode).toUpperCase() as DnsResponseType)
      : null;
    answer.rcode = rcodeUpper ? (DNS_RESPONSE_CODES[rcodeUpper] ?? null) : null;

    // set the response code name, e.g. 'NOERROR', 'SERVFAIL', etc
    answer.rcodeName = rcodeUpper;

    // map packet response flags to our DNS flag constants
    // e.g: flag_aa, flag_tc, flag_rd, flag_ra, flag_ad, flag_cd
    Object.keys(DNS_FLAGS).forEach(flag => {
      const packetFlagName = `flag_${flag.toLowerCase()}` as keyof DnsPacket;
      if (
        packetFlagName in response &&
        response[packetFlagName] !== undefined &&
        response[packetFlagName]
      ) {
        answer.flags.push(flag as DnsFlag);
      }
    });

    // check for truncated response flag
    if (
      options.transport === DNS_TRANSPORT_UDP &&
      options.tcpFallback &&
      answer.flags.includes(FLAG_TRUNCATED_RESPONSE)
    ) {
      throw new TruncatedResponseError(
        `Response was truncated (TC flag set) for query '${question.query}', type '${question.type}', from server '${question.server}' (${response.bytes} bytes)`
      );
    }

    // response has authorities, i.e. nameserver referrals
    if (response.authorities && response.authorities.length > 0) {
      // parse and sort the records into our DnsRecords type
      answer.authorities = this.parseAnswers(response.authorities);
    }

    // response has additionals, i.e. Nameserver IPs and EDNS0 options
    if (response.additionals && response.additionals.length > 0) {
      // A/AAAA - IP addresses for nameservers referenced in NS records or mail servers in MX records
      // RRSIG - DNSSEC signatures for records in other sections
      // NSEC/NSEC3 - DNSSEC authenticated denial of existence records
      // OPT - EDNS(0) extension information and capabilities
      // TSIG - Transaction signatures for authenticated DNS exchanges

      // parse and sort the records into our DnsRecords type
      answer.additionals = this.parseAnswers(response.additionals);

      // parse OPT records from additionals for EDNS processing
      const packetOptions = parsePacketOptions(response.additionals);

      // parse the DNS Extended Errors, only present if the EDNS options are set in the query
      // https://www.rfc-editor.org/rfc/rfc8914.html
      // https://developers.cloudflare.com/1.1.1.1/infrastructure/extended-dns-error-codes/
      const extendedErrors = parseExtendedDnsErrors(packetOptions);
      if (Object.keys(extendedErrors).length > 0) {
        answer.extendedErrors = extendedErrors;
      }

      // parse the EDNS0 options, these are only present if the EDNS options are set in the query
      // https://www.rfc-editor.org/rfc/rfc6891.html#name-edns-0-options
      const ednsOptions = parseEdnsOptions(packetOptions);
      if (ednsOptions.length > 0) {
        answer.ednsOptions = ednsOptions;
      }
    }

    // response has answers, i.e DNS records, return the answer
    if (response.answers && response.answers.length > 0) {
      // parse and sort the records into our DnsRecords type
      const parsedRecords = this.parseAnswers(response.answers);

      // filter out CNAME/DNAME records if the requested record type is not CNAME or DNAME
      // this prevents CNAME records from showing up when querying a host that is a CNAME itself
      answer.records = parsedRecords.filter(record => {
        if (question.type === CNAME_RECORD || question.type === DNAME_RECORD) {
          // if we're specifically querying for CNAME or DNAME, don't filter anything out
          return true;
        }
        // for all other query types, filter out CNAME and DNAME records
        return record.type !== CNAME_RECORD && record.type !== DNAME_RECORD;
      });
    }

    // cache the answer if caching is enabled
    if (options.cache && this.queryCache) {
      this.queryCache.set(question, answer);
    }

    // return the answer
    return answer;
  }

  // helper method to resolve a server string to both IP and hostname
  // for DoH: returns server URL as-is
  // for UDP/TCP with IP: returns IP with no hostname
  // for UDP/TCP with hostname: resolves to IP (using cache or DNS lookup)
  protected async resolveServer(
    server: string,
    options: DnsOptions
  ): Promise<{ server: string; serverHost: string | null }> {
    // DoH servers are URLs, return as-is
    if (options.transport === DNS_TRANSPORT_DOH) {
      return { server, serverHost: null };
    }

    // normalize the server string
    const host = normalizeHost(server);

    // server is already an IP address
    if (isValidIp(host)) {
      return { server: host, serverHost: null };
    }

    // check cache first
    const cached = this.nsCache.get(host);
    if (cached) {
      return {
        server: cached, // resolved IP
        serverHost: host,
      };
    }

    // resolve using the same mode as the original query for consistency
    // inherit most options from original query, but override server and recursion
    const resolveOpts: DnsOptions = {
      ...options,
      // use appropriate server based on authoritative mode (DoH not possible here)
      server: options.authoritative ? getRandomRootServer() : DEFAULT_PUBLIC_DNS_SERVER,
      // set recursion flag: use RD for recursive mode, no RD for authoritative mode
      flags: options.authoritative ? [] : [FLAG_RECURSION_DESIRED],
      cache: true, // enable cache for this resolution
    };

    // create a DnsQuestion object for the resolution
    // this will include the DNSSEC flags based on the options, and RD flag based on authoritative mode
    const question: DnsQuestion = {
      query: host,
      type: A_RECORD,
      server: resolveOpts.server,
      flags: resolveOpts.flags,
    };

    // resolve the server hostname to an IP address
    const answer = await this.resolveWithRetries(question, resolveOpts);
    const aRecord = answer.records?.find(r => r.type === A_RECORD) as ARecord;
    if (aRecord?.address) {
      // cache successful resolution and return
      this.nsCache.set(host, aRecord.address);
      return {
        server: aRecord.address, // resolved IP
        serverHost: host, // keep original hostname
      };
    }

    // couldn't resolve hostname to IP - throw error for UDP/TCP
    throw new ServerNotFoundError(`Failed to resolve server '${host}' to IP address`);
  }

  // create a DnsAnswer object with optional overrides
  protected createAnswer(question: DnsQuestion, overrides?: Partial<DnsAnswer>): DnsAnswer {
    return {
      query: question.query,
      type: question.type,
      server: question.server,
      serverHost: null,
      elapsed: null,
      bytes: null,
      rcode: null,
      rcodeName: null,
      extendedErrors: null,
      ednsOptions: null,
      error: null,
      flags: [],
      records: [],
      authorities: [],
      additionals: [],
      trace: [],
      ...overrides,
    };
  }

  // parse/format the records from dns-packet into our DnsRecords type with canonical sorting
  protected parseAnswers(answers: PacketAnswer[]): DnsRecord[] {
    // handle null/undefined/empty answers
    if (!answers || answers.length === 0) {
      return [];
    }

    // parse the packet answers individually and filter out any null entries (OPT records)
    const records = answers
      .map(answer => parsePacketAnswer(answer))
      .filter((record): record is DnsRecord => record !== null);

    // deduplicate records
    const deduplicatedRecords = deduplicateRecords(records);

    // sort the records in canonical order
    return sortRecordsCanonical(deduplicatedRecords);
  }

  // sleep helper for backoff
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// export types and constants
export type * from './types';
export * from './constants';
export * from './utils';
export * from './errors';
