// map of root servers to their IP addresses
// https://www.iana.org/domains/root/servers
// https://www.internic.net/domain/named.root
export const ROOT_SERVERS = {
  'a.root-servers.net': ['198.41.0.4', '2001:503:ba3e::2:30'],
  'b.root-servers.net': ['170.247.170.2', '2801:1b8:10::b'],
  'c.root-servers.net': ['192.33.4.12', '2001:500:2::c'],
  'd.root-servers.net': ['199.7.91.13', '2001:500:2d::d'],
  'e.root-servers.net': ['192.203.230.10', '2001:500:a8::e'],
  'f.root-servers.net': ['192.5.5.241', '2001:500:2f::f'],
  'g.root-servers.net': ['192.112.36.4', '2001:500:12::d0d'],
  'h.root-servers.net': ['198.97.190.53', '2001:500:1::53'],
  'i.root-servers.net': ['192.36.148.17', '2001:7fe::53'],
  'j.root-servers.net': ['192.58.128.30', '2001:503:c27::2:30'],
  'k.root-servers.net': ['193.0.14.129', '2001:7fd::1'],
  'l.root-servers.net': ['199.7.83.42', '2001:500:9f::42'],
  'm.root-servers.net': ['202.12.27.33', '2001:dc3::35'],
};

// map of reverse nameservers for IP4 addresses
export const REVERSE_SERVERS = {
  'a.in-addr-servers.arpa': ['199.180.182.53', '2620:37:e000::53'],
  'b.in-addr-servers.arpa': ['199.253.183.183', '2620:37:e000:b000::53'],
  'c.in-addr-servers.arpa': ['196.216.169.10', '2001:43f8:110::10'],
  'd.in-addr-servers.arpa': ['200.10.60.53', '2001:13c7:7012::53'],
  'e.in-addr-servers.arpa': ['203.119.86.101', '2001:dd8:6::101'],
  'f.in-addr-servers.arpa': ['193.0.9.1', '2001:67c:e0::1'],
};

// map of reverse nameservers for IP6 addresses, same servers as above
export const REVERSE6_SERVERS = {
  'a.ip6.arpa': ['199.180.182.53', '2620:37:e000::53'],
  'b.ip6.arpa': ['199.253.183.183', '2620:37:e000:b000::53'],
  'c.ip6.arpa': ['196.216.169.10', '2001:43f8:110::10'],
  'd.ip6.arpa': ['200.10.60.53', '2001:13c7:7012::53'],
  'e.ip6.arpa': ['203.119.86.101', '2001:dd8:6::101'],
  'f.ip6.arpa': ['193.0.9.1', '2001:67c:e0::1'],
};

// nameserver cache entry with expiration
interface NameserverCacheEntry {
  ip: string | undefined;
  expires: number; // timestamp when entry expires
}

// in-memory cache for resolved nameserver hostnames
export class NameserverCache {
  private cache: Map<string, NameserverCacheEntry>;

  constructor() {
    this.cache = new Map();
    // pre-populate cache with root server IPv4 addresses
    this.initRootHints();
  }

  // initialize cache with root server IPv4 addresses (never expire)
  private initRootHints(): void {
    for (const [hostname, ips] of Object.entries(ROOT_SERVERS)) {
      this.cache.set(hostname, {
        ip: ips[0], // use IPv4 address (first element)
        expires: Number.MAX_SAFE_INTEGER, // never expire
      });
    }
  }

  get(host: string): string | undefined | null {
    const entry = this.cache.get(host);
    if (!entry) return null; // not found in cache

    // check TTL expiration
    if (Date.now() > entry.expires) {
      this.cache.delete(host);
      return null;
    }
    return entry.ip;
  }

  set(host: string, ip: string | undefined): void {
    this.cache.set(host, {
      ip,
      expires: Date.now() + 300 * 1000, // 5 minute TTL
    });
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}
