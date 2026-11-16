// the root servers: where a resolution that knows nothing starts. From the root hints
// file IANA publishes, which `scripts/refresh-anchors.ts` compares this with (a weekly CI
// job runs it in check mode)
export const ROOT_HINTS_SOURCE = 'https://www.internic.net/domain/named.root';

// the version of that file the data below was taken from: its "related version of root
// zone" line
export const ROOT_HINTS_DATA_VERSION = '2026111201';

// when the data below was last checked against the source
export const ROOT_HINTS_REFRESHED = '2026-11-16';

export interface NameserverHint {
  // the server's name, for the trace
  name?: string;
  ipv4?: string;
  ipv6?: string;
}

export const ROOT_HINTS: readonly NameserverHint[] = [
  { name: 'a.root-servers.net', ipv4: '198.41.0.4', ipv6: '2001:503:ba3e::2:30' },
  { name: 'b.root-servers.net', ipv4: '170.247.170.2', ipv6: '2801:1b8:10::b' },
  { name: 'c.root-servers.net', ipv4: '192.33.4.12', ipv6: '2001:500:2::c' },
  { name: 'd.root-servers.net', ipv4: '199.7.91.13', ipv6: '2001:500:2d::d' },
  { name: 'e.root-servers.net', ipv4: '192.203.230.10', ipv6: '2001:500:a8::e' },
  { name: 'f.root-servers.net', ipv4: '192.5.5.241', ipv6: '2001:500:2f::f' },
  { name: 'g.root-servers.net', ipv4: '192.112.36.4', ipv6: '2001:500:12::d0d' },
  { name: 'h.root-servers.net', ipv4: '198.97.190.53', ipv6: '2001:500:1::53' },
  { name: 'i.root-servers.net', ipv4: '192.36.148.17', ipv6: '2001:7fe::53' },
  { name: 'j.root-servers.net', ipv4: '192.58.128.30', ipv6: '2001:503:c27::2:30' },
  { name: 'k.root-servers.net', ipv4: '193.0.14.129', ipv6: '2001:7fd::1' },
  { name: 'l.root-servers.net', ipv4: '199.7.83.42', ipv6: '2001:500:9f::42' },
  { name: 'm.root-servers.net', ipv4: '202.12.27.33', ipv6: '2001:dc3::35' },
];
