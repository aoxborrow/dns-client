import { getServers } from 'node:dns';
import { readFileSync, statSync } from 'node:fs';
import { isIpv4, isIpv6 } from './endpoint';

// what the machine itself says about names, read the way the system resolver reads it: the
// hosts file and the configured DNS servers. Node only; the `node:dns` facade is the one
// user, and loads this at import

export interface HostsEntry {
  address: string;
  family: 4 | 6;
}

// the DNS servers this machine is set up to use, as `node:dns` reports them
export function configuredServers(): string[] {
  try {
    return getServers();
  } catch {
    return [];
  }
}

const HOSTS_PATH =
  process.platform === 'win32'
    ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32\\drivers\\etc\\hosts`
    : '/etc/hosts';

// the file is read again when it changes, and looked at no more than once a second
const RECHECK_MS = 1000;

let hosts: Map<string, HostsEntry[]> | undefined;
let hostsModified = -1;
let hostsChecked = 0;

// one name per line after the address; `#` starts a comment. Names are compared without
// regard to case, and an address listed twice for a name is kept once
export function parseHosts(text: string): Map<string, HostsEntry[]> {
  const table = new Map<string, HostsEntry[]>();
  for (const line of text.split(/\r?\n/)) {
    const [address, ...names] = line.replace(/#.*/, '').trim().split(/\s+/);
    if (!address || names.length === 0) continue;
    // a zone (`fe80::1%lo0`) stays on the address, as the system resolver keeps it
    const family = isIpv4(address) ? 4 : isIpv6(address) ? 6 : undefined;
    if (!family) continue;
    for (const name of names) {
      const key = name.toLowerCase().replace(/\.$/, '');
      const entries = table.get(key) ?? [];
      if (!entries.some(entry => entry.address === address)) entries.push({ address, family });
      table.set(key, entries);
    }
  }
  return table;
}

// the addresses the hosts file gives a name, in the order the file lists them
export function hostsEntries(name: string): HostsEntry[] {
  const now = Date.now();
  if (now - hostsChecked >= RECHECK_MS) {
    hostsChecked = now;
    try {
      const modified = statSync(HOSTS_PATH).mtimeMs;
      if (modified !== hostsModified || !hosts) {
        hosts = parseHosts(readFileSync(HOSTS_PATH, 'utf8'));
        hostsModified = modified;
      }
    } catch {
      hosts = new Map();
    }
  }
  return hosts?.get(name.toLowerCase().replace(/\.$/, '')) ?? [];
}
