import { isNode } from './runtime';

// the resolvers this machine is set up to use, which is what `node:dns` asks. Empty on a
// runtime that has no such list to read
export async function systemServers(): Promise<string[]> {
  if (!isNode()) return [];
  try {
    const dns = await import('node:dns');
    return dns.getServers();
  } catch {
    return [];
  }
}
