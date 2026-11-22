// what a resolver needs from a cache, and the default: a small least-recently-used map
// whose entries expire

// the longest anything is kept, in seconds, whatever its TTL says: one day, as Unbound
// keeps (cache-max-ttl). Answers, delegations and nameserver addresses alike
export const MAX_TTL = 86_400;
// the longest a negative answer (NXDOMAIN, or no records of the type) is kept, in
// seconds. RFC 2308 §5 calls one to three hours a sensible default and more than a day
// problematic; Unbound and PowerDNS keep an hour
export const MAX_NEGATIVE_TTL = 3600;

export interface Cache<Value> {
  get(key: string): Value | undefined;
  // keep `value` for `ttl` milliseconds
  set(key: string, value: Value, ttl: number): void;
  delete(key: string): void;
  clear(): void;
}

export interface LruCacheOptions {
  // how many entries to keep. Default 1000
  max?: number;
  // the clock, in milliseconds. For tests
  now?: () => number;
}

export function createLruCache<Value>(options: LruCacheOptions = {}): Cache<Value> {
  const max = Math.max(1, options.max ?? 1000);
  const now = options.now ?? Date.now;
  // a Map remembers insertion order, so the first key is the least recently used
  const entries = new Map<string, { value: Value; expires: number }>();

  return {
    get(key) {
      const entry = entries.get(key);
      if (!entry) return undefined;
      if (entry.expires <= now()) {
        entries.delete(key);
        return undefined;
      }
      // move to the back: this is now the most recently used
      entries.delete(key);
      entries.set(key, entry);
      return entry.value;
    },
    set(key, value, ttl) {
      if (ttl <= 0) return;
      entries.delete(key);
      entries.set(key, { value, expires: now() + ttl });
      if (entries.size > max) {
        const oldest = entries.keys().next();
        if (!oldest.done) entries.delete(oldest.value);
      }
    },
    delete(key) {
      entries.delete(key);
    },
    clear() {
      entries.clear();
    },
  };
}

// what a resolver's `cache` option accepts: false for none, a cache to use, or settings
// for the default one
export type CacheOption<Value> = false | Cache<Value> | LruCacheOptions;

export function resolveCache<Value>(
  option: CacheOption<Value> | undefined
): Cache<Value> | undefined {
  if (option === false) return undefined;
  if (option && 'get' in option) return option;
  return createLruCache<Value>(option);
}
