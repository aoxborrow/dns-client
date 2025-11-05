import type { DnsAnswer, DnsQuestion } from '../types.js';

// default maximum query cache size
const MAX_CACHE_SIZE = 1000;

// query cache entry with expiration
interface QueryCacheEntry {
  answer: DnsAnswer;
  expires: number; // timestamp when entry expires
}

// query cache with TTL and LRU eviction, keyed by DnsQuestion
export class QueryCache {
  private cache: Map<string, QueryCacheEntry>;
  private maxSize: number;

  constructor(maxSize: number = MAX_CACHE_SIZE) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }

  get(question: DnsQuestion): DnsAnswer | null {
    const key = this.makeKey(question);
    const entry = this.cache.get(key);
    if (!entry) return null;

    // check TTL expiration
    if (Date.now() > entry.expires) {
      this.cache.delete(key);
      return null;
    }

    // move to end (most recently used) for proper LRU behavior
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.answer;
  }

  set(question: DnsQuestion, answer: DnsAnswer): void {
    // LRU eviction if cache is full
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }
    const key = this.makeKey(question);
    const ttl = this.getMinTTL(answer);
    this.cache.set(key, {
      answer,
      expires: Date.now() + ttl * 1000,
    });
  }

  private makeKey(question: DnsQuestion): string {
    // key by question properties that affect the answer
    const flags = question.flags?.sort().join(':') ?? '';
    return `${question.query}:${question.type}:${question.server}:${flags}`;
  }

  private getMinTTL(answer: DnsAnswer): number {
    // find minimum TTL from all records
    let minTTL = Infinity;
    for (const record of answer.records ?? []) {
      if (record.ttl < minTTL) minTTL = record.ttl;
    }
    return minTTL === Infinity ? 300 : minTTL; // default 5 min
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}
