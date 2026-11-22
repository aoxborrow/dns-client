// the resolvers: how questions get asked
export { AuthoritativeResolver } from './authoritative';
export type { AuthoritativeQueryOptions, AuthoritativeResolverOptions } from './authoritative';
export { Resolver } from './resolver';
export type { CachedResponse, ResolverOptions, ResolverQueryOptions } from './resolver';
export { createLruCache } from './cache';
export type { Cache, CacheOption, LruCacheOptions } from './cache';
export {
  ROOT_HINTS,
  ROOT_HINTS_DATA_VERSION,
  ROOT_HINTS_REFRESHED,
  ROOT_HINTS_SOURCE,
} from './root-hints';
export type { NameserverHint } from './root-hints';
export type { Answer, QuerySettings, TraceHop } from './answer';
export { toDig } from '../exchange';
export type { DigSource, ExchangeResult, QueryFlags, SentQuery } from '../exchange';
