// three ways a resolver holds itself back: a cap on how many queries are in flight at
// once, a cap on how many are in flight to any one server, and a minimum gap between
// queries to any one server

export type Limiter = <T>(task: () => Promise<T>) => Promise<T>;

// run at most `max` tasks at a time; the rest wait their turn in the order they came
export function createLimiter(max: number): Limiter {
  if (!Number.isFinite(max) || max <= 0) return task => task();
  let running = 0;
  const waiting: (() => void)[] = [];

  return async task => {
    if (running >= max) await new Promise<void>(resolve => waiting.push(resolve));
    running++;
    try {
      return await task();
    } finally {
      running--;
      waiting.shift()?.();
    }
  };
}

// wait until `gap` milliseconds have passed since the last query to the same server. A
// burst of questions for one authoritative server then goes out spaced, not all at once
export function createPacer(gap: number): (server: string) => Promise<void> {
  const next = new Map<string, number>();
  return async server => {
    if (gap <= 0) return;
    const now = Date.now();
    const at = Math.max(now, next.get(server) ?? 0);
    next.set(server, at + gap);
    if (at > now) await new Promise<void>(resolve => setTimeout(resolve, at - now));
  };
}

export type KeyedLimiter = <T>(key: string, task: () => Promise<T>) => Promise<T>;

// run at most `max` tasks at a time under each key, a server's address. A key is
// forgotten once nothing is running or waiting under it, so the map holds only the
// servers being asked right now
export function createKeyedLimiter(max: number): KeyedLimiter {
  if (!Number.isFinite(max) || max <= 0) return (_key, task) => task();
  const queues = new Map<string, { running: number; waiting: (() => void)[] }>();

  return async (key, task) => {
    let queue = queues.get(key);
    if (!queue) queues.set(key, (queue = { running: 0, waiting: [] }));
    if (queue.running >= max) await new Promise<void>(resolve => queue.waiting.push(resolve));
    queue.running++;
    try {
      return await task();
    } finally {
      queue.running--;
      const next = queue.waiting.shift();
      if (next) next();
      else if (queue.running === 0) queues.delete(key);
    }
  };
}
