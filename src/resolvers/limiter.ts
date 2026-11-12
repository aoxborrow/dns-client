// two ways a resolver holds itself back: a cap on how many queries are in flight at once,
// and a minimum gap between queries to any one server

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
