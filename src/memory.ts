import type { KeyValueStore, RateLimiter, Session, SessionStore } from "./stores";

/**
 * In-process stores: for tests, scripts and single-server development. Production with more than
 * one server needs shared state: use the Redis stores ("@mgpl-diagnostics/auth-kit/redis").
 */

export function memorySessionStore(): SessionStore {
  const sessions = new Map<string, { s: Session; idleUntil: number }>();
  const alive = (id: string) => {
    const e = sessions.get(id);
    if (!e) return null;
    if (e.idleUntil <= Date.now() || e.s.expiresAt <= Date.now()) {
      sessions.delete(id);
      return null;
    }
    return e;
  };
  return {
    async create(s, idleMs) {
      sessions.set(s.id, { s: { ...s }, idleUntil: Math.min(s.expiresAt, Date.now() + idleMs) });
    },
    async get(id) {
      const e = alive(id);
      return e ? { ...e.s } : null;
    },
    async touch(id, lastSeenAt, idleMs) {
      const e = alive(id);
      if (e) {
        e.s.lastSeenAt = lastSeenAt;
        e.idleUntil = Math.min(e.s.expiresAt, Date.now() + idleMs);
      }
    },
    async delete(id) {
      sessions.delete(id);
    },
    async listByUser(userId) {
      return [...sessions.keys()].map(alive).filter((e): e is NonNullable<typeof e> => !!e && e.s.userId === userId).map((e) => ({ ...e.s }));
    },
    async deleteByUser(userId, exceptId) {
      let n = 0;
      for (const [id, e] of sessions) if (e.s.userId === userId && id !== exceptId) { sessions.delete(id); n++; }
      return n;
    },
  };
}

export function memoryKeyValueStore(): KeyValueStore {
  const values = new Map<string, { v: string; until: number }>();
  return {
    async set(key, value, ttlMs) {
      values.set(key, { v: value, until: Date.now() + ttlMs });
    },
    async take(key) {
      const e = values.get(key);
      values.delete(key);
      return e && e.until > Date.now() ? e.v : null;
    },
  };
}

/** Sliding window: at most `limit` hits per `windowMs` per key. */
export function memoryRateLimiter(o: { limit: number; windowMs: number }): RateLimiter {
  const hits = new Map<string, number[]>();
  return {
    async hit(key) {
      const now = Date.now();
      const list = (hits.get(key) ?? []).filter((t) => t > now - o.windowMs);
      if (list.length >= o.limit) {
        hits.set(key, list);
        return { allowed: false, retryAfterMs: list[0]! + o.windowMs - now };
      }
      list.push(now);
      hits.set(key, list);
      return { allowed: true, retryAfterMs: 0 };
    },
    async reset(key) {
      hits.delete(key);
    },
    async undo(key) {
      hits.get(key)?.pop();
    },
  };
}
