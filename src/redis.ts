import { randomBytes } from "node:crypto";
import type { Redis } from "ioredis";
import type { KeyValueStore, RateLimiter, Session, SessionStore } from "./stores";

/**
 * Redis stores: shared by every backend server, so a logout or password change on one server
 * applies everywhere at once.
 *   sess:<id>        session JSON, expires after the idle window (never past expiresAt)
 *   usess:<userId>   set of a user's session ids (for "log out everywhere")
 */

export function redisSessionStore(redis: Redis, prefix = "mgpl:auth:"): SessionStore {
  const key = (id: string) => `${prefix}sess:${id}`;
  const userKey = (userId: string) => `${prefix}usess:${userId}`;
  const ttl = (s: Session, idleMs: number) => Math.max(1, Math.min(idleMs, s.expiresAt - Date.now()));

  return {
    async create(s, idleMs) {
      await redis
        .multi()
        .set(key(s.id), JSON.stringify(s), "PX", ttl(s, idleMs))
        .sadd(userKey(s.userId), s.id)
        .pexpireat(userKey(s.userId), s.expiresAt)
        .exec();
    },
    async get(id) {
      const raw = await redis.get(key(id));
      if (!raw) return null;
      const s = JSON.parse(raw) as Session;
      return s.expiresAt > Date.now() ? s : null;
    },
    async touch(id, lastSeenAt, idleMs) {
      const raw = await redis.get(key(id));
      if (!raw) return;
      const s = { ...(JSON.parse(raw) as Session), lastSeenAt };
      await redis.set(key(id), JSON.stringify(s), "PX", ttl(s, idleMs), "XX");
    },
    async delete(id) {
      const raw = await redis.get(key(id));
      const multi = redis.multi().del(key(id));
      if (raw) multi.srem(userKey((JSON.parse(raw) as Session).userId), id);
      await multi.exec();
    },
    async listByUser(userId) {
      const ids = await redis.smembers(userKey(userId));
      if (!ids.length) return [];
      const raws = await redis.mget(...ids.map(key));
      const gone = ids.filter((_, i) => !raws[i]);
      if (gone.length) await redis.srem(userKey(userId), ...gone); // tidy expired ids
      return raws.filter((r): r is string => !!r).map((r) => JSON.parse(r) as Session).filter((s) => s.expiresAt > Date.now());
    },
    async deleteByUser(userId, exceptId) {
      const ids = (await redis.smembers(userKey(userId))).filter((id) => id !== exceptId);
      if (!ids.length) return 0;
      const removed = await redis.del(...ids.map(key));
      await redis.srem(userKey(userId), ...ids);
      return removed;
    },
  };
}

export function redisKeyValueStore(redis: Redis, prefix = "mgpl:auth:kv:"): KeyValueStore {
  return {
    async set(k, value, ttlMs) {
      await redis.set(prefix + k, value, "PX", ttlMs);
    },
    async take(k) {
      // GET + DEL in one transaction: two servers cannot both take the same value
      const res = await redis.multi().get(prefix + k).del(prefix + k).exec();
      return (res?.[0]?.[1] as string | null) ?? null;
    },
  };
}

/** Sliding-window log in a sorted set: at most `limit` hits in any `windowMs`, across all servers. */
export function redisRateLimiter(redis: Redis, o: { limit: number; windowMs: number; prefix?: string }): RateLimiter {
  const prefix = o.prefix ?? "mgpl:auth:rl:";
  return {
    async hit(k) {
      const full = prefix + k;
      const now = Date.now();
      const member = `${now}:${randomBytes(4).toString("hex")}`;
      const res = await redis
        .multi()
        .zremrangebyscore(full, 0, now - o.windowMs)
        .zadd(full, now, member)
        .zcard(full)
        .zrange(full, 0, 0, "WITHSCORES")
        .pexpire(full, o.windowMs)
        .exec();
      const count = Number(res?.[2]?.[1] ?? 0);
      if (count <= o.limit) return { allowed: true, retryAfterMs: 0 };
      await redis.zrem(full, member); // a blocked attempt does not extend the block
      const oldest = Number((res?.[3]?.[1] as string[] | undefined)?.[1] ?? now);
      return { allowed: false, retryAfterMs: Math.max(0, oldest + o.windowMs - now) };
    },
    async reset(k) {
      await redis.del(prefix + k);
    },
    async undo(k) {
      await redis.zpopmax(prefix + k);
    },
  };
}
