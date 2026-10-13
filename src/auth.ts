import { AuthError } from "./errors";
import { memoryRateLimiter } from "./memory";
import { assertPasswordPolicy, hashPassword, hashToken, needsRehash, randomToken, verifyPassword, type PasswordPolicy } from "./password";
import { branchesFor, can, permissionsOf, roleMap, type Permission, type RoleAssignment, type RoleMap } from "./rbac";
import type { AuditSink, AuthUser, KeyValueStore, OrgStore, RateLimiter, RoleStore, Session, SessionStore, UserStore } from "./stores";

export interface AuthOptions {
  users: UserStore;
  sessions: SessionStore;
  /** Needed for login with an organisation code. */
  orgs?: OrgStore;
  /** The organisation's own roles; without it only SYSTEM_ROLES apply. */
  roles?: RoleStore;
  audit?: AuditSink;
  /** Needed for password reset. */
  kv?: KeyValueStore;
  /** Login / reset attempts per IP and per email. Default: 10 per 15 minutes per key, in memory. */
  limiter?: RateLimiter;
  session?: {
    /** Logged out after this long without use. Default 12 h. */
    idleMs?: number;
    /** Logged out after this long regardless. Default 30 days. */
    maxAgeMs?: number;
    /** Extend the idle window at most this often (saves writes). Default 60 s. */
    touchEveryMs?: number;
  };
  /** Password-reset link lifetime. Default 30 minutes. */
  resetTtlMs?: number;
  /** How long an organisation's role list is cached. Default 30 s. */
  roleCacheMs?: number;
  passwordPolicy?: PasswordPolicy;
}

/** The signed-in user for one request. */
export interface Viewer {
  userId: string;
  orgId: string;
  name: string;
  email: string;
  roles: RoleAssignment[];
  sessionId: string;
}

/** What a request handler needs: who is calling and what they may do (fits db-kit's GraphQL context). */
export interface AuthContext {
  viewer: Viewer | null;
  can(permission: string, branchId?: string | null): boolean;
  branchesFor(permission: string): "all" | string[];
  permissions(branchId?: string | null): Permission[];
}

export type PublicUser = Omit<AuthUser, "passwordHash">;

export interface LoginInput {
  email: string;
  password: string;
  /** Required only when the same email/password exists in several organisations. */
  orgCode?: string;
  ip?: string;
  userAgent?: string;
}

export interface LoginResult {
  /** Give this to the client (Authorization: Bearer … or an httpOnly cookie). It is never stored. */
  token: string;
  expiresAt: Date;
  user: PublicUser;
}

const publicUser = ({ passwordHash: _p, ...u }: AuthUser): PublicUser => u;
const normalizeEmail = (e: string) => e.trim().toLowerCase();

export type Auth = ReturnType<typeof createAuth>;

/**
 * The backend's internal auth API. No HTTP: call it from GraphQL resolvers, REST handlers, jobs.
 *
 *   const auth = createAuth({ users: db.repos.users, orgs: db.repos.orgs, roles: db.repos.roles,
 *                             audit: db.repos.audit, sessions: redisSessionStore(redis), kv: redisKeyValueStore(redis),
 *                             limiter: redisRateLimiter(redis, { limit: 10, windowMs: 15 * 60_000 }) });
 *   const { token } = await auth.login({ email, password, ip });
 *   const ctx = await auth.context(token);      // { viewer, can, branchesFor, permissions }
 */
export function createAuth(o: AuthOptions) {
  const idleMs = o.session?.idleMs ?? 12 * 3600_000;
  const maxAgeMs = o.session?.maxAgeMs ?? 30 * 86400_000;
  const touchEveryMs = o.session?.touchEveryMs ?? 60_000;
  const resetTtlMs = o.resetTtlMs ?? 30 * 60_000;
  const roleCacheMs = o.roleCacheMs ?? 30_000;
  const limiter = o.limiter ?? memoryRateLimiter({ limit: 10, windowMs: 15 * 60_000 });
  const roleCache = new Map<string, { map: RoleMap; at: number }>();
  let dummy: Promise<string> | undefined;

  const audit = async (entry: Parameters<AuditSink["log"]>[0]) => {
    try {
      await o.audit?.log(entry);
    } catch {
      /* auditing must never break a login */
    }
  };

  async function limit(keys: (string | undefined)[]) {
    for (const k of keys) {
      if (!k) continue;
      const r = await limiter.hit(k);
      if (!r.allowed) throw new AuthError("RATE_LIMITED", "Too many attempts. Try again later.", { retryAfterMs: r.retryAfterMs });
    }
  }

  async function findCandidates(email: string, orgCode?: string): Promise<AuthUser[]> {
    if (!orgCode) return o.users.findAllByEmail(email);
    if (!o.orgs) throw new Error("createAuth: pass `orgs` to log in with an organisation code");
    const org = await o.orgs.findOne({ code: orgCode.trim().toUpperCase() });
    const user = org ? await o.users.findByEmail(org.id, email) : null;
    return user ? [user] : [];
  }

  async function startSession(user: AuthUser, ip?: string, userAgent?: string): Promise<{ token: string; session: Session }> {
    const token = randomToken();
    const now = Date.now();
    const session: Session = { id: hashToken(token), userId: user.id, orgId: user.orgId, createdAt: now, lastSeenAt: now, expiresAt: now + maxAgeMs, ip, userAgent };
    await o.sessions.create(session, idleMs);
    return { token, session };
  }

  async function rolesFor(orgId: string): Promise<RoleMap> {
    const hit = roleCache.get(orgId);
    if (hit && Date.now() - hit.at < roleCacheMs) return hit.map;
    const map = roleMap(o.roles ? await o.roles.find({ orgId }) : []);
    roleCache.set(orgId, { map, at: Date.now() });
    return map;
  }

  async function authenticate(token: string | null | undefined): Promise<Viewer | null> {
    if (!token || token.length < 20 || token.length > 200) return null;
    const s = await o.sessions.get(hashToken(token));
    if (!s) return null;
    // the user is read on every request, so disabling an account or changing roles applies immediately
    const user = await o.users.get(s.userId);
    if (!user || user.status !== "active") {
      await o.sessions.deleteByUser(s.userId); // disabled or deleted: end every device at once
      return null;
    }
    if (user.orgId !== s.orgId) {
      await o.sessions.delete(s.id);
      return null;
    }
    const now = Date.now();
    if (now - s.lastSeenAt >= touchEveryMs) await o.sessions.touch(s.id, now, idleMs);
    return { userId: user.id, orgId: user.orgId, name: user.name, email: user.email, roles: user.roles, sessionId: s.id };
  }

  async function setNewPassword(user: AuthUser, newPassword: string, keepSessionId?: string) {
    assertPasswordPolicy(newPassword, { email: user.email, name: user.name }, o.passwordPolicy);
    await o.users.update(user.id, { passwordHash: await hashPassword(newPassword) });
    await o.sessions.deleteByUser(user.id, keepSessionId);
  }

  return {
    /** Email + password → session token. Timing-safe, rate-limited, audited. */
    async login(input: LoginInput): Promise<LoginResult> {
      const email = normalizeEmail(input.email);
      await limit([input.ip && `login:ip:${input.ip}`, `login:email:${email}`]);
      const candidates = await findCandidates(email, input.orgCode);
      // unknown email still costs one scrypt verification, so its timing matches a wrong password
      if (!candidates.length) await verifyPassword(input.password, await (dummy ??= hashPassword(randomToken())));
      const matched: AuthUser[] = [];
      for (const u of candidates) if (await verifyPassword(input.password, u.passwordHash)) matched.push(u);
      if (!matched.length) {
        const first = candidates[0];
        if (first) await audit({ orgId: first.orgId, userId: first.id, action: "auth.login_failed", ip: input.ip });
        throw new AuthError("INVALID_CREDENTIALS", "Email or password is incorrect");
      }
      if (matched.length > 1) throw new AuthError("ORG_REQUIRED", "This email belongs to several organisations. Choose one.");
      const user = matched[0]!;
      if (user.status === "disabled") throw new AuthError("ACCOUNT_DISABLED", "This account is disabled");
      if (user.status === "invited") throw new AuthError("INVITE_PENDING", "Accept your invitation first");

      await limiter.reset(`login:email:${email}`);
      const patch: { lastLoginAt: Date; passwordHash?: string } = { lastLoginAt: new Date() };
      if (needsRehash(user.passwordHash)) patch.passwordHash = await hashPassword(input.password);
      await o.users.update(user.id, patch);
      const { token, session } = await startSession(user, input.ip, input.userAgent);
      await audit({ orgId: user.orgId, userId: user.id, action: "auth.login", ip: input.ip });
      return { token, expiresAt: new Date(session.expiresAt), user: publicUser({ ...user, lastLoginAt: patch.lastLoginAt }) };
    },

    /** Token → viewer, or null (unknown, expired, logged out, disabled). Extends the idle window. */
    authenticate,

    /** Everything a request needs. Pass a null/invalid token for an anonymous context. */
    async context(token: string | null | undefined): Promise<AuthContext> {
      const viewer = await authenticate(token);
      if (!viewer) return { viewer: null, can: () => false, branchesFor: () => [], permissions: () => [] };
      const rm = await rolesFor(viewer.orgId);
      return {
        viewer,
        can: (permission, branchId) => can(viewer.roles, permission, rm, branchId),
        branchesFor: (permission) => branchesFor(viewer.roles, permission, rm),
        permissions: (branchId) => permissionsOf(viewer.roles, rm, branchId),
      };
    },

    /** Throws UNAUTHENTICATED / FORBIDDEN; returns the viewer. */
    async require(token: string | null | undefined, permission?: string, branchId?: string | null): Promise<Viewer> {
      const ctx = await this.context(token);
      if (!ctx.viewer) throw new AuthError("UNAUTHENTICATED", "Sign in required");
      if (permission && !ctx.can(permission, branchId)) throw new AuthError("FORBIDDEN", `Missing permission ${permission}`, { permission });
      return ctx.viewer;
    },

    async logout(token: string): Promise<void> {
      const s = await o.sessions.get(hashToken(token));
      if (!s) return;
      await o.sessions.delete(s.id);
      await audit({ orgId: s.orgId, userId: s.userId, action: "auth.logout" });
    },

    /** Logs a user out everywhere (optionally keeping the current session). */
    async logoutAll(userId: string, keepToken?: string): Promise<number> {
      return o.sessions.deleteByUser(userId, keepToken ? hashToken(keepToken) : undefined);
    },

    /** Active sessions ("devices") of a user. `id` can be passed to revokeSession. */
    async sessionsOf(userId: string): Promise<Omit<Session, "userId" | "orgId">[]> {
      return (await o.sessions.listByUser(userId)).map(({ userId: _u, orgId: _o, ...s }) => s).sort((a, b) => b.lastSeenAt - a.lastSeenAt);
    },

    async revokeSession(userId: string, sessionId: string): Promise<boolean> {
      const s = await o.sessions.get(sessionId);
      if (!s || s.userId !== userId) return false;
      await o.sessions.delete(sessionId);
      return true;
    },

    /** Needs the current password; logs out every other session. */
    async changePassword(input: { userId: string; currentPassword: string; newPassword: string; currentToken?: string }): Promise<void> {
      const user = await o.users.get(input.userId);
      if (!user || !(await verifyPassword(input.currentPassword, user.passwordHash))) throw new AuthError("INVALID_CREDENTIALS", "Current password is incorrect");
      if (input.currentPassword === input.newPassword) throw new AuthError("WEAK_PASSWORD", "Choose a different password");
      await setNewPassword(user, input.newPassword, input.currentToken ? hashToken(input.currentToken) : undefined);
      await audit({ orgId: user.orgId, userId: user.id, action: "auth.password_change" });
    },

    /**
     * Starts a reset. Returns the token to deliver (email / SMS link), or null when there is no such
     * active user. Respond the same way in both cases, so the endpoint does not reveal accounts.
     */
    async requestPasswordReset(input: { email: string; orgCode?: string; ip?: string }): Promise<{ token: string; expiresAt: Date; user: PublicUser } | null> {
      if (!o.kv) throw new Error("createAuth: pass `kv` to enable password reset");
      const email = normalizeEmail(input.email);
      await limit([input.ip && `reset:ip:${input.ip}`, `reset:email:${email}`]);
      const candidates = (await findCandidates(email, input.orgCode)).filter((u) => u.status === "active");
      if (candidates.length !== 1) return null;
      const user = candidates[0]!;
      const token = randomToken();
      await o.kv.set(`reset:${hashToken(token)}`, user.id, resetTtlMs);
      await audit({ orgId: user.orgId, userId: user.id, action: "auth.reset_requested", ip: input.ip });
      return { token, expiresAt: new Date(Date.now() + resetTtlMs), user: publicUser(user) };
    },

    /** Completes a reset: single-use token, new password, every session logged out. */
    async resetPassword(input: { token: string; newPassword: string }): Promise<PublicUser> {
      if (!o.kv) throw new Error("createAuth: pass `kv` to enable password reset");
      const userId = await o.kv.take(`reset:${hashToken(input.token)}`);
      const user = userId ? await o.users.get(userId) : null;
      if (!user || user.status !== "active") throw new AuthError("INVALID_TOKEN", "This reset link is invalid or has expired");
      await setNewPassword(user, input.newPassword);
      await audit({ orgId: user.orgId, userId: user.id, action: "auth.password_reset" });
      return publicUser(user);
    },

    /** Admin sets a password (e.g. new staff). Logs the user out everywhere. */
    async setPassword(userId: string, newPassword: string, actorId?: string): Promise<void> {
      const user = await o.users.get(userId);
      if (!user) throw new AuthError("INVALID_TOKEN", "No such user");
      await setNewPassword(user, newPassword);
      await audit({ orgId: user.orgId, userId: actorId ?? null, action: "auth.password_set", entity: "user", entityId: userId });
    },

    /** Call after editing an organisation's roles, so permission changes apply at once. */
    invalidateRoles(orgId?: string): void {
      if (orgId) roleCache.delete(orgId);
      else roleCache.clear();
    },

    /** For creating users: hash + policy check. */
    async hashNewPassword(password: string, user: { email?: string; name?: string } = {}): Promise<string> {
      assertPasswordPolicy(password, user, o.passwordPolicy);
      return hashPassword(password);
    },
  };
}
