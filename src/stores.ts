import type { RoleAssignment } from "./rbac";

/**
 * Storage interfaces. They are deliberately small and structural: db-kit's repositories satisfy the
 * user / org / role / audit ones as they are (db.repos.users, db.repos.orgs, …), and any other
 * database can implement them in a few lines.
 */

export type UserStatus = "active" | "disabled" | "invited";

export interface AuthUser {
  id: string;
  orgId: string;
  name: string;
  email: string;
  passwordHash: string;
  status: UserStatus;
  roles: RoleAssignment[];
  lastLoginAt?: Date | null;
}

export interface UserStore {
  get(id: string): Promise<AuthUser | null>;
  findByEmail(orgId: string, email: string): Promise<AuthUser | null>;
  /** Same email may exist in several organisations. */
  findAllByEmail(email: string): Promise<AuthUser[]>;
  update(id: string, patch: { passwordHash?: string; lastLoginAt?: Date; status?: UserStatus }): Promise<unknown>;
}

export interface OrgStore {
  findOne(filter: { code: string }): Promise<{ id: string; code: string } | null>;
}

export interface RoleStore {
  /** The organisation's own roles (custom ones and seeded system roles). */
  find(filter: { orgId: string }): Promise<{ key: string; permissions: string[] }[]>;
}

export interface AuditSink {
  log(entry: { orgId: string; userId?: string | null; action: string; ip?: string; entity?: string; entityId?: string | null; data?: Record<string, unknown> }): Promise<unknown>;
}

// ------------------------------------------------------------------ sessions & short-lived values

export interface Session {
  /** sha256 of the token; the token itself is never stored. */
  id: string;
  userId: string;
  orgId: string;
  createdAt: number;
  lastSeenAt: number;
  /** Absolute end (epoch ms): the session dies here even if it is used continuously. */
  expiresAt: number;
  ip?: string;
  userAgent?: string;
}

export interface SessionStore {
  /** Stores a session that disappears after `idleMs` without use (and never outlives `expiresAt`). */
  create(session: Session, idleMs: number): Promise<void>;
  get(id: string): Promise<Session | null>;
  /** Marks use; extends the idle window. */
  touch(id: string, lastSeenAt: number, idleMs: number): Promise<void>;
  delete(id: string): Promise<void>;
  listByUser(userId: string): Promise<Session[]>;
  /** Deletes all of a user's sessions except `exceptId`; returns how many. */
  deleteByUser(userId: string, exceptId?: string): Promise<number>;
}

/** Single-use values with expiry (password-reset tokens). */
export interface KeyValueStore {
  set(key: string, value: string, ttlMs: number): Promise<void>;
  /** Reads and deletes atomically: a value can be taken once. */
  take(key: string): Promise<string | null>;
}

export interface RateLimiter {
  hit(key: string): Promise<{ allowed: boolean; retryAfterMs: number }>;
  reset(key: string): Promise<void>;
}
