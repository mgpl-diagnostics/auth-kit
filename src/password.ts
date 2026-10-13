import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { AuthError } from "./errors";

const scrypt = (password: string, salt: Buffer, keylen: number, options: ScryptOptions) =>
  new Promise<Buffer>((resolve, reject) => scryptCb(password.normalize("NFKC"), salt, keylen, options, (err, key) => (err ? reject(err) : resolve(key))));

/** scrypt cost: N=2^15, r=8, p=1 ≈ 50–100 ms per hash on a server. Slow for attackers, fine for logins. */
export const SCRYPT = { N: 2 ** 15, r: 8, p: 1, keylen: 32 } as const;
const maxmem = (N: number, r: number) => 128 * N * r * 2;

/** "scrypt$N$r$p$salt$hash" (base64url): self-describing, so the cost can be raised later. */
export async function hashPassword(password: string, params: { N: number; r: number; p: number } = SCRYPT): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT.keylen, { N: params.N, r: params.r, p: params.p, maxmem: maxmem(params.N, params.r) });
  return ["scrypt", params.N, params.r, params.p, salt.toString("base64url"), key.toString("base64url")].join("$");
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [algo, n, r, p, saltB64, keyB64] = stored.split("$");
  if (algo !== "scrypt" || !saltB64 || !keyB64) return false;
  const N = Number(n), R = Number(r), P = Number(p);
  if (!(N >= 2 ** 10 && N <= 2 ** 20) || !(R >= 1 && R <= 32) || !(P >= 1 && P <= 16)) return false; // refuse absurd params
  const expected = Buffer.from(keyB64, "base64url");
  const key = await scrypt(password, Buffer.from(saltB64, "base64url"), expected.length, { N, r: R, p: P, maxmem: maxmem(N, R) });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

/** True when the stored hash is weaker than today's parameters: re-hash after a successful login. */
export function needsRehash(stored: string): boolean {
  const [algo, n, r, p] = stored.split("$");
  return algo !== "scrypt" || Number(n) < SCRYPT.N || Number(r) < SCRYPT.r || Number(p) < SCRYPT.p;
}

const COMMON = new Set([
  "password", "password1", "password123", "12345678", "123456789", "1234567890", "qwerty123", "11111111", "00000000",
  "iloveyou", "admin123", "welcome1", "abcd1234", "india123", "letmein1", "changeme", "passw0rd", "p@ssw0rd",
]);

export interface PasswordPolicy {
  minLength?: number;
  maxLength?: number;
}

/** Throws WEAK_PASSWORD with a readable reason. Length first (NIST 800-63B), no forced symbol rules. */
export function assertPasswordPolicy(password: string, context: { email?: string; name?: string } = {}, policy: PasswordPolicy = {}): void {
  const min = policy.minLength ?? 8;
  const max = policy.maxLength ?? 128;
  const reason =
    password.length < min ? `Use at least ${min} characters`
    : password.length > max ? `Use at most ${max} characters`
    : /^(.)\1+$/.test(password) ? "Do not repeat one character"
    : COMMON.has(password.toLowerCase()) ? "This password is too common"
    : context.email && password.toLowerCase().includes(context.email.split("@")[0]!.toLowerCase()) && context.email.split("@")[0]!.length >= 4 ? "Do not use your email in the password"
    : null;
  if (reason) throw new AuthError("WEAK_PASSWORD", reason);
}

/** Random opaque token (sessions, reset links). 32 bytes → 43 base64url chars. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** Stores keep only this: a leaked database or Redis does not reveal usable tokens. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}
