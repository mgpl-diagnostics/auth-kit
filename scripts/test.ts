// npm test — passwords, login, sessions (memory + Redis stores), permissions, reset flow.
import RedisMock from "ioredis-mock";
import {
  AuthError, cleanDeviceSignals, createAuth, hashTlsFingerprint, hashPassword, hashToken, memoryKeyValueStore, memoryRateLimiter, memorySessionStore, needsRehash,
  permissionsOf, roleMap, verifyPassword, assertPasswordPolicy, can, branchesFor, SYSTEM_ROLES,
  type AuditSink, type AuthUser, type KeyValueStore, type RateLimiter, type RoleStore, type SessionStore, type UserStore,
} from "../src/index";
import { redisKeyValueStore, redisRateLimiter, redisSessionStore } from "../src/redis";

let failed = 0, passed = 0;
const ok = (cond: unknown, msg: string) => {
  if (cond) { passed++; console.log(`  ok    ${msg}`); }
  else { failed++; console.log(`  FAIL  ${msg}`); }
};
const code = async (p: Promise<unknown>) => { try { await p; return "none"; } catch (e) { return e instanceof AuthError ? e.code : `other:${(e as Error).message}`; } };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ in-memory stand-ins for db-kit repositories

function fakeDb() {
  const users = new Map<string, AuthUser>();
  const orgs = [{ id: "org-a", code: "MGPL" }, { id: "org-b", code: "OTHER" }];
  const orgRoles: Record<string, { key: string; permissions: string[] }[]> = { "org-a": [{ key: "lab_auditor", permissions: ["audit:read", "accounts:read"] }] };
  const auditLog: { action: string; userId?: string | null; data?: Record<string, unknown> }[] = [];
  const userStore: UserStore = {
    get: async (id) => (users.has(id) ? { ...users.get(id)! } : null),
    findByEmail: async (orgId, email) => [...users.values()].find((u) => u.orgId === orgId && u.email === email) ?? null,
    findAllByEmail: async (email) => [...users.values()].filter((u) => u.email === email),
    update: async (id, patch) => { users.set(id, { ...users.get(id)!, ...patch }); },
  };
  const roleStore: RoleStore = { find: async ({ orgId }) => orgRoles[orgId] ?? [] };
  const audit: AuditSink = { log: async (e) => { auditLog.push(e); } };
  const add = async (u: Omit<AuthUser, "passwordHash"> & { password: string; hashParams?: { N: number; r: number; p: number } }) => {
    users.set(u.id, { ...u, passwordHash: await hashPassword(u.password, u.hashParams) });
  };
  return { users, userStore, orgStore: { findOne: async ({ code }: { code: string }) => orgs.find((o) => o.code === code) ?? null }, roleStore, audit, auditLog, orgRoles, add };
}

// ------------------------------------------------------------------ unit: passwords & RBAC

async function units() {
  console.log("\n[passwords]");
  const h = await hashPassword("correct horse battery");
  ok(h.startsWith("scrypt$32768$8$1$") && (await verifyPassword("correct horse battery", h)) && !(await verifyPassword("wrong horse", h)), "scrypt hash verifies right, rejects wrong");
  ok((await hashPassword("same")) !== (await hashPassword("same")), "salted: same password → different hashes");
  ok(needsRehash(await hashPassword("x".repeat(9), { N: 2 ** 14, r: 8, p: 1 })) && !needsRehash(h), "needsRehash spots weaker parameters");
  ok(!(await verifyPassword("a", "scrypt$99999999999$8$1$aa$bb")) && !(await verifyPassword("a", "md5$abc")), "absurd or foreign hashes are refused, not executed");
  const weak = (p: string, email?: string) => { try { assertPasswordPolicy(p, { email }); return null; } catch (e) { return (e as AuthError).code; } };
  ok(weak("short") === "WEAK_PASSWORD" && weak("password123") === "WEAK_PASSWORD" && weak("aaaaaaaaaa") === "WEAK_PASSWORD" && weak("ravi.kumar-2026", "ravi.kumar@x.in") === "WEAK_PASSWORD" && weak("tulsi-leaf-raipur") === null, "password policy: length, common, repeated, contains email");

  console.log("\n[rbac]");
  const rm = roleMap([{ key: "lab_auditor", permissions: ["audit:read"] }]);
  const desk = [{ role: "front_desk", branchId: "b1" }];
  ok(can(desk, "invoice:create", rm, "b1") && !can(desk, "invoice:create", rm, "b2") && !can(desk, "accounts:read", rm), "branch-scoped role: allowed in its branch only");
  ok(can([{ role: "owner", branchId: null }], "anything:goes", rm) && can([{ role: "admin", branchId: null }], "accounts:post", rm, "b9"), "owner *:*, admin accounts:* everywhere");
  ok(branchesFor(desk, "booking:read", rm).toString() === "b1" && branchesFor([{ role: "admin", branchId: null }], "booking:read", rm) === "all", "branchesFor: list vs all");
  ok(permissionsOf([{ role: "lab_auditor", branchId: null }], rm).join() === "audit:read", "custom organisation role");
  ok(SYSTEM_ROLES.some((r) => r.key === "accountant" && r.permissions.includes("accounts:*")), "accountant role covers the books");
}

// ------------------------------------------------------------------ flows, per store

async function flows(label: string, stores: { sessions: SessionStore; kv: KeyValueStore; limiter: RateLimiter }) {
  console.log(`\n[auth / ${label}]`);
  const db = fakeDb();
  await db.add({ id: "u1", orgId: "org-a", name: "Asha", email: "asha@mgpl.in", password: "tulsi-leaf-raipur", status: "active", roles: [{ role: "front_desk", branchId: "b1" }] });
  await db.add({ id: "u2", orgId: "org-a", name: "Old", email: "old@mgpl.in", password: "neem-tree-arang", status: "active", roles: [{ role: "owner", branchId: null }], hashParams: { N: 2 ** 14, r: 8, p: 1 } });
  await db.add({ id: "u3", orgId: "org-a", name: "Gone", email: "gone@mgpl.in", password: "mango-season-27", status: "disabled", roles: [] });
  await db.add({ id: "u4", orgId: "org-a", name: "Dual A", email: "dual@x.in", password: "shared-pass-99", status: "active", roles: [{ role: "owner", branchId: null }] });
  await db.add({ id: "u5", orgId: "org-b", name: "Dual B", email: "dual@x.in", password: "shared-pass-99", status: "active", roles: [{ role: "owner", branchId: null }] });
  const auth = createAuth({
    users: db.userStore, orgs: db.orgStore, roles: db.roleStore, audit: db.audit, ...stores,
    session: { idleMs: 60_000, maxAgeMs: 120_000, touchEveryMs: 0 },
  });

  const login = await auth.login({ email: "  ASHA@mgpl.in ", password: "tulsi-leaf-raipur", ip: "1.1.1.1", userAgent: "test" });
  ok(login.token.length === 43 && login.user.email === "asha@mgpl.in" && !("passwordHash" in login.user), "login: token issued, email normalised, no hash returned");
  const v = await auth.authenticate(login.token);
  ok(v?.userId === "u1" && v.orgId === "org-a" && v.sessionId === hashToken(login.token), "authenticate: token → viewer");
  ok((await code(auth.login({ email: "asha@mgpl.in", password: "wrong-password" }))) === "INVALID_CREDENTIALS", "wrong password → INVALID_CREDENTIALS");
  ok((await code(auth.login({ email: "nobody@mgpl.in", password: "whatever-pass" }))) === "INVALID_CREDENTIALS", "unknown email → same INVALID_CREDENTIALS");

  let t = Date.now(); await code(auth.login({ email: "nobody2@mgpl.in", password: "whatever-pass" })); const unknownMs = Date.now() - t;
  t = Date.now(); await code(auth.login({ email: "asha@mgpl.in", password: "whatever-pass" })); const wrongMs = Date.now() - t;
  ok(unknownMs > wrongMs * 0.4, `timing-safe: unknown email ${unknownMs} ms vs wrong password ${wrongMs} ms`);

  ok((await code(auth.login({ email: "gone@mgpl.in", password: "mango-season-27" }))) === "ACCOUNT_DISABLED", "disabled account → ACCOUNT_DISABLED");
  ok((await code(auth.login({ email: "dual@x.in", password: "shared-pass-99" }))) === "ORG_REQUIRED", "same email in two organisations → ORG_REQUIRED");
  ok((await auth.login({ email: "dual@x.in", password: "shared-pass-99", orgCode: "other" })).user.id === "u5", "…with orgCode → the right one");

  const before = db.users.get("u2")!.passwordHash;
  await auth.login({ email: "old@mgpl.in", password: "neem-tree-arang" });
  ok(before.startsWith("scrypt$16384$") && db.users.get("u2")!.passwordHash.startsWith("scrypt$32768$"), "weak hash upgraded on login");

  // context & permissions
  const ctx = await auth.context(login.token);
  ok(ctx.can("invoice:create", "b1") && !ctx.can("invoice:create", "b2") && !ctx.can("accounts:read") && ctx.branchesFor("booking:read").toString() === "b1", "context: branch-aware can / branchesFor");
  db.users.set("u1", { ...db.users.get("u1")!, roles: [{ role: "lab_auditor", branchId: null }] });
  ok((await auth.context(login.token)).can("accounts:read"), "role change applies on the next request (custom org role)");
  db.orgRoles["org-a"] = [{ key: "lab_auditor", permissions: ["audit:read"] }];
  auth.invalidateRoles("org-a");
  ok(!(await auth.context(login.token)).can("accounts:read"), "invalidateRoles: edited role applies at once");
  ok((await code(auth.require(login.token, "settings:manage"))) === "FORBIDDEN" && (await code(auth.require("bad-token-xxxxxxxxxxxxxxxx"))) === "UNAUTHENTICATED", "require: FORBIDDEN / UNAUTHENTICATED");
  const anon = await auth.context(null);
  ok(anon.viewer === null && !anon.can("patient:read"), "anonymous context can nothing");

  // sessions
  const second = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur", userAgent: "phone" });
  ok((await auth.sessionsOf("u1")).length === 2 && (await auth.revokeSession("u1", hashToken(second.token))) && (await auth.authenticate(second.token)) === null, "two devices listed; one revoked by id");
  // idle timeout, with its own short window (logins themselves take ~100 ms of scrypt)
  const short = createAuth({ users: db.userStore, ...stores, session: { idleMs: 500, maxAgeMs: 60_000, touchEveryMs: 0 } });
  const busy = await short.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  const idle = await short.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  await sleep(300);
  await short.authenticate(busy.token); // used: slides its window
  await sleep(300);
  ok((await short.authenticate(busy.token)) !== null && (await short.authenticate(idle.token)) === null, "idle timeout: used session slides, unused one expires");
  const capped = createAuth({ users: db.userStore, ...stores, session: { idleMs: 60_000, maxAgeMs: 300, touchEveryMs: 0 } });
  const c = await capped.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  await sleep(350);
  ok((await capped.authenticate(c.token)) === null, "absolute max age ends even an active session");
  db.users.set("u1", { ...db.users.get("u1")!, status: "disabled" });
  ok((await auth.authenticate(login.token)) === null && (await auth.sessionsOf("u1")).length === 0, "disabling a user ends their sessions at once");
  db.users.set("u1", { ...db.users.get("u1")!, status: "active" });

  const s1 = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  const s2 = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  await auth.logout(s1.token);
  ok((await auth.authenticate(s1.token)) === null && (await auth.authenticate(s2.token)) !== null, "logout ends only that session");
  ok((await code(auth.changePassword({ userId: "u1", currentPassword: "nope-nope-nope", newPassword: "banyan-roots-7" }))) === "INVALID_CREDENTIALS", "change password needs the current one");
  const s3 = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  await auth.changePassword({ userId: "u1", currentPassword: "tulsi-leaf-raipur", newPassword: "banyan-roots-7", currentToken: s3.token });
  ok((await auth.authenticate(s3.token)) !== null && (await auth.authenticate(s2.token)) === null, "change password keeps this session, ends the others");

  // reset
  ok((await auth.requestPasswordReset({ email: "ghost@mgpl.in" })) === null, "reset for unknown email → null (respond the same either way)");
  const r = (await auth.requestPasswordReset({ email: "asha@mgpl.in" }))!;
  await auth.resetPassword({ token: r.token, newPassword: "peepal-shade-12" });
  ok((await auth.login({ email: "asha@mgpl.in", password: "peepal-shade-12" })).user.id === "u1" && (await auth.authenticate(s3.token)) === null, "reset sets the password and ends every session");
  ok((await code(auth.resetPassword({ token: r.token, newPassword: "another-one-55" }))) === "INVALID_TOKEN", "reset token is single-use");
  ok((await code(auth.resetPassword({ token: (await auth.requestPasswordReset({ email: "asha@mgpl.in" }))!.token, newPassword: "short" }))) === "WEAK_PASSWORD", "reset enforces the password policy");

  // rate limit (fresh limiter: 3 attempts / window)
  const strict = createAuth({ users: db.userStore, sessions: stores.sessions, limiter: label === "redis" ? redisRateLimiter(new RedisMock() as any, { limit: 3, windowMs: 60_000, prefix: `rl${Date.now()}:` }) : memoryRateLimiter({ limit: 3, windowMs: 60_000 }) });
  const codes: string[] = [];
  for (let i = 0; i < 4; i++) codes.push(await code(strict.login({ email: "old@mgpl.in", password: "bad-guess-000", ip: "9.9.9.9" })));
  ok(codes.slice(0, 3).every((c) => c === "INVALID_CREDENTIALS") && codes[3] === "RATE_LIMITED", "4th attempt from the same IP/email → RATE_LIMITED");

  ok(db.auditLog.some((e) => e.action === "auth.login") && db.auditLog.some((e) => e.action === "auth.login_failed") && db.auditLog.some((e) => e.action === "auth.password_reset"), "audit trail written");
}

// ------------------------------------------------------------------ JWT mode: access + refresh tokens

const SECRET = "test-secret-0123456789-abcdefghijklmnop";
const issued: string[] = []; // refresh tokens handed out, to prove Redis never stores them

async function jwtFlows(label: string, stores: { sessions: SessionStore; kv: KeyValueStore; limiter: RateLimiter }) {
  console.log(`\n[jwt / ${label}]`);
  const db = fakeDb();
  await db.add({ id: "j1", orgId: "org-a", name: "Asha", email: "asha@mgpl.in", password: "tulsi-leaf-raipur", status: "active", roles: [{ role: "front_desk", branchId: "b1" }] });
  const auth = createAuth({ users: db.userStore, audit: db.audit, ...stores, session: { idleMs: 60_000, maxAgeMs: 120_000, touchEveryMs: 0 }, jwt: { secret: SECRET, issuer: "mgpl-api", accessTtlMs: 60_000, reuseGraceMs: 200 } });

  const l = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  issued.push(l.refreshToken!);
  const [h, p] = l.token.split(".");
  const header = JSON.parse(Buffer.from(h!, "base64url").toString());
  const claims = JSON.parse(Buffer.from(p!, "base64url").toString());
  ok(header.alg === "HS256" && claims.sub === "j1" && claims.org === "org-a" && claims.iss === "mgpl-api" && claims.exp - claims.iat === 60, "login: HS256 access JWT (sub, org, sid, iss, 60 s)");
  ok(!!l.refreshToken && l.refreshToken.length === 43 && l.refreshExpiresAt! > l.expiresAt, "login: opaque refresh token outlives the access token");
  ok((await auth.authenticate(l.token))?.userId === "j1" && auth.verifyAccessToken(l.token)?.sid === claims.sid, "access token → viewer; verifyAccessToken without storage");
  ok((await auth.authenticate(l.refreshToken)) === null, "a refresh token is not a bearer token");

  // tampering
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...claims, sub: "someone-else" })).toString("base64url")}.${l.token.split(".")[2]}`;
  const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${p}.`;
  const other = createAuth({ users: db.userStore, ...stores, jwt: { secret: "another-secret-0123456789-abcdefghijk" } });
  ok((await auth.authenticate(forged)) === null && (await auth.authenticate(none)) === null && (await other.authenticate(l.token)) === null, "forged claims, alg none and a foreign secret are refused");
  const rotated = createAuth({ users: db.userStore, ...stores, jwt: { secret: ["new-secret-0123456789-abcdefghijklmnopq", SECRET], issuer: "mgpl-api" } });
  ok((await rotated.authenticate(l.token))?.userId === "j1", "secret rotation: old tokens verify while the old secret is listed");

  // refresh rotation
  const r1 = await auth.refresh({ refreshToken: l.refreshToken! });
  issued.push(r1.refreshToken);
  ok(r1.refreshToken !== l.refreshToken && (await auth.authenticate(r1.accessToken))?.userId === "j1" && auth.verifyAccessToken(r1.accessToken)?.sid === claims.sid, "refresh: new access + new refresh token, same session");
  ok((await code(auth.refresh({ refreshToken: l.refreshToken! }))) === "INVALID_TOKEN" && (await auth.authenticate(r1.accessToken)) !== null, "spent refresh token within the grace window: refused, session kept");
  await sleep(250);
  ok((await code(auth.refresh({ refreshToken: l.refreshToken! }))) === "INVALID_TOKEN" && (await auth.authenticate(r1.accessToken)) === null, "spent refresh token reused later: session ended (theft)");
  ok((await code(auth.refresh({ refreshToken: r1.refreshToken }))) === "INVALID_TOKEN" && db.auditLog.some((e) => e.action === "auth.refresh_reuse"), "…its newer refresh token dies too, and it is audited");

  // logout / revocation apply at once despite a valid signature
  const a = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  const b = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  issued.push(a.refreshToken!, b.refreshToken!);
  await auth.logout(a.token);
  ok((await auth.authenticate(a.token)) === null && (await code(auth.refresh({ refreshToken: a.refreshToken! }))) === "INVALID_TOKEN" && (await auth.authenticate(b.token)) !== null, "logout with the access token ends that session and its refresh token");
  await auth.logout(b.refreshToken!);
  ok((await auth.authenticate(b.token)) === null, "logout with the refresh token works too");
  const c = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  const d = await auth.login({ email: "asha@mgpl.in", password: "tulsi-leaf-raipur" });
  issued.push(c.refreshToken!, d.refreshToken!);
  await auth.changePassword({ userId: "j1", currentPassword: "tulsi-leaf-raipur", newPassword: "banyan-roots-7", currentToken: c.token });
  ok((await auth.authenticate(c.token)) !== null && (await auth.authenticate(d.token)) === null, "change password with an access token keeps this session only");
  db.users.set("j1", { ...db.users.get("j1")!, status: "disabled" });
  ok((await code(auth.refresh({ refreshToken: c.refreshToken! }))) === "INVALID_TOKEN" && (await auth.authenticate(c.token)) === null, "disabled user: refresh refused, access token dead at once");

  const expiring = createAuth({ users: db.userStore, ...stores, jwt: { secret: SECRET, accessTtlMs: 1000 } });
  db.users.set("j1", { ...db.users.get("j1")!, status: "active" });
  const e = await expiring.login({ email: "asha@mgpl.in", password: "banyan-roots-7" });
  issued.push(e.refreshToken!);
  await sleep(1100);
  ok((await expiring.authenticate(e.token)) === null && (await expiring.authenticate((await expiring.refresh({ refreshToken: e.refreshToken! })).accessToken)) !== null, "expired access token refused; refresh brings a working one");
  // device binding: the refresh token works only on the device that signed in
  const phone = { deviceId: "dev-phone-0001-abcdef", fingerprint: "fp-aaaaaaaaaaaa", clientSessionId: "tab-0001-xyz", info: { platform: "Android", screen: "412x915", "bad key": "x", note: "y".repeat(500) } };
  const f = await auth.login({ email: "asha@mgpl.in", password: "banyan-roots-7", device: phone as any });
  issued.push(f.refreshToken!);
  const stored = (await auth.sessionsOf("j1")).find((x) => x.id === auth.verifyAccessToken(f.token)?.sid);
  ok(stored?.device?.deviceId === phone.deviceId && stored.device.info?.platform === "Android" && !("bad key" in (stored.device.info ?? {})) && String(stored.device.info?.note).length === 200, "login stores the device signals on the session (cleaned, capped)");
  const f2 = await auth.refresh({ refreshToken: f.refreshToken!, device: { ...phone, fingerprint: "fp-bbbbbbbbbbbb" } });
  issued.push(f2.refreshToken);
  ok(!!f2.accessToken && db.auditLog.some((x) => x.action === "auth.fingerprint_changed"), "same device, new fingerprint: refresh works, change audited");
  ok((await code(auth.refresh({ refreshToken: f2.refreshToken, device: { deviceId: "dev-laptop-9999-zzzzzz" } }))) === "INVALID_TOKEN" && (await auth.authenticate(f2.accessToken)) === null && db.auditLog.some((x) => x.action === "auth.device_mismatch"), "refresh from another device: refused, session ended, audited");
  const g = await auth.login({ email: "asha@mgpl.in", password: "banyan-roots-7", device: phone });
  issued.push(g.refreshToken!);
  ok((await code(auth.refresh({ refreshToken: g.refreshToken! }))) === "INVALID_TOKEN", "refresh without the device id of a bound session: refused");
  const flagging = createAuth({ users: db.userStore, audit: db.audit, ...stores, deviceBinding: "flag", jwt: { secret: SECRET } });
  const h2 = await flagging.login({ email: "asha@mgpl.in", password: "banyan-roots-7", device: phone });
  issued.push(h2.refreshToken!);
  const h3 = await flagging.refresh({ refreshToken: h2.refreshToken!, device: { deviceId: "dev-laptop-9999-zzzzzz" } });
  issued.push(h3.refreshToken);
  ok(!!h3.accessToken, 'deviceBinding "flag": a refresh from another device works (and is audited)');
  ok(cleanDeviceSignals({ deviceId: "short", fingerprint: "<script>alert(1)</script>xx" }) === undefined, "malformed device ids are dropped");

  // TLS fingerprint (from the proxy, server side): stored hashed, a change is audited, never blocking
  const JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1", JA4b = "t13d1517h2_8daaf6152771_b1ff8ab2d16f";
  const t = await auth.login({ email: "asha@mgpl.in", password: "banyan-roots-7", device: phone, tlsFingerprint: JA4 });
  issued.push(t.refreshToken!, JA4, JA4b);
  const sidOf = (tok: string) => auth.verifyAccessToken(tok)?.sid;
  const tStored = (await auth.sessionsOf("j1")).find((x) => x.id === sidOf(t.token));
  ok(tStored?.tlsFingerprintHash === hashTlsFingerprint(JA4) && tStored?.tlsFingerprintHash !== JA4 && !JSON.stringify(tStored).includes(JA4), "login stores the TLS fingerprint as a hash only");
  const before = db.auditLog.length;
  const t2 = await auth.refresh({ refreshToken: t.refreshToken!, device: phone, tlsFingerprint: JA4 });
  ok(!db.auditLog.slice(before).some((x) => x.action === "auth.tls_fingerprint_changed"), "same TLS fingerprint: nothing audited");
  const t3 = await auth.refresh({ refreshToken: t2.refreshToken, device: phone, tlsFingerprint: JA4b });
  issued.push(t2.refreshToken, t3.refreshToken);
  const tlsAudit = db.auditLog.find((x) => x.action === "auth.tls_fingerprint_changed");
  ok(!!t3.accessToken && tlsAudit?.data?.from === hashTlsFingerprint(JA4) && tlsAudit?.data?.to === hashTlsFingerprint(JA4b), "new TLS fingerprint: refresh works, change audited (hashes)");
  ok((await auth.sessionsOf("j1")).find((x) => x.id === sidOf(t3.accessToken))?.tlsFingerprintHash === hashTlsFingerprint(JA4b), "the session records the latest TLS fingerprint hash");
  const t4 = await auth.refresh({ refreshToken: t3.refreshToken, device: phone });
  issued.push(t4.refreshToken);
  ok((await auth.sessionsOf("j1")).find((x) => x.id === sidOf(t4.accessToken))?.tlsFingerprintHash === hashTlsFingerprint(JA4b), "a refresh without a TLS fingerprint (TLS ended elsewhere) keeps the stored one");
  const u = await auth.login({ email: "asha@mgpl.in", password: "banyan-roots-7", device: phone });
  issued.push(u.refreshToken!);
  const u2 = await auth.refresh({ refreshToken: u.refreshToken!, device: phone, tlsFingerprint: JA4 });
  issued.push(u2.refreshToken);
  ok((await auth.sessionsOf("j1")).find((x) => x.id === sidOf(u2.accessToken))?.tlsFingerprintHash === hashTlsFingerprint(JA4), "a session without one is bound by the first refresh that has one");
  ok((await code(auth.refresh({ refreshToken: t4.refreshToken, device: { deviceId: "dev-laptop-9999-zzzzzz" }, tlsFingerprint: JA4b }))) === "INVALID_TOKEN" && db.auditLog.some((x) => x.action === "auth.device_mismatch" && x.data?.tls === "same"), "a device mismatch audit says whether the TLS fingerprint matched");
  ok(hashTlsFingerprint("has space x") === undefined && hashTlsFingerprint("short") === undefined && hashTlsFingerprint("x".repeat(257)) === undefined, "malformed TLS fingerprints are dropped");

  let threw = false;
  try { createAuth({ users: db.userStore, sessions: stores.sessions, jwt: { secret: "short" } }); } catch { threw = true; }
  ok(threw, "JWT mode refuses short secrets and a missing kv");
}

async function main() {
  const t0 = Date.now();
  await units();
  await flows("memory", { sessions: memorySessionStore(), kv: memoryKeyValueStore(), limiter: memoryRateLimiter({ limit: 100, windowMs: 60_000 }) });
  const redis = new RedisMock() as any;
  await flows("redis", { sessions: redisSessionStore(redis), kv: redisKeyValueStore(redis), limiter: redisRateLimiter(redis, { limit: 100, windowMs: 60_000 }) });
  await jwtFlows("memory", { sessions: memorySessionStore(), kv: memoryKeyValueStore(), limiter: memoryRateLimiter({ limit: 100, windowMs: 60_000 }) });
  await jwtFlows("redis", { sessions: redisSessionStore(redis), kv: redisKeyValueStore(redis), limiter: redisRateLimiter(redis, { limit: 100, windowMs: 60_000 }) });
  const dump = (await Promise.all(((await redis.keys("*")) as string[]).map(async (k) => `${k} ${(await redis.type(k)) === "string" ? await redis.get(k) : ""}`))).join("\n");
  ok(issued.length > 5 && issued.every((t) => !dump.includes(t)), "redis never holds a raw refresh token");
  const keys: string[] = await redis.keys("*");
  ok(keys.length > 0 && !keys.some((k) => /[A-Za-z0-9_-]{43}$/.test(k) && !k.includes("sess:") && !k.includes("kv:")), "redis holds token hashes only");
  redis.disconnect();
  console.log(`\n${passed} passed, ${failed} failed in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
