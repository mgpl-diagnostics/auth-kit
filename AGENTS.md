# AGENTS.md — @mgpl-diagnostics/auth-kit

The backend's internal authentication API: passwords, sessions, login, reset, roles, permissions.
**No HTTP server, no GraphQL, no browser code.** The backend repo exposes these calls through its API.

## Map

```
src/password.ts  scrypt hash/verify/needsRehash, policy, randomToken, hashToken
src/jwt.ts       HS256 JWT sign/verify (node:crypto), secret rotation
src/rbac.ts      PERMISSIONS, SYSTEM_ROLES, can, branchesFor, permissionsOf, roleMap
src/stores.ts    storage interfaces (UserStore, OrgStore, RoleStore, AuditSink, SessionStore, KeyValueStore, RateLimiter)
src/memory.ts    in-process stores (tests, single server)
src/redis.ts     Redis stores ("/redis" entry): sessions, single-use values, sliding-window limiter
src/auth.ts      createAuth(): login, refresh (JWT mode), authenticate, context, require, logout, sessions, password change/reset
scripts/test.ts  110 checks; session, JWT and device-binding flows run on both memory and Redis (ioredis-mock) stores
```

## Rules

1. **Never store or log raw tokens.** Stores receive `hashToken(token)` only. A test asserts Redis holds no raw token.
2. **Login stays timing-safe.** An unknown email must still run one scrypt verification.
3. **Every request re-reads the user** (`authenticate`), so disabling and role changes apply at once. Do not cache users across requests.
4. Interfaces stay **structural and small**. db-kit's repositories must keep satisfying them (users, orgs, roles, audit).
5. Permissions the backend checks must exist in `PERMISSIONS` and be granted by the right `SYSTEM_ROLES`
   (db-kit's resolvers need `accounts:read|post|manage`, among others).
6. **JWT mode keeps rules 1 and 3.** Access JWTs carry the session id and every request still checks the
   session and re-reads the user; refresh tokens are opaque, single-use and stored as hashes. Never accept
   `alg` from the token (HS256 only), never sign with a secret under 32 characters.
   Device signals from clients are untrusted: always pass them through `cleanDeviceSignals`; a refresh
   from another `deviceId` ends the session unless `deviceBinding` says otherwise.
7. Error codes are a public contract (`AuthError.code`). Add new ones; never rename existing ones.

## Commands

```bash
npm run typecheck && npm test && npm run build
```

## Licence

All rights reserved (see LICENSE).
