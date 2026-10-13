# auth-kit

**Authentication and permissions for the MGPL Diagnostics backend, as an internal API.**
There is no HTTP server here. Your backend (GraphQL resolvers, REST handlers, jobs) calls these functions.

![tests](https://img.shields.io/badge/checks-65-14264A) ![deps](https://img.shields.io/badge/runtime%20dependencies-0-E9A23B)

## What it does

| | |
| --- | --- |
| **Passwords** | scrypt (N=2¹⁵), salted, self-describing hashes; weaker hashes upgraded on the next login; NIST-style policy (length, common passwords, repeated characters, no email) |
| **Login** | rate-limited per IP and per email; timing-safe (an unknown email costs the same as a wrong password); same email in several organisations → `ORG_REQUIRED`; audited |
| **Sessions** | opaque tokens, stored only as SHA-256; idle timeout that slides with use plus an absolute maximum age; list devices, revoke one, log out everywhere |
| **Accounts** | disabling a user or changing roles applies on the very next request |
| **Passwords, again** | change (keeps this device, ends the others); reset (single-use, expiring token; ends every session); admin set |
| **Permissions** | `resource:action` with wildcards; roles per branch or organisation-wide; built-in lab roles plus each organisation's own |
| **Stores** | memory (tests, one server) or Redis (`/redis`, shared by all servers) |

## Use

```ts
import { createAuth, SYSTEM_ROLES } from "@mgpl-diagnostics/auth-kit";
import { redisKeyValueStore, redisRateLimiter, redisSessionStore } from "@mgpl-diagnostics/auth-kit/redis";

// db-kit's repositories satisfy the user / org / role / audit stores as they are
const auth = createAuth({
  users: db.repos.users,
  orgs: db.repos.orgs,
  roles: db.repos.roles,
  audit: db.repos.audit,
  sessions: redisSessionStore(redis),
  kv: redisKeyValueStore(redis),
  limiter: redisRateLimiter(redis, { limit: 10, windowMs: 15 * 60_000 }),
});

const { token, user } = await auth.login({ email, password, ip, userAgent });

// per request, e.g. in the GraphQL context
const { viewer, can, branchesFor } = await auth.context(bearerToken);
can("invoice:create", branchId);   // true / false
branchesFor("booking:read");        // "all" or ["branch-id", …]
```

When you create an organisation, seed the roles: `seedOrganization(repos, { …, roles: SYSTEM_ROLES })`
(db-kit). To create a user, call `auth.hashNewPassword(password, { email })`, which checks the policy
and then hashes.

## API

| Call | Returns / throws |
| --- | --- |
| `login({ email, password, orgCode?, ip?, userAgent? })` | `{ token, expiresAt, user }` · `INVALID_CREDENTIALS` `ACCOUNT_DISABLED` `INVITE_PENDING` `ORG_REQUIRED` `RATE_LIMITED` |
| `authenticate(token)` | `Viewer \| null` (slides the idle window) |
| `context(token)` | `{ viewer, can, branchesFor, permissions }` (anonymous when the token is missing or invalid) |
| `require(token, permission?, branchId?)` | `Viewer` · `UNAUTHENTICATED` `FORBIDDEN` |
| `logout(token)` · `logoutAll(userId, keepToken?)` | |
| `sessionsOf(userId)` · `revokeSession(userId, sessionId)` | devices; revoke one |
| `changePassword({ userId, currentPassword, newPassword, currentToken? })` | `INVALID_CREDENTIALS` `WEAK_PASSWORD` |
| `requestPasswordReset({ email, orgCode?, ip? })` | `{ token, expiresAt, user } \| null`. Deliver the token yourself; reply identically when it is null |
| `resetPassword({ token, newPassword })` | `INVALID_TOKEN` `WEAK_PASSWORD` |
| `setPassword(userId, newPassword, actorId?)` · `hashNewPassword(pw, user)` | admin tools |
| `invalidateRoles(orgId?)` | call after editing roles |

Also exported:
- `hashPassword`, `verifyPassword`, `needsRehash`, `assertPasswordPolicy`;
- `randomToken`, `hashToken`;
- `PERMISSIONS`, `SYSTEM_ROLES`;
- `can`, `branchesFor`, `permissionsOf`, `roleMap`.

Every failure is an `AuthError` with a stable `code`, an HTTP-style `statusCode`, and `details.retryAfterMs`
where it applies.

## Built-in roles

`owner` (everything) · `admin` · `branch_manager` · `front_desk` · `phlebotomist` · `technician` ·
`pathologist` · `accountant` (including the books: `accounts:*`) · `doctor` (referring; read only).

## Not here (by design)

- **HTTP / GraphQL endpoints.** The backend exposes `login`, `logout`, `me` and the rest as GraphQL
  mutations and queries, and calls this API.
- **Browser code.** A client package comes later.

## Licence

All rights reserved. See [LICENSE](LICENSE).
