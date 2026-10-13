/**
 * Role-based access control. Permissions are "resource:action"; "*" works in either part
 * ("invoice:*", "*:read", "*:*"). A user holds roles per branch (branchId) or organisation-wide (null).
 */

export interface RoleAssignment {
  role: string;
  branchId: string | null;
}

export const PERMISSIONS = [
  "org:read", "org:update",
  "branch:read", "branch:create", "branch:update",
  "user:read", "user:create", "user:update", "user:disable",
  "role:read", "role:manage",
  "patient:read", "patient:create", "patient:update", "patient:delete",
  "doctor:read", "doctor:manage",
  "booking:read", "booking:create", "booking:update", "booking:cancel",
  "sample:read", "sample:collect", "sample:receive", "sample:reject",
  "report:read", "report:enter", "report:verify", "report:release", "report:amend",
  "invoice:read", "invoice:create", "invoice:discount", "invoice:cancel",
  "payment:read", "payment:create", "payment:refund",
  "accounts:read", "accounts:post", "accounts:manage",
  "audit:read",
  "settings:manage",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

export interface RoleDefinition {
  key: string;
  name: string;
  permissions: string[];
}

/** Built-in roles. Seed them per organisation (db-kit: seedOrganization(repos, { …, roles: SYSTEM_ROLES })). */
export const SYSTEM_ROLES: RoleDefinition[] = [
  { key: "owner", name: "Owner", permissions: ["*:*"] },
  {
    key: "admin",
    name: "Administrator",
    permissions: ["org:read", "branch:*", "user:*", "role:*", "patient:*", "doctor:*", "booking:*", "sample:*", "report:*", "invoice:*", "payment:*", "accounts:*", "audit:read", "settings:manage"],
  },
  {
    key: "branch_manager",
    name: "Branch manager",
    permissions: ["org:read", "branch:read", "user:read", "patient:*", "doctor:*", "booking:*", "sample:*", "report:read", "report:release", "invoice:*", "payment:*", "accounts:read", "audit:read"],
  },
  {
    key: "front_desk",
    name: "Front desk",
    permissions: ["org:read", "branch:read", "patient:read", "patient:create", "patient:update", "doctor:read", "booking:read", "booking:create", "booking:update", "sample:read", "report:read", "invoice:read", "invoice:create", "payment:read", "payment:create"],
  },
  { key: "phlebotomist", name: "Phlebotomist", permissions: ["branch:read", "patient:read", "booking:read", "sample:read", "sample:collect"] },
  { key: "technician", name: "Lab technician", permissions: ["branch:read", "patient:read", "booking:read", "sample:*", "report:read", "report:enter"] },
  { key: "pathologist", name: "Pathologist", permissions: ["branch:read", "patient:read", "booking:read", "sample:read", "report:*"] },
  { key: "accountant", name: "Accountant", permissions: ["org:read", "branch:read", "patient:read", "invoice:read", "invoice:cancel", "payment:*", "accounts:*", "audit:read"] },
  { key: "doctor", name: "Referring doctor", permissions: ["patient:read", "report:read"] },
];

/** role key → permissions */
export type RoleMap = Map<string, readonly string[]>;

/** System roles, overridden / extended by the organisation's own roles. */
export function roleMap(orgRoles: Pick<RoleDefinition, "key" | "permissions">[] = []): RoleMap {
  const m: RoleMap = new Map();
  for (const r of SYSTEM_ROLES) m.set(r.key, r.permissions);
  for (const r of orgRoles) m.set(r.key, r.permissions);
  return m;
}

export function permissionMatches(granted: string, wanted: string): boolean {
  if (granted === wanted || granted === "*:*" || granted === "*") return true;
  const [gr, ga] = granted.split(":");
  const [wr, wa] = wanted.split(":");
  return (gr === "*" || gr === wr) && (ga === "*" || ga === wa);
}

/**
 * Does someone holding `assignments` have `permission`? With `branchId`, only roles held in that
 * branch or organisation-wide count; without it, a role in any branch counts.
 */
export function can(assignments: readonly RoleAssignment[], permission: string, roles: RoleMap, branchId?: string | null): boolean {
  for (const a of assignments) {
    if (branchId && a.branchId && a.branchId !== branchId) continue;
    if (roles.get(a.role)?.some((g) => permissionMatches(g, permission))) return true;
  }
  return false;
}

/** Where `permission` applies: "all" (an organisation-wide role grants it) or the list of branch ids. */
export function branchesFor(assignments: readonly RoleAssignment[], permission: string, roles: RoleMap): "all" | string[] {
  const out = new Set<string>();
  for (const a of assignments) {
    if (!roles.get(a.role)?.some((g) => permissionMatches(g, permission))) continue;
    if (!a.branchId) return "all";
    out.add(a.branchId);
  }
  return [...out];
}

/** Concrete permissions (wildcards expanded against PERMISSIONS) — e.g. to show or hide UI. */
export function permissionsOf(assignments: readonly RoleAssignment[], roles: RoleMap, branchId?: string | null): Permission[] {
  return PERMISSIONS.filter((p) => can(assignments, p, roles, branchId));
}
