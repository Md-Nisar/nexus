/**
 * The RBAC permission catalogue as a closed type (US-018 B5, FR-B5.b).
 *
 * Mirrors the backend's `common.security.Permissions` class and the `permissions` table
 * (V5 seeds seven, V6 and V11 add one each). Keeping the two lists in step is manual:
 * adding a catalogue row means adding it here, to {@link PERMISSIONS}, and to
 * `Permissions.java`. The backend's `PermissionsCatalogueTest` / `PermissionsCatalogueIT` and
 * `app.routes.spec.ts` fail on their respective sides when a referenced name is unknown.
 *
 * @security UX only. Typing a permission name does not authorize anything; the server's
 * `@RequiresPermission` is the sole enforcement point.
 */
export type Permission =
  | 'tenant:read'
  | 'tenant:write'
  | 'user:read'
  | 'user:write'
  | 'role:read'
  | 'role:write'
  | 'audit:read'
  | 'user:role:assign'
  | 'user:directory:read';

/** Every catalogue entry, for tests and tooling that must enumerate the catalogue. */
export const PERMISSIONS: readonly Permission[] = [
  'tenant:read',
  'tenant:write',
  'user:read',
  'user:write',
  'role:read',
  'role:write',
  'audit:read',
  'user:role:assign',
  'user:directory:read',
];

/** The resource a permission belongs to: the segment before its first `:`. */
export type PermissionResource = 'tenant' | 'user' | 'role' | 'audit';

/**
 * Human-readable label per permission. Typed as a `Record` so a new union member without a
 * label is a compile error. The copy is a placeholder (the backend descriptions) until D3.
 */
export const PERMISSION_LABELS: Readonly<Record<Permission, string>> = {
  'tenant:read': 'Read tenant configuration and metadata',
  'tenant:write': 'Create and modify tenant configuration',
  'user:read': 'Read user accounts and profiles',
  'user:write': 'Create and modify user accounts',
  'role:read': 'Read roles and their permission assignments',
  'role:write': 'Create roles and manage role-permission assignments',
  'audit:read': 'Read the authentication and audit event trail',
  'user:role:assign': 'Assign and revoke roles for users in the tenant',
  'user:directory:read': 'Read the tenant user directory, including email addresses',
};

/** Heading shown for each permission group. */
export const PERMISSION_GROUP_LABELS: Readonly<Record<PermissionResource, string>> = {
  tenant: 'Tenant',
  user: 'Users',
  role: 'Roles',
  audit: 'Audit',
};

/** Returns the resource group of a permission (`user:role:assign` groups under `user`). */
export function permissionResource(permission: Permission): PermissionResource {
  return permission.slice(0, permission.indexOf(':')) as PermissionResource;
}
