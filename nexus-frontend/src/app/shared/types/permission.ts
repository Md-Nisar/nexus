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
