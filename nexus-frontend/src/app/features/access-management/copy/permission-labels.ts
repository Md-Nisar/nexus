import type { Permission, PermissionResource } from '../../../shared/types/permission';

/**
 * Human-readable label per permission (US-020 design §9.4). Typed as a `Record` so a new union
 * member without a label is a compile error. **PROVISIONAL:** the copy is the backend descriptions
 * until UX supplies the D3 labels. A code the backend returns that is not in the union has no
 * label here; the catalogue page shows it as "Unlabelled" (see {@link permissionLabel}).
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

/** The fixed order the groups are shown in. */
export const PERMISSION_GROUP_ORDER: readonly PermissionResource[] = [
  'tenant',
  'user',
  'role',
  'audit',
];

/**
 * The label of a permission code, or `undefined` when the code is not in the {@link Permission}
 * union. Own properties only, so a code such as `constructor` is never "labelled".
 */
export function permissionLabel(code: string): string | undefined {
  return Object.hasOwn(PERMISSION_LABELS, code) ? PERMISSION_LABELS[code as Permission] : undefined;
}
