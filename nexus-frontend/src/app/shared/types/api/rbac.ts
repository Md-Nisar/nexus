/**
 * Wire types of the RBAC API (US-019). Each shape mirrors a backend response record and is pinned
 * to the recorded responses in `contracts/api` by `api-contract.spec.ts`.
 */

export interface PageMetadata {
  readonly size: number;
  readonly number: number;
  readonly totalElements: number;
  readonly totalPages: number;
}

export interface PageLinks {
  readonly next: string | null;
  readonly prev: string | null;
}

export interface RoleResponse {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly isSystemRole: boolean;
  readonly createdAt: string;
  readonly memberCount: number;
  readonly permissionCount: number;
}

export interface RoleListResponse {
  readonly data: readonly RoleResponse[];
  readonly page: PageMetadata;
  readonly links: PageLinks;
}

export interface PermissionResponse {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly isSensitive: boolean;
}

export interface PermissionListResponse {
  readonly data: readonly PermissionResponse[];
}

export interface CallerRoleEntry {
  readonly roleId: string;
  readonly name: string;
}

export interface CallerAuthorizationResponse {
  readonly userId: string;
  readonly roles: readonly CallerRoleEntry[];
  readonly permissions: readonly string[];
  readonly isAdministrator: boolean;
}

export interface ReplaceRolePermissionsRequest {
  readonly permissionIds: readonly string[];
}

/** Why the backend refused an `RBAC_001`; see `AppError.reason`. */
export const RBAC_DENIAL_REASONS = [
  'GRANT_EXCEEDS_CALLER',
  'SELF_ASSIGNMENT',
  'ADMINISTRATOR_REQUIRED',
  'UNSPECIFIED',
] as const;

export type RbacDenialReason = (typeof RBAC_DENIAL_REASONS)[number];

export function isRbacDenialReason(value: unknown): value is RbacDenialReason {
  return RBAC_DENIAL_REASONS.some((reason) => reason === value);
}

/**
 * Error codes the RBAC endpoints return. `RBAC_012` is a 409: the role's classification changed
 * while the request waited. It is a plain `AppError`: no redirect and no automatic retry.
 */
export type RbacErrorCode =
  'RBAC_001' | 'RBAC_003' | 'RBAC_004' | 'RBAC_005' | 'RBAC_010' | 'RBAC_011' | 'RBAC_012';
