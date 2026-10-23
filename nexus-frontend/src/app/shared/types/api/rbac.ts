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

/**
 * The unpaginated envelope of `GET /roles/{id}/permissions` only. `GET /permissions` is paged:
 * see {@link PermissionPageResponse}.
 */
export interface PermissionListResponse {
  readonly data: readonly PermissionResponse[];
}

/** Envelope of `GET /permissions`, ordered by the unique permission name. */
export interface PermissionPageResponse {
  readonly data: readonly PermissionResponse[];
  readonly page: PageMetadata;
  readonly links: PageLinks;
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

/**
 * One active role assignment: the 201 body of `POST /users/{userId}/roles` (AS-6, recorded from
 * the real serializer) and each element of {@link RoleAssignmentListResponse}. `assignedBy` is
 * `null` when the caller may not see who made the assignment.
 */
export interface RoleAssignmentResponse {
  readonly userId: string;
  readonly roleId: string;
  readonly roleName: string;
  readonly assignedAt: string;
  readonly assignedBy: string | null;
}

export interface RoleAssignmentListResponse {
  readonly data: readonly RoleAssignmentResponse[];
  readonly page: PageMetadata;
  readonly links: PageLinks;
}

export interface AssignRoleRequest {
  readonly roleId: string;
}

export interface CreateRoleRequest {
  readonly name: string;
  readonly description: string;
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
 * while the request waited, so the write was not applied. The HTTP interceptor never retries a
 * request; the console's write client re-sends `PUT` permissions and `POST` assign exactly once
 * on `RBAC_012`, and every other code surfaces as a plain `AppError` with no redirect.
 */
export type RbacErrorCode =
  | 'RBAC_001'
  | 'RBAC_002'
  | 'RBAC_003'
  | 'RBAC_004'
  | 'RBAC_005'
  | 'RBAC_006'
  | 'RBAC_007'
  | 'RBAC_008'
  | 'RBAC_009'
  | 'RBAC_010'
  | 'RBAC_011'
  | 'RBAC_012';
