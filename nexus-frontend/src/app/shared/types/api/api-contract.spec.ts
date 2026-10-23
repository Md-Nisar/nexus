import assignRoleRequest from '../../../../../../contracts/api/assign-role-request.json';
import callerAuthorization from '../../../../../../contracts/api/caller-authorization-response.json';
import createRoleRequest from '../../../../../../contracts/api/create-role-request.json';
import permissionCatalogue from '../../../../../../contracts/api/permission-catalogue.json';
import permissionPageResponse from '../../../../../../contracts/api/permission-page-response.json';
import permissionResponse from '../../../../../../contracts/api/permission-response.json';
import problemPreconditionFailed from '../../../../../../contracts/api/problem-precondition-failed.json';
import problemPreconditionRequired from '../../../../../../contracts/api/problem-precondition-required.json';
import problemRbac001 from '../../../../../../contracts/api/problem-rbac-001.json';
import problemRbac002 from '../../../../../../contracts/api/problem-rbac-002.json';
import problemRbac006 from '../../../../../../contracts/api/problem-rbac-006.json';
import problemRbac008 from '../../../../../../contracts/api/problem-rbac-008.json';
import problemRbac011 from '../../../../../../contracts/api/problem-rbac-011.json';
import problemRbac012 from '../../../../../../contracts/api/problem-rbac-012.json';
import problemResourceNotFound from '../../../../../../contracts/api/problem-resource-not-found.json';
import problemUserDir001 from '../../../../../../contracts/api/problem-user-dir-001.json';
import problemValidationFailed from '../../../../../../contracts/api/problem-validation-failed.json';
import replaceRolePermissions from '../../../../../../contracts/api/replace-role-permissions-request.json';
import roleAssignmentList from '../../../../../../contracts/api/role-assignment-list-response.json';
import roleAssignment from '../../../../../../contracts/api/role-assignment-response.json';
import roleListResponse from '../../../../../../contracts/api/role-list-response.json';
import roleResponse from '../../../../../../contracts/api/role-response.json';
import userDirectoryEntry from '../../../../../../contracts/api/user-directory-entry.json';
import userDirectoryPage from '../../../../../../contracts/api/user-directory-page.json';
import userLookupRequest from '../../../../../../contracts/api/user-lookup-request.json';
import userLookupResponse from '../../../../../../contracts/api/user-lookup-response.json';
import type { AppError } from '../app-error';
import { isRbacDenialReason } from './rbac';
import type {
  AssignRoleRequest,
  CallerAuthorizationResponse,
  CallerRoleEntry,
  CreateRoleRequest,
  PageLinks,
  PageMetadata,
  PermissionListResponse,
  PermissionPageResponse,
  PermissionResponse,
  RbacDenialReason,
  RbacErrorCode,
  ReplaceRolePermissionsRequest,
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
  RoleListResponse,
  RoleResponse,
} from './rbac';
import type {
  DirectoryErrorCode,
  UserDirectoryEntry,
  UserDirectoryPage,
  UserLookupRequest,
  UserLookupResponse,
} from './user-directory';

/**
 * Each key list is declared `satisfies Record<keyof T, true>`, so a field added to or removed
 * from a DTO type fails compilation until the list follows; the fixtures recorded by the backend's
 * `ApiContractFixturesTest` then have to carry exactly those keys.
 */
const keysOf = (value: object): string[] => Object.keys(value).sort();
const expected = (keys: Record<string, true>): string[] => Object.keys(keys).sort();

const pageMetadata = {
  size: true,
  number: true,
  totalElements: true,
  totalPages: true,
} as const satisfies Record<keyof PageMetadata, true>;
const pageLinks = { next: true, prev: true } as const satisfies Record<keyof PageLinks, true>;
const roleKeys = {
  id: true,
  name: true,
  description: true,
  isSystemRole: true,
  createdAt: true,
  memberCount: true,
  permissionCount: true,
} as const satisfies Record<keyof RoleResponse, true>;
const permissionKeys = {
  id: true,
  name: true,
  description: true,
  isSensitive: true,
} as const satisfies Record<keyof PermissionResponse, true>;
const entryKeys = {
  userId: true,
  email: true,
  status: true,
  emailVerified: true,
  createdAt: true,
} as const satisfies Record<keyof UserDirectoryEntry, true>;

const assignmentKeys = {
  userId: true,
  roleId: true,
  roleName: true,
  assignedAt: true,
  assignedBy: true,
} as const satisfies Record<keyof RoleAssignmentResponse, true>;
const problemKeys = ['code', 'detail', 'status', 'title', 'traceId'];

describe('API contract fixtures', () => {
  it('should match RoleResponse', () => {
    expect(keysOf(roleResponse)).toEqual(expected(roleKeys));
  });

  it('should match RoleListResponse, its page and its links', () => {
    const keys = { data: true, page: true, links: true } as const satisfies Record<
      keyof RoleListResponse,
      true
    >;
    expect(keysOf(roleListResponse)).toEqual(expected(keys));
    expect(keysOf(roleListResponse.page)).toEqual(expected(pageMetadata));
    expect(keysOf(roleListResponse.links)).toEqual(expected(pageLinks));
    expect(keysOf(roleListResponse.data[0])).toEqual(expected(roleKeys));
  });

  it('should match PermissionResponse and the permission catalogue', () => {
    const keys = { data: true } as const satisfies Record<keyof PermissionListResponse, true>;
    expect(keysOf(permissionResponse)).toEqual(expected(permissionKeys));
    expect(keysOf(permissionCatalogue)).toEqual(expected(keys));
    for (const permission of permissionCatalogue.data) {
      expect(keysOf(permission)).toEqual(expected(permissionKeys));
    }
  });

  it('should match CallerAuthorizationResponse and its role entries', () => {
    const keys = {
      userId: true,
      roles: true,
      permissions: true,
      isAdministrator: true,
    } as const satisfies Record<keyof CallerAuthorizationResponse, true>;
    const roleEntry = { roleId: true, name: true } as const satisfies Record<
      keyof CallerRoleEntry,
      true
    >;
    expect(keysOf(callerAuthorization)).toEqual(expected(keys));
    expect(keysOf(callerAuthorization.roles[0])).toEqual(expected(roleEntry));
  });

  it('should match ReplaceRolePermissionsRequest', () => {
    const keys = { permissionIds: true } as const satisfies Record<
      keyof ReplaceRolePermissionsRequest,
      true
    >;
    expect(keysOf(replaceRolePermissions)).toEqual(expected(keys));
  });

  it('should match UserDirectoryEntry, UserDirectoryPage and the lookup shapes', () => {
    const pageKeys = { data: true, page: true, links: true } as const satisfies Record<
      keyof UserDirectoryPage,
      true
    >;
    const requestKeys = { email: true } as const satisfies Record<keyof UserLookupRequest, true>;
    const responseKeys = { data: true } as const satisfies Record<keyof UserLookupResponse, true>;
    expect(keysOf(userDirectoryEntry)).toEqual(expected(entryKeys));
    expect(keysOf(userDirectoryPage)).toEqual(expected(pageKeys));
    expect(keysOf(userDirectoryPage.page)).toEqual(expected(pageMetadata));
    expect(keysOf(userDirectoryPage.links)).toEqual(expected(pageLinks));
    expect(keysOf(userDirectoryPage.data[0])).toEqual(expected(entryKeys));
    expect(keysOf(userLookupRequest)).toEqual(expected(requestKeys));
    expect(keysOf(userLookupResponse)).toEqual(expected(responseKeys));
    expect(keysOf(userLookupResponse.data[0])).toEqual(expected(entryKeys));
  });

  it('should record RBAC_001 with a reason and RBAC_012 as typed error codes', () => {
    const code001: RbacErrorCode = problemRbac001.code as RbacErrorCode;
    const code012: RbacErrorCode = problemRbac012.code as RbacErrorCode;
    expect(isRbacDenialReason(problemRbac001.reason)).toBe(true);
    const reason: RbacDenialReason = problemRbac001.reason as RbacDenialReason;
    const appError: AppError = { code: problemRbac001.code, message: 'x', reason };
    expect([code001, code012, appError.reason]).toEqual([
      'RBAC_001',
      'RBAC_012',
      'GRANT_EXCEEDS_CALLER',
    ]);
    expect(isRbacDenialReason('NOT_A_REASON')).toBe(false);
    expect(isRbacDenialReason(7)).toBe(false);
    expect(problemRbac012.status).toBe(409);
    expect('reason' in problemRbac012).toBe(false);
  });

  it('should match PermissionPageResponse, its page and its links', () => {
    const keys = { data: true, page: true, links: true } as const satisfies Record<
      keyof PermissionPageResponse,
      true
    >;
    expect(keysOf(permissionPageResponse)).toEqual(expected(keys));
    expect(keysOf(permissionPageResponse.page)).toEqual(expected(pageMetadata));
    expect(keysOf(permissionPageResponse.links)).toEqual(expected(pageLinks));
    for (const permission of permissionPageResponse.data) {
      expect(keysOf(permission)).toEqual(expected(permissionKeys));
    }
  });

  it('should match RoleAssignmentResponse, which is also the assign 201 body (AS-6)', () => {
    const body: RoleAssignmentResponse = roleAssignment;
    expect(keysOf(body)).toEqual(expected(assignmentKeys));
    expect(body.assignedBy).toEqual(expect.any(String));
  });

  it('should match RoleAssignmentListResponse with assignedBy both set and null', () => {
    const keys = { data: true, page: true, links: true } as const satisfies Record<
      keyof RoleAssignmentListResponse,
      true
    >;
    expect(keysOf(roleAssignmentList)).toEqual(expected(keys));
    expect(keysOf(roleAssignmentList.page)).toEqual(expected(pageMetadata));
    expect(keysOf(roleAssignmentList.links)).toEqual(expected(pageLinks));
    for (const item of roleAssignmentList.data) {
      expect(keysOf(item)).toEqual(expected(assignmentKeys));
    }
    expect(roleAssignmentList.data.map((item) => item.assignedBy === null)).toEqual([false, true]);
  });

  it('should match AssignRoleRequest and CreateRoleRequest', () => {
    const assignKeys = { roleId: true } as const satisfies Record<keyof AssignRoleRequest, true>;
    const createKeys = { name: true, description: true } as const satisfies Record<
      keyof CreateRoleRequest,
      true
    >;
    expect(keysOf(assignRoleRequest)).toEqual(expected(assignKeys));
    expect(keysOf(createRoleRequest)).toEqual(expected(createKeys));
  });

  it('should record every handled error code with the problem fields and its status', () => {
    const recorded: readonly (readonly [{ code: string; status: number }, string, number])[] = [
      [problemRbac002, 'RBAC_002', 409],
      [problemRbac006, 'RBAC_006', 409],
      [problemRbac008, 'RBAC_008', 409],
      [problemRbac011, 'RBAC_011', 429],
      [problemPreconditionFailed, 'PRECONDITION_FAILED', 412],
      [problemPreconditionRequired, 'PRECONDITION_REQUIRED', 428],
      [problemUserDir001, 'USER_DIR_001', 429],
      [problemResourceNotFound, 'RESOURCE_NOT_FOUND', 404],
    ];
    for (const [fixture, code, status] of recorded) {
      expect(keysOf(fixture)).toEqual(problemKeys);
      expect(fixture.code).toBe(code);
      expect(fixture.status).toBe(status);
    }
    const rbacCodes: RbacErrorCode[] = [
      problemRbac002.code,
      problemRbac006.code,
      problemRbac008.code,
      problemRbac011.code,
    ] as RbacErrorCode[];
    const directoryCode: DirectoryErrorCode = problemUserDir001.code as DirectoryErrorCode;
    expect([...rbacCodes, directoryCode]).toEqual([
      'RBAC_002',
      'RBAC_006',
      'RBAC_008',
      'RBAC_011',
      'USER_DIR_001',
    ]);
  });

  it('should record VALIDATION_FAILED with details of field and message', () => {
    expect(keysOf(problemValidationFailed)).toEqual([...problemKeys, 'details'].sort());
    expect(problemValidationFailed.status).toBe(400);
    expect(problemValidationFailed.details.length).toBeGreaterThan(0);
    for (const detail of problemValidationFailed.details) {
      expect(keysOf(detail)).toEqual(['field', 'message']);
    }
  });

  it('should type RbacErrorCode as exactly RBAC_001 to RBAC_012', () => {
    const all = [
      'RBAC_001',
      'RBAC_002',
      'RBAC_003',
      'RBAC_004',
      'RBAC_005',
      'RBAC_006',
      'RBAC_007',
      'RBAC_008',
      'RBAC_009',
      'RBAC_010',
      'RBAC_011',
      'RBAC_012',
    ] as const satisfies readonly RbacErrorCode[];
    type Missing = Exclude<RbacErrorCode, (typeof all)[number]>;
    const none: Missing[] = [];
    expect(all).toHaveLength(12);
    expect(none).toEqual([]);
  });

  it('should hold no real-looking email address in any recorded fixture', () => {
    expect(userDirectoryEntry.email).toMatch(/@example\.test$/);
    expect(userLookupRequest.email).toMatch(/@example\.test$/);
    const everyFixture: readonly unknown[] = [
      assignRoleRequest,
      createRoleRequest,
      permissionPageResponse,
      problemPreconditionFailed,
      problemPreconditionRequired,
      problemRbac002,
      problemRbac006,
      problemRbac008,
      problemRbac011,
      problemResourceNotFound,
      problemUserDir001,
      problemValidationFailed,
      roleAssignment,
      roleAssignmentList,
    ];
    for (const fixture of everyFixture) {
      expect(JSON.stringify(fixture)).not.toContain('@');
    }
  });
});
