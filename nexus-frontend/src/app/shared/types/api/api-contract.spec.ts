import callerAuthorization from '../../../../../../contracts/api/caller-authorization-response.json';
import permissionCatalogue from '../../../../../../contracts/api/permission-catalogue.json';
import permissionResponse from '../../../../../../contracts/api/permission-response.json';
import problemRbac001 from '../../../../../../contracts/api/problem-rbac-001.json';
import problemRbac012 from '../../../../../../contracts/api/problem-rbac-012.json';
import replaceRolePermissions from '../../../../../../contracts/api/replace-role-permissions-request.json';
import roleListResponse from '../../../../../../contracts/api/role-list-response.json';
import roleResponse from '../../../../../../contracts/api/role-response.json';
import userDirectoryEntry from '../../../../../../contracts/api/user-directory-entry.json';
import userDirectoryPage from '../../../../../../contracts/api/user-directory-page.json';
import userLookupRequest from '../../../../../../contracts/api/user-lookup-request.json';
import userLookupResponse from '../../../../../../contracts/api/user-lookup-response.json';
import type { AppError } from '../app-error';
import { isRbacDenialReason } from './rbac';
import type {
  CallerAuthorizationResponse,
  CallerRoleEntry,
  PageLinks,
  PageMetadata,
  PermissionListResponse,
  PermissionResponse,
  RbacDenialReason,
  RbacErrorCode,
  ReplaceRolePermissionsRequest,
  RoleListResponse,
  RoleResponse,
} from './rbac';
import type {
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

  it('should hold no real-looking email address', () => {
    expect(userDirectoryEntry.email).toMatch(/@example\.test$/);
    expect(userLookupRequest.email).toMatch(/@example\.test$/);
  });
});
