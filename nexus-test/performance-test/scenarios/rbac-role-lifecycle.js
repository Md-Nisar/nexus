import { sleep, fail } from 'k6';
import exec from 'k6/execution';
import { bearer, currentUserId, obtainAccessToken } from '../utils/auth.js';
import { checkResponse } from '../utils/checks.js';
import { del, get, postJson } from '../utils/http.js';

/**
 * RbacRoleLifecycle: an administrator managing one custom role end to end, exercising every RBAC
 * write endpoint.
 *
 * Each VU creates ONE role on its first iteration, then every iteration attaches a permission to
 * it, detaches it, assigns the role to the test user, lists the user's roles and revokes it again.
 * The permission is detached before the role is assigned, so the role is empty while held.
 *
 * Why one role per VU rather than one per iteration: roles cannot be deleted (there is no delete
 * endpoint) and a tenant holds at most nexus.rbac.max-roles-per-tenant (default 500), so a role per
 * iteration would hit that cap and turn every later create into a 409. Roles are named
 * `perf-<runId>-vu<n>`, so they are identifiable and unique across runs; a run leaves as many as
 * it had VUs. Reset the local database when the cap is near (nexus-scripts/reset-local-db.sh).
 * Assignments are soft-revoked (user_roles is append-only), so each iteration adds one row.
 *
 * Needs a user holding role:write, user:write and TENANT_ADMIN, which also satisfies the caller
 * checks on assignment; see "Test data" in the README. Expects the object returned by
 * setupRbacRoleLifecycle() as `data`. Access tokens expire after 900s, so this is not suitable for
 * a soak test until a token refresh is added.
 */

// Module scope is per VU in k6, so this survives across iterations without being shared.
let roleId;

const PERMISSION_NAME = 'audit:read';

export function setupRbacRoleLifecycle() {
  const accessToken = obtainAccessToken();
  const catalogue = get('/api/v1/permissions', bearer(accessToken));
  const permission =
    catalogue.status === 200 ? catalogue.json('data').find(isAuditRead) : undefined;
  if (!permission) {
    fail(`Permission ${PERMISSION_NAME} not found in GET /api/v1/permissions`);
  }
  return {
    accessToken,
    userId: currentUserId(accessToken),
    permissionId: permission.id,
    runId: Date.now().toString(36),
  };
}

export function rbacRoleLifecycle(data) {
  const params = bearer(data.accessToken);

  if (!roleId) {
    roleId = createRole(data, params);
    if (!roleId) {
      sleep(1);
      return;
    }
  }

  const rolePermissions = `/api/v1/roles/${roleId}/permissions`;
  const attach = postJson(
    rolePermissions,
    { permissionId: data.permissionId },
    tagged(params, '/api/v1/roles/{roleId}/permissions'),
  );
  checkResponse(attach, 201, { 'attached permission matches': (b) => b.id === data.permissionId });

  const detach = del(
    `${rolePermissions}/${data.permissionId}`,
    tagged(params, '/api/v1/roles/{roleId}/permissions/{permissionId}'),
  );
  checkResponse(detach, 204);

  const userRoles = `/api/v1/users/${data.userId}/roles`;
  const assign = postJson(userRoles, { roleId }, tagged(params, '/api/v1/users/{userId}/roles'));
  checkResponse(assign, 201, { 'assignment is for the role': (b) => b.roleId === roleId });

  const assigned = get(userRoles, tagged(params, '/api/v1/users/{userId}/roles'));
  checkResponse(assigned, 200, {
    'role is listed as assigned': (b) => b.data.some((a) => a.roleId === roleId),
  });

  const revoke = del(
    `${userRoles}/${roleId}`,
    tagged(params, '/api/v1/users/{userId}/roles/{roleId}'),
  );
  checkResponse(revoke, 204);
  sleep(1);
}

function createRole(data, params) {
  const name = `perf-${data.runId}-vu${exec.vu.idInTest}`;
  const res = postJson('/api/v1/roles', { name, description: 'k6 performance test role' }, params);
  checkResponse(res, 201, { 'role has an id': (b) => typeof b.id === 'string' });
  return res.status === 201 ? res.json('id') : undefined;
}

function isAuditRead(permission) {
  return permission.name === PERMISSION_NAME;
}

function tagged(params, name) {
  return { ...params, tags: { name } };
}
