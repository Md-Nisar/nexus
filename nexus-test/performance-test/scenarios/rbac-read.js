import { sleep } from 'k6';
import { bearer } from '../utils/auth.js';
import { checkResponse } from '../utils/checks.js';
import { get } from '../utils/http.js';

/**
 * RbacRead: an administrator browsing the RBAC catalogue, read-only.
 *
 * Lists roles and permissions, opens the permissions of the first role returned (its id comes from
 * the response, nothing is hard-coded), and lists the test user's own role assignments. Needs a user
 * holding role:read and user:read; see "Test data" in the README. Expects `data.accessToken` and
 * `data.userId` from the test's setup() (see utils/auth.js). Access tokens expire after 900s, so
 * this is not suitable for a soak test until a token refresh is added.
 */
export function rbacRead(data) {
  const params = bearer(data.accessToken);
  const isList = (body) => Array.isArray(body.data);

  const roles = get('/api/v1/roles', params);
  checkResponse(roles, 200, { 'roles is a list': isList });

  const permissions = get('/api/v1/permissions', params);
  checkResponse(permissions, 200, { 'permissions is a list': isList });

  const firstRole = parseFirstRoleId(roles);
  if (firstRole) {
    const rolePermissions = get(`/api/v1/roles/${firstRole}/permissions`, {
      ...params,
      tags: { name: '/api/v1/roles/{roleId}/permissions' },
    });
    checkResponse(rolePermissions, 200, { 'role permissions is a list': isList });
  }

  const userRoles = get(`/api/v1/users/${data.userId}/roles`, {
    ...params,
    tags: { name: '/api/v1/users/{userId}/roles' },
  });
  checkResponse(userRoles, 200, { 'user roles is a list': isList });
  sleep(1);
}

function parseFirstRoleId(res) {
  try {
    return res.json('data.0.id');
  } catch {
    return undefined;
  }
}
