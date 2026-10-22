# US-019 Rollback Plan

Companions: [deployment.md](deployment.md), [runbook.md](runbook.md), [monitoring.md](monitoring.md).

## 1. Fastest lever: feature flags (config only, no code revert)

| Flag set to `false` | Effect |
|---|---|
| `feature.nexus-us019-user-directory.enabled` | The directory routes (list, batch, get, lookup) and `GET /api/v1/users/me/authorization` become the generic 404 `RESOURCE_NOT_FOUND`. This is the kill switch for everything that returns email addresses. The controllers are conditional beans, so the change takes effect when each instance restarts |
| `feature.nexus-us015-rbac-role-management.enabled` | Removes `RoleController` and `PermissionController`: B3, B8 **and** the existing role and permission management (create, attach, detach, patch, delete) return 404 |
| `feature.nexus-us012-rbac-role-assignment.enabled` | Removes assign, revoke and list of user roles |

A flag is an availability lever, not a way back to the old rules. It stops the endpoints; it does not undo data, and the unflagged changes (below) stay live. The frontend has no flag: with the directory off the shell, guards and Not Found page still work; only the future console (US-020) would be affected.

**Unflagged, so only a code revert removes them:** B7 (429 `RBAC_011` for a throttled actor, `reason` on `RBAC_001`), the RC-56/RC-57 locking changes with 409 `RBAC_012` on assign, attach, revoke and role deletion, the 400/405/415 handlers, and the frontend release.

## 2. Code rollback

Revert the US-019 commits (or redeploy the previous backend image and frontend build).

- **Schema-safe.** V11 is data only and adds nothing the old code depends on being absent. Old code ignores the extra `permissions` row and the extra `role_permissions` rows.
- **Do not edit or delete V11** (ADR-0003, Flyway checksum). Reverting code that no longer contains V11 while the database has it applied makes Flyway fail with a missing-migration error unless validation is relaxed (the same constraint as US-018 V6 to V10). Prefer rolling forward with the flag off.
- **Order:** deploy the older code first; any data cleanup (section 3) after, never before.
- Tokens are compatible both ways: the new code adds no token claim or schema version.

## 3. Data: V11 is irreversible, and that is acceptable

- V11 inserted `user:directory:read` (`019f6839-1808-7000-8000-000000000009`) and attached it, through footer (a), to every live role that held all eight earlier permissions and, through footer (b), to every system `TENANT_ADMIN`. **There is no down migration, and the design (section 18) records that removing the permission would demote every administrator** (the footer has no inverse).
- Leaving it in place is safe. Nothing grants or uses the permission until the directory flag is on, and with the flag off no endpoint checks it. If a clean removal is nevertheless required it is a manual, approved production data change by the owner of the RBAC schema, followed by the cache flush in section 4. Re-run the zero-admin check afterwards.
- Rows written while the feature was live are real records and are **not** rolled back: `auth_events` (`USER_DIRECTORY_READ`, `ROLE_PERMISSION_GRANTED`/`ROLE_PERMISSION_REVOKED` with `operation=REPLACE`, `ROLE_ASSIGNMENT_DENIED`), `user_roles` (append-only) and the `role_permissions` rows a B8 replace wrote. A mistaken permission replace is corrected by another replace (a fresh `GET` for the `ETag`, then `PUT`), or by attach and detach, by an authorised caller.
- A role that gained `user:directory:read` by footer (a) keeps it. Review those roles (deployment.md section 4) if the permission is to be withdrawn.

## 4. Cache invalidation

- Turning a flag off or reverting code needs **no** flush: a cached permission set that includes `user:directory:read` is harmless with no endpoint checking it.
- If the permission data was removed (section 3), flush `{keyPrefix}:rbac:permset:*` and `{keyPrefix}:rbac:roleset:*` (`SCAN` then `UNLINK`). Existing access tokens keep the claim until they expire (up to 900 s).
- The directory and lookup throttles (`DIR_LOOKUP`, `DIR_ALL` buckets) expire with their windows (60 s); there is nothing to clear.
- Role changes through the API already evict the per-user permission cache after commit, independent of any rollback.
- The B8 `ETag` is computed from the permission set on each request; nothing is stored.

## 5. What a rollback re-opens

- **Code revert:** the attach and assign races closed by review R1-1 and R1-2 (a non-administrator-assigned holder on a role that becomes admin-defining, a demoted administrator still passing the self-assign and PII checks), the throttled-403 behaviour of B7, and 500 for malformed bodies. Keep the role-management flags off in shared environments while rolled back.
- **Flag off only:** nothing is re-opened; the controls that remain live are the locking and grant-subset rules.

## 6. Verification after rollback

1. `GET /actuator/health` is UP and `rbacZeroActiveAdmins` is green.
2. With the directory flag off, `GET /api/v1/users` answers 404 `RESOURCE_NOT_FOUND` for a caller with a valid token.
3. `nexus.identity.directory.requests` stops increasing.
4. After a code revert: `PUT /api/v1/roles/{roleId}/permissions` is gone (405 or 404), and `RBAC_011` / `RBAC_012` no longer appear in logs.
