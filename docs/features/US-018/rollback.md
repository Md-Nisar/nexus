# US-018 M2: Rollback Plan

**Scope:** Milestone 2 (A1 to A4, M-1, L-1, L-2, L-5). Companion: [deployment.md](deployment.md), [runbook.md](runbook.md).

## 1. Fastest lever: parent feature flags (config only, no code revert)

M2 has **no flag of its own**. The kill switches are the existing parent flags:

| Flag | Turning it `false` does |
|---|---|
| `feature.nexus-us012-rbac-role-assignment.enabled` | Removes `UserRoleController`: `POST`, `GET`, `DELETE /api/v1/users/{userId}/roles[/{roleId}]` return 404. No role can be assigned or revoked through the API |
| `feature.nexus-us015-rbac-role-management.enabled` | Removes `RoleController` and `PermissionController`: no role creation and no permission attach or detach |

Both are `false` by default outside `dev` and `test`, so in a default production configuration M2 is already dark.

**A flag flip is an availability lever, not a way back to the old authorization rules.** It stops the endpoints; it does not restore `user:write`-based assignment. Restart or redeploy the config change (or no restart if the flag is externalised).

## 2. Code rollback

Revert the M2 commits on `feature/US-018` (or the merge commit) and redeploy. The previous code gates assign and revoke on `user:write` and uses the name-based attach gate.

- **Schema-safe.** V6 is data only and adds nothing that old code depends on being absent. The old code ignores the extra `permissions` row and the extra `role_permissions` rows.
- **Do not edit or delete V6** (ADR-0003, Flyway checksum). Flyway validates applied migrations; reverting code that no longer contains V6 while the database has it applied makes Flyway fail with a missing-migration error unless validation is relaxed. Prefer rolling back the **application** only if V6 stays in the deployed artifact (for example a hotfix that restores the old controller gate but keeps the migration file), or, if the migration file must go, an explicit DBA decision to tolerate an applied-but-missing migration.
- **Order if both a code and a data cleanup are wanted:** deploy the older code first, then (optional) data cleanup in section 3. Never the reverse.

## 3. Data: V6 is effectively irreversible, and that is acceptable

- V6 inserted the `user:role:assign` permission and attached it to system `TENANT_ADMIN` roles and to every role that already carried the whole pre-migration catalogue. There is no down migration.
- Leaving the data in place is harmless to old code. If a clean removal is nevertheless required, it is a manual, approved production data change (delete the `role_permissions` rows for permission id `019f6839-1807-7000-8000-000000000008`, then the `permissions` row), and `nexus_app` cannot do it (it has `SELECT` only on `permissions`), so it needs the DBA or DDL account. Removing it while the new code is still deployed makes every assignment 403, because L-1 requires the permission in live holdings.
- `user_roles`, `auth_events`: rows written while M2 was live are real administrative actions and audit records. They are **not** rolled back. `user_roles` is append-only (`BEFORE DELETE` trigger, no `DELETE` grant). A specific mistaken assignment is corrected by the ordinary data-correction process, not by this rollback.
- `ROLE_ASSIGNMENT_DENIED` rows with reasons `GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT` and `PERMISSION_ABSENT` remain in `auth_events`. `event_type` and reason are strings, so old code reading them needs no change.

## 4. Cache invalidation

- Reverting code to `user:write`-based gating needs **no** cache flush: the old gate reads permissions that were present before V6.
- If you removed the `user:role:assign` data (section 3), flush `{keyPrefix}:rbac:permset:*` (SCAN then DEL) so cached permission sets that include it are rebuilt, and note that existing access tokens keep the claim until they expire.
- Role changes made through the API already evict the per-user permission cache after commit, independent of this rollback.

## 5. What a rollback re-opens

Rolling the code back removes the grant-subset bounds: a `user:write` holder can again assign roles allowed by the legacy gate (including to themselves, US-017 RES-13) and any `role:write` holder can attach non-dangerous permissions they do not hold. Keep the parent flags off in shared environments while rolled back.

## 6. Verification after rollback

1. `GET /actuator/health` is UP.
2. With the flags on in a test environment: an assigner holding `user:write` can assign; `nexus.rbac.permission_denied{reason="GRANT_EXCEEDS_CALLER"}` and `{reason="SELF_ASSIGNMENT"}` stop increasing (they no longer exist in the old code path).
3. No `RBAC_ENDPOINT_PERMISSION_NOT_HELD` WARN in the logs.

---

## 7. M7: permission token freshness (A9, A10)

**Code rollback.** Revert the M7 PR (or redeploy the M6 image). It is safe in a rolling fashion: M6 accepts schema versions 2 and 3, so tokens minted by M7 (v3, with `perm_epoch`) are still accepted by M6, which ignores the claim. Do **not** roll back past M6: older code rejects v3 tokens with 401 and logs every user out.

**Kill switch.** There is none. M7 has no flag. The levers short of a revert are configuration, and none disables the check:
- `fail-open-window` bounds how long a Redis outage is tolerated before 503, but cannot be set to switch the check off.
- A Redis outage already degrades to the pre-A9 token lifetime for up to 15 minutes.

**Data.** Nothing to undo. The epoch keys expire after `key-ttl-seconds` (960 s) and nothing else reads them. Replay queues are in memory and are lost on restart (RES-31).

**Cache invalidation.** After a rollback, M6 reads permission cache keys without the epoch suffix. The epoch-keyed entries written by M7 are never read again and expire within the cache TTL (900 s). To avoid serving a permission set that is stale against a role change made while M7 ran, delete `{keyPrefix}:rbac:permset:*` and `{keyPrefix}:rbac:roleset:*` (`SCAN` and `UNLINK`).

**What a rollback re-opens.** A revoked or detached user's token stays valid for its remaining lifetime (up to 15 minutes) plus the cache TTL (up to 15 minutes), and the refresh limits (T-013) and the Redis-auth startup assertion (T-014) are gone. Tell the security owner before rolling back during an incident that involves a revocation.

**Verification after rollback.** Login and refresh succeed, `token_rejected{reason=schema_version}` is 0, and no `perm_epoch` metrics are emitted.

