# US-018 Milestone 2: Test Audit (Phase 8, test-validate)

Branch `feature/US-018`, base commit 892aaeb, module `nexus-backend`. Docker was up (server 29.8.1). Frontend not touched, so npm was skipped. No PII.

## Run results

| Run | Command | Unit (surefire) | IT (failsafe) | Outcome |
|---|---|---|---|---|
| 1 (first full) | `./mvnw verify -Dscan=false -Ddevelocity.scan.disabled=true` | 1177 run, 0 fail, 1 skipped | 346 run, 1 failure, 2 errors | FAIL |
| 2 | targeted: `LastAdminLockoutIT`, `RoleAssignmentCacheIT` | n/a | 21 run, 0 fail | pass |
| 3 | targeted: `GrantSubsetIT` (with 7 new tests) | n/a | 22 run, 0 fail | pass |
| 4 (final full, JaCoCo gate on) | same as run 1 | 1177 run, 0 fail, 1 skipped | 353 run, 0 fail, 0 errors | BUILD SUCCESS (28:46) |

Run-4 log contains a `Surefire is going to kill self fork JVM` line (JVM exit after 30 s); it is a surefire warning, not a test failure, and the build succeeded.

## Known-risk results

- **(a) M14 HQL** (`JpaRoleRepository.findPermissionIdsByRoleAndTenantId`, roles LEFT JOIN RolePermission): held. The context started in every IT, so Spring Data accepted the query. Behaviour is now pinned against real MySQL by four new tests (see below), including the null-element row for an empty role.
- **(b) Blind IT fixtures:** nine of the ten patched classes passed first time. Two failures traced to fixture or test-selector issues, both fixed (below). No assertion was weakened and no status code loosened. No missing 403 occurred, so there is no production authz defect.
- **(c) Blockers:** `GrantSubsetIT`, `RbacSchemaMigrationIT` (14) and `LastAdminLockoutIT` 6d/6f all green. The one `LastAdminLockoutIT` failure was a different test (below).

## Failures and fixes (run 1)

1. `RoleAssignmentCacheIT.should_stillCompleteSuccessfully_when_redisIsUnreachableDuringAssign` and `...DuringRevoke` (2 errors). Root cause: fixture. The patched `seedActor` built the assigner role name from the scenario tag plus a 36-char UUID (69 chars), and `roles.name` is 64 chars wide, so MySQL raised `Data too long for column 'name'`. Fix: the assigner role uses a fixed short tag (`CACHE-ASSIGNER-<uuid>`, 51 chars). The actor still genuinely holds `user:role:assign` in the DB.
2. `LastAdminLockoutIT.should_neverEmitForShareOrForUpdate_when_capturingM7M8AndM9sSql` (1 failure). Root cause: test selector. A3/L-1 added M13 to the attach flow, and M13 also touches `user_roles`, so the "exactly one `user_roles` statement" lookup for M9 matched two statements. Fix: M9 is identified by also excluding `role_permissions`, and M13 is now additionally pinned as lock-free (strengthens MC-A; the assertion on M9 is unchanged).

## Gaps closed (all in `GrantSubsetIT`)

| Sev | Gap | Test added |
|---|---|---|
| HIGH | L-1 only covered at the endpoint gate (JWT lacks permission). The service-level DB re-check (stale JWT, caller lost the role) had unit coverage only | `should_return403PermissionAbsentAndWriteDenialRow_when_assignWithStaleTokenAfterCallerLosesRole`; `should_return403PermissionAbsentAndKeepAssignment_when_revokeWithStaleTokenAfterCallerLosesRole`; `should_return403PermissionAbsentAndAttachNothing_when_attachWithStaleTokenAfterCallerLosesRole` (assert 403, denial row with reason and operation for assign/revoke, no row for attach, metric +1, no state change) |
| HIGH | L-2 / M14 fail-closed shape was verified only through mocked adapter tests, never against the real LEFT JOIN query | `should_returnEmptyOptional_when_roleBelongsToAnotherTenant`; `should_returnEmptyOptional_when_roleDoesNotExist`; `should_returnPresentEmptySet_when_roleInTenantHasNoPermissions`; `should_returnEveryAttachedPermissionId_when_roleInTenantHasPermissions` |
| LOW | `LastAdminLockoutIT` did not pin M13 as non-locking on the attach path | extra `assertNoLockingClause` on M13 in the existing capture test |

Matrix coverage confirmed existing (no change needed): A1 per-endpoint pair tests and user:write-only denial (`RoleAssignmentSecurityIT`); A2 positive, negative, EC7 empty role, foreign-tenant M13 row; A4 non-admin, admin, two-role catalogue, dangerous-holder self-assign of TENANT_ADMIN; A3 positive, negative, duplicate-ordering (403 not 409); M-1 revoke-subset positive and negative; each with unit coverage in `RoleAssignmentServiceTest` / `RoleManagementServiceTest`.

Not covered by design and out of M2 scope: revoke-subset administrator requirement on admin-defining targets and role-subset on detach (M3), cross-tenant 404 (M8 B1), throttled-actor behaviour for the new reasons beyond the existing throttle tests.

## Files changed (uncommitted)

- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentCacheIT.java` (fixture role-name length)
- `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java` (M9 selector, M13 lock-free assertion)
- `nexus-backend/src/test/java/com/example/nexus/rbac/GrantSubsetIT.java` (7 new tests, `UserRoleAssignmentPort` injection, `revokeAllAssignmentsOf` helper)
- `docs/features/US-018/08-test-audit.md` (this report)

No production code changed.

## Load scenarios

Not applicable. The design's only hot-path load item for this feature is A9's epoch check (M7); M2's assign, revoke and attach are low-volume admin endpoints (task breakdown gap G-2), so no k6 or Gatling script was added.

## Flaky tests

None found. No `Thread.sleep`; the concurrency ITs (`LastAdminLockoutIT`, `RoleAssignmentIT`, `RoleAssignmentAuditIT`, `AdminEquivalentLockoutIT`) use a `CyclicBarrier` with 5 s bounds and assert on outcome sets, not timing. Watch items, not failures:
- `LastAdminLockoutIT.assertBootstrapTenantAdminBaselineIsZero` depends on other ITs cleaning up bootstrap-tenant rows (order and shared-state dependency).
- `RoleAssignmentCacheIT` Redis-unreachable cases rely on a closed local port; fast and deterministic here, but environment-dependent.
- Slow ITs: `GrantSubsetIT` 89 s and `LastAdminLockoutIT` about 40-60 s per class, dominated by Spring context and Testcontainers start-up rather than individual tests; the suite takes about 29 minutes end to end.
