# US-018 M3: threat-model re-pass (preparation)

Status: prepared by the implementer; the Security sign-off is pending. Integration tests named below were written and compile but **were not run** (no Docker). Where a row says "unit", the unit test ran green in `verify -DskipITs` (2005 run, 0 failures).

Paths: services in `nexus-backend/src/main/java/com/example/nexus/rbac/application/` (`RoleAssignmentService` = RAS, `RoleManagementService` = RMS); tests under `src/test/java/com/example/nexus/rbac/`.

## 1. Ledger rows (design 5.1)

| Row | Change | Code | Proving test |
|---|---|---|---|
| 1 | Assign gates removed; A2 + A4; administrator from M11 rows on the lock path | RAS `assign`, `acquireSetLock`, `requireGrantWithinCallerHoldings` | Unit `RoleAssignmentServiceTest` (A4 from lock rows with M13 stubbed to disagree, A2 union); IT `RoleAssignmentSecurityIT`, `GrantSubsetIT` |
| 2 | Revoke-subset + administrator requirement from M11 rows | RAS `revoke`, `requireAdministratorFromSetLock` | Unit revoke-subset and ordering tests; IT `RoleRevocationSymmetryIT`, `LastAdminLockoutIT.should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin` (kept verbatim) |
| 3 | Last-admin lockout over admin-defining holders | RAS `wouldLeaveTenantWithoutAdministrator` | Unit (MC-D, one user two roles counted once, determinism); IT `LastAdminLockoutIT`, `AdminEquivalentLockoutIT` |
| 4 | Set lock re-scoped, ascending unsigned-byte, single statement, only if target admin-defining | RAS `buildAscendingLockSet`, `acquireSetLock` | Unit (MC-E unsigned sort, benign target takes no lock); IT harness C incl. RC-25.3 |
| 5 | H-1 filter removed | `JpaUserRoleRepository` M11 | Folded into rows 3/4 |
| 6 | M10 replaced by M10' | `JpaRoleRepository.findRolePermissionIdsByTenantRoles` | MC-A IT (no lock clause); `RbacRepositoryRoundTripIT` |
| 7 | Independent per-role capture before INSERT, ERROR + counter | RAS `captureIndependentAdministratorCheck`, `JpaUserRoleRepository.findHeldAdminDefiningRoleIds` (M16) | Unit (disagree, agree, before INSERT, not on denied/duplicate/non-self); IT `RoleRevocationSymmetryIT` delta tests; MC-A for M16 |
| 8 | M12 deleted | `UserRoleAssignmentPort` | Compile-time; source-scan test |
| 9 | D23 / `privileged_role_change_*` removed; `admin_role_assigned{selfTarget}` | RAS | Unit (retired-meter absence, admin_role_assigned) |
| 10 | Lock-hold timer, lock-set-size summary kept | RAS | Unit timers |
| 11 | Attach name gate removed; A3 | RMS `requireCallerHoldsPermission` | Unit; IT `GrantSubsetIT`, `RoleManagementAdminGateIT` |
| 12 | Detach role-subset (+ administrator through another role) | RMS `requireRoleSubset` | Unit matrix; IT `RoleManagementAdminGateIT`, `RolePermissionSecurityIT` |
| 13 | Provenance signal on every attach | RMS `readAttachSnapshot`, `emitAttachSignals` | Unit; IT `AttachEscalationSignalIT` |
| 14 | `RBAC_ROLE_BECAME_ADMIN_DEFINING` + narrow 409 `RBAC_010` | RMS `attachWouldMakeRoleAdminDefining`, `requireNoNonAdministratorAssignedHolder`; `AttachProvenanceConflictException` | Unit incl. RBAC_005 for an already admin-defining role; IT `AttachEscalationSignalIT` |
| 15 | Indicator re-scoped | `RbacZeroActiveAdminsHealthIndicator`, `ZeroAdminTenantReader`, `JpaUserRoleRepository` | Unit; IT `RbacZeroActiveAdminsHealthIndicatorIT`, `AdminEquivalenceSqlJavaEquivalenceIT` (MC-I) |
| 16 | `assignedBy` redaction for non-administrators | RAS `listActive` | Unit; IT `RoleAssignmentSecurityIT` (union-holder redaction) |
| 17 | Predicates deleted | files removed | Source-scan test `rbac_application_must_not_reference_the_retired_authorization_machinery` |
| 18 | ArchUnit rules replaced | `HexagonalArchitectureTest` | Same test |
| 19 | Detach to zero administrators | row 12 + row 15 | Unit and IT union-holder detach 403; RES-28 race accepted |

## 2. Retired tests and their replacements

| Retired | Replacement |
|---|---|
| Name/ANY/ALL gate tests in `RoleAssignmentServiceTest` | A2/A4/revoke-subset unit blocks (rows 1, 2) |
| MC-G / canary tests (M12) | `captureIndependentAdministratorCheck` unit tests; `HeldPermissionPartitionIT` (MC-H') |
| D23 and `privileged_role_change_*` tests | `admin_role_assigned` and retired-meter-absence unit tests |
| `resolveAdminEquivalentRoles` tests | `RbacAdministratorsTest` (`adminDefiningRoleIds`), lock-set unit tests |
| `RbacDangerousPermissionsTest`, `RbacAdminEquivalenceTest`, `RolePermissionNameTest`, `AdminEquivalenceEquivalenceIT` | `RbacAdministratorsTest`; `AdminEquivalenceSqlJavaEquivalenceIT` (MC-I) |
| AC11/D13 tests in `RoleManagementServiceTest` | A3, role-subset and RBAC_010 unit blocks |
| Old Q11 concurrent-revocation IT | RES-27 characterization in `RoleManagementAdminGateIT` |
| M5b parts of MC-C/MC-5 IT | `should_pinKeyToFkUserRolesRole_acrossInListCardinalities_forM11_MCC` |
| M7/M8/M9 MC-A IT | `should_neverEmitForShareOrForUpdate_when_capturingEveryAttachRead_MCA`, M16 MC-A test |
| Case-variant MC-I sub-proof | none needed: names no longer enter the definition |
| Canary ITs | `RoleRevocationSymmetryIT` disagreement delta test; `RoleAssignmentSecurityIT` custom-admin self-assign |

## 3. Gaps found, stated honestly

1. RES-27: the attach/detach snapshot can be stale against an uncommitted revoke (characterized, not closed).
2. On the lock path, A2's union comparison uses the M13 snapshot, so it can be stale for a union-holder (same family as RES-27).
3. Classification (M14/M15) is read before the lock; a concurrent attach can change admin-defining status in between.
4. The "reverse" disagreement (A4 administrator, M16 not) is unreachable in the self-target path and untested.
5. No L-1 re-check on detach beyond the endpoint permission; detach is outside the lock family (RES-28).
6. The attach audit row no longer carries `holderCount`.
7. The k6 script `load/role-change-privileged-denial-throttle.k6.js` still uses retired names.
8. A-13 ordering: the administrator requirement precedes the subset check on revoke.
9. Two `RoleRevocationSymmetryIT` tests could not stay verbatim (dangerous custom role now `PERMISSION_ABSENT`; `TENANT_ADMIN` fixture needs the whole catalogue). Each is mapped above and in `09-technical.md` section 14.
10. No integration test ran; harness C, MC-H' and all ITs above need a run with Docker before the sign-off.
11. Environment items (zero-admin sweep, RES-6 retention, RES-26 owner confirmation) are deferred to the first deployment.
