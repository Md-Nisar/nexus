# US-018 Milestone 2 code review (T-001, T-002, T-003)

**Verdict: APPROVE WITH NITS.** No Blocker or High findings. Fix the Medium finding (one missing test) before the PR is opened.

Scope: `git diff 1a8c017..HEAD -- nexus-backend` (commits 9b823d5, 9b2a7e9, 489b0fb). Checked against design §2.1–2.3 and §4.1–4.11, `04-tasks.md` T-001 to T-003, and threat rows T-E32, T-E35, T-E36, T-E41, T-E42, T-T21.

**Reviewer ran (offline, `-DskipITs`, JaCoCo skipped), all passing:** RoleAssignmentServiceTest 136, RoleManagementServiceTest 61, HexagonalArchitectureTest 15, TenantIsolationArchitectureTest 1, RbacAdministratorsTest 6, RolePermissionRefTest 2, JpaUserRoleAssignmentAdapterTest 26, UserRoleControllerTest 15, RbacAuthEventAdapterTest 45, GlobalExceptionHandlerTest 24.
**Not run:** full `./mvnw verify -DskipITs` (JaCoCo gate) and every IT (compiled only, as the DoD allows).

## What is correct

- `assign()` order matches Decision 6 (`RoleAssignmentService.java:229-319`): tenant checks, throttle, legacy M11/M5b gate, single M13 read, A4, A2, duplicate 409, insert. Throttle precedes M13/M14/M15 (EC8). M15 is read only on a self-target.
- `attachPermission` order matches §4.3 (`RoleManagementService.java:183-207`). A3 runs before the duplicate check, so a 409 cannot reveal attachment state; unit and IT tests pin this.
- `RbacAdministrators.isAdminDefining` compares ids per role; A4 groups M13 rows by `roleId`, so holding the catalogue across two partial roles is denied.
- Fails closed when M13, M14 or M15 throws; empty M13 denies any role with permissions; empty target role passes (EC7).
- Every new 403 carries the endpoint permission as `requiredPermission`. `nexus.rbac.permission_denied{permission,reason}` is incremented once, centrally (`GlobalExceptionHandler:167`).
- Audit: one `ROLE_ASSIGNMENT_DENIED` row per request (first reason); `missingCount` is a count only; A3 writes no audit row. WARN logs carry ids only.
- Tenant scoping: M13 joins `r.tenantId = ur.tenantId` (T-S1); an IT seeds a drifted cross-tenant row and checks no widening. M14 has a tenant predicate.
- MC-2: ArchUnit rule `m12_is_never_read_on_an_rbac_decision_path` is well built. MC-A: M13/M14/M15 SQL-capture tests assert no `FOR SHARE`/`FOR UPDATE`.
- V6 is data only, idempotent; `RbacSchemaMigrationIT` re-runs the footer text read from V6 itself.
- Performance (§4.6): ~2 statements per assign (3 on self-target), 1 per attach, all indexed; within the 10 ms p95 budget.
- No new flag, no new error code. IT fixture churn legitimate; no assertion weakened.

## Findings

**[Medium] A4 denying a privileged self-assignment that the legacy gate allows is untested**
- Files: `RoleAssignmentServiceTest.java` (A4 tests ~:3770-4065 all use `stubBenignSelfAssignTarget`), `RoleAssignmentSecurityIT.java:505-534`.
- Before US-018 a caller holding all three dangerous permissions (not the whole catalogue) could self-assign `TENANT_ADMIN` (US-017 RES-13). A4 is now the only control that denies it and no test asserts that. The IT fixture at `:511` moved to "whole catalogue", so the old success path still passes. The "legacy passes, then A4 denies" pair and the lock-held path (denial row in `REQUIRES_NEW`, lock-hold timer `outcome=denied`) are untested.
- Fix: (1) unit test: `privileged=true`, legacy gate passes the all-three set, M13 returns one role with the three dangerous permissions + `user:role:assign`, catalogue = 9. Assert reason `SELF_ASSIGNMENT`, `recordRoleAssignmentDenied(..., SELF_ASSIGNMENT, "assign")` once, `assign()`/`hasActiveAssignment()` never called, timer `outcome=denied`. (2) `GrantSubsetIT`: caller role with `user:write`, `role:write`, `tenant:write`, `user:role:assign` self-assigns `TENANT_ADMIN`; expect 403 `RBAC_001`, one denial row `reason=SELF_ASSIGNMENT`, zero active assignments.

**[Low] M14 tenant predicate fails open** (`RoleAssignmentService.java:1076-1079`, `JpaRoleRepository.findPermissionIdsByRoleAndTenantId`)
- A tenant mismatch returns an empty set, which A2 treats as "grants nothing" (passes). Safe today only because `resolveRoleInTenant` runs first. Fix: correct the Javadoc (predicate satisfies the tenant-isolation gate, not an authorization control) or fail closed with `Optional<Set<UUID>>`.

**[Low] Undocumented design deviations** (`JpaUserRoleAssignmentAdapter.java:47`, `JpaPermissionRepository.java`, `UserRoleAssignmentPort.findPermissionIdsForRole(UUID, UUID)`)
- M15 is on `JpaPermissionRepository` (design/T-002(b) say `JpaRoleRepository`); M14 takes `(roleId, tenantId)` (T-001(c) says `(UUID roleId)`); the adapter constructor changed (§4.3 says unchanged). Reasons are sound (avoids a tenant-isolation exemption). Record all three; optionally host M15 on a narrow read-only `PermissionCatalogueReader` interface.

**[Low] `DangerousPermissionHolderSignalIT` stale name and misleading comment** (`:88`, `:93`)
- Name `...ToSelfAssignedBenignRole` no longer fits; the comment claims A2/A4 coverage but the holding is seeded directly. Rename, then either route through `assign()` with a `user:role:assign` holder or reword the comment.

**[Low] TS-4's last assertion cannot fail** (`GrantSubsetIT.java:256-262`)
- Fix: drop it, or make a real administrator attach via `POST /roles/{id}/permissions` and assert the caller's resolved permissions lack `role:write`.

**[Low] New JPQL and V6 footer verified only by ITs that have not run**
- M13 constructor expression, M14/M15 `Set<UUID>` projections, `RbacSchemaMigrationIT` footer re-run, `GrantSubsetIT` `missing_count` extraction. Make `/test-validate` (full IT suite) a hard gate; treat failures in `GrantSubsetIT`, `RbacSchemaMigrationIT`, `LastAdminLockoutIT` 6d/6f as blockers.

**[Nit]** `RbacAuditPort.java:41` Javadoc still says `user:write` holders; should be `user:role:assign`.
**[Nit]** `LastAdminLockoutIT.java:1124-1130` two stacked Javadoc blocks on `seedTenantAdminRole`; merge.
**[Nit]** `recordDenial` null-dispatch plus 3-arg/4-arg `RbacAuditPort` overloads duplicate logic; make the 3-arg a default method or accept.

## Notes (not findings)

- A throttled actor gets `DenialReason.NOT_TENANT_ADMIN` (pre-existing); tidy when B8 lands in M8.
- Residuals correctly recorded in code comments: RES-27 (snapshot TOCTOU), RES-1(b) not claimed closed ("self path only, RES-26"). On privileged targets M13 runs after the M11 lock wait; §4.3 accepts this for M2.

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 1 |
| Low | 5 |
| Nit | 3 |

**Verdict: APPROVE WITH NITS.** Before the PR: (1) add the missing A4-on-privileged-target tests, (2) run the IT suite green, (3) record the three design deviations.
