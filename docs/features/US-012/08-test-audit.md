# Coverage audit for Task US-012

**Phase:** 8 (test-validate)
**Scope:** `com.example.nexus.rbac` (assign/revoke/list role endpoints) + the `identity`/`common` files US-012 touched (`RbacAuthEventAdapter`, `JpaUserDirectoryAdapter`, `DenialReason`, `GlobalExceptionHandler`, `AuthEventType`).

## Existing tests

- `rbac/application/RoleAssignmentServiceTest.java`: all 8 ACs at the unit level — every 404/403/409 error branch on `assign`/`revoke`/`listActive`, the `equalsIgnoreCase` mixed-case `TENANT_ADMIN` matching branch (assign and revoke), the actor-agnostic AC5 lockout (self-revoke and different-admin-revoke variants), the T-E8 tenant-check-not-bypassed assertion, and the inline-vs-`afterCommit` side-effect fallback.
- `rbac/interfaces/rest/UserRoleControllerTest.java`: MockMvc slice — principal/tenant unwrapping, T-E10 provenance (path `userId` ≠ actor), `MALFORMED_AUTHENTICATION`/`MISSING_TENANT`/null-principal fail-closed cases, malformed-UUID path/body → 400 (not 500), 201 + `Location` header, `assignedBy` null serialization, 204 on revoke.
- `rbac/RoleAssignmentIT.java`: happy path (assign/revoke/reassign-after-revoke), duplicate 409, all 404 paths, M6 microsecond-precision assertion, non-null `assignedAt` re-read, T-S3 four-distinct-UUID provenance.
- `rbac/LastAdminLockoutIT.java`: self-revoke and different-admin-revoke lockout (409 RBAC_002), 8-thread concurrency race (`CyclicBarrier`) proving exactly one winner and the tenant retains ≥1 admin, non-bootstrap-tenant R-9 regression case, `EXPLAIN` pinning M1's query plan + `for update` in emitted SQL.
- `rbac/security/RoleAssignmentSecurityIT.java`: cross-tenant 403 on all 3 verbs (T-E8), 404 vs 403 distinction, AC8 non-admin-writer 403, the stale-JWT T-E7 test (out-of-band revoke, same still-valid JWT denied), paired positive/negative permission controls per endpoint (T-E11), T-E10 provenance over real HTTP, T-S4 fail-closed forged-principal JWT, malformed path/body UUID → 400 regression.
- `rbac/RoleAssignmentCacheIT.java`: both real Redis keys evicted on assign/revoke, Redis-down fail-open, no eviction on 403/409/404.
- `rbac/RoleAssignmentAuditIT.java`: `ROLE_ASSIGNED`/`ROLE_REVOKED` field mapping via `JSON_VALID`/`JSON_EXTRACT`, adversarial `roleName` round-trip against real MySQL, no audit row on rollback, the T-R3 forced real-MySQL-commit-boundary audit-write-failure case (ERROR log + counter).
- `rbac/UserRolesPrivilegeIT.java`: `nexus_app` DB-privilege boundary (column-scoped `UPDATE`, `FOR UPDATE`, grant shape).
- `rbac/domain/*Test.java` (`ActiveAssignmentRefTest`, `ActiveRoleAssignmentTest`, `DuplicateRoleAssignmentExceptionTest`, `LastAdminRoleExceptionTest`, `RbacRoleNamesTest`, `RoleChangeActorTest`): JaCoCo-floor domain tests, code/message literal-regardless-of-cause assertions.
- `rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorTest.java`, `RbacDbPrivilegeHealthIndicatorTest.java`: T-D4 zero-admin detector, positive-grant check.
- `identity/infrastructure/audit/RbacAuthEventAdapterTest.java`, `identity/infrastructure/persistence/JpaUserDirectoryAdapterTest.java`: field-mapping table, full adversarial `roleName` matrix, never-throws behavior, present/absent-user cases.
- `common/web/GlobalExceptionHandlerTest.java`, `identity/domain/AuthEventTypeTest.java`: `nexus.domain.conflict{code}` counter for RBAC_002/RBAC_004, 22-constant/`PRIORITY` exhaustive assertions.

This is an unusually thorough test-first suite — nearly every AC, threat-model finding, and design decision already had a named, deliberate test before this audit began.

## Gaps identified

- **[HIGH] TOCTOU backstop in `JpaUserRoleAssignmentAdapter.assign()` never exercised end-to-end, and turned out to be genuinely broken** — added in `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentIT.java` (`should_allowExactlyOneWinner_when_eightConcurrentAssignsRaceForSameUserAndRole`) and `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java` (new file). `RoleAssignmentIT`'s existing duplicate test only exercises the service's M2 *pre-check* (never reaches the adapter's insert); `ActiveAssignmentIT`'s concurrent-insert test calls `JpaUserRoleRepository#save` directly, bypassing the adapter entirely. No test drove two genuinely concurrent `RoleAssignmentService.assign()` calls through the real adapter. **This test caught a real bug**: `JpaUserRoleAssignmentAdapter.assign()` called `userRoleRepository.save(...)` (not `saveAndFlush`), so under a real TOCTOU race the `uq_user_role_active` constraint violation was not thrown by `save()` itself — Hibernate deferred the physical INSERT until the next auto-flush-triggering call, which turned out to be `RoleAssignmentService.assign()`'s own M4a re-read (`findActiveAssignmentView`) immediately afterward. The `DataIntegrityViolationException` therefore escaped the adapter's `try/catch` entirely and would have surfaced to a real client as an unhandled 500 instead of a clean `409 RBAC_004`, on any real concurrent duplicate-assignment attempt. **Fixed** in `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` by switching to `saveAndFlush`, forcing the INSERT (and any constraint violation) to happen synchronously inside the existing `try/catch`.
- **[HIGH] `JpaUserRoleAssignmentAdapter` had only 12% unit line coverage / 0-of-4 branches** (JaCoCo: 88 missed / 12 covered lines) — added in `JpaUserRoleAssignmentAdapterTest.java` (new file, 15 tests: delegation tests for all 9 port methods + the `DataIntegrityViolationException` → `DuplicateRoleAssignmentException` translation, both success and failure). Confirmed this was a real gap, not "covered end-to-end just not by unit tests": no existing IT exercised the translation branch either (see the HIGH finding above) — it is genuinely closed now, both by a fast Mockito unit test and by the real-MySQL concurrency IT. Post-fix coverage: **100% lines, 4/4 branches**. (`JpaUserRoleQueryAdapter`'s separate 33% gap is pre-existing from US-010, untouched by this branch's diff — out of scope for this audit, flagged for a future story.)
- **[MED] O-10's `assignedBy` redaction decision had no end-to-end HTTP proof against a real caller's live admin status** — added in `RoleAssignmentSecurityIT.java` (`should_includeAssignedBy_when_callerIsActiveTenantAdmin`, `should_omitAssignedBy_when_callerIsNotActiveTenantAdmin`). The decision (03-design.md §4.2/O-10, threat T-I5 admin-roster enumeration) was previously proven only at the unit level (mocked ports) and via a MockMvc slice with a **mocked** `RoleAssignmentService` (`UserRoleControllerTest`) — neither exercises the real `callerHoldsActiveTenantAdmin` DB read through a real HTTP request. Closed with two real-JWT, real-embedded-server tests: a `TENANT_ADMIN` caller sees `assignedBy`; an ordinary-permission caller does not (value is `null`, matching the DTO's documented "omitted/null" contract — no `@JsonInclude(NON_NULL)` is applied, so the field is present-but-null rather than absent, consistent with `UserRoleControllerTest`'s own `jsonPath(...).doesNotExist()` assertion which accepts both).
- **[LOW] `JpaUserRoleQueryAdapter` at 33% unit coverage** — pre-existing (US-010), not modified by this branch's diff (`git log` confirms last touch was `aa028b9`). Not actioned here; noted for whoever next touches that class.
- **[LOW] No dedicated concurrency test for two callers revoking the same *non-admin* assignment simultaneously** — considered, not added. The mechanism (`M6`'s bulk `UPDATE ... WHERE revoked_at IS NULL`, affected-rows-as-concurrency-guard) is simpler than the admin-lockout and duplicate-assign races already covered, is already proven correct at the unit level (`should_throwResourceNotFound_when_revokeLosesRaceAndZeroRowsAffected`), and shares its core mechanism with `LastAdminLockoutIT`'s own concurrency harness (which already exercises the M6 lost-race path for admin rows under real concurrency). Lower marginal value; flagged rather than added, to avoid low-value test-suite bloat.

## Tests added

`nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java` (new file, unit, 15 tests):
- `should_delegateToRoleRepository_when_findingRoleById`
- `should_returnEmpty_when_roleNotFound`
- `should_returnTrue_when_activeAssignmentCountIsPositive`
- `should_returnFalse_when_activeAssignmentCountIsZero`
- `should_returnTrue_when_lockActiveAdminAssignmentReturnsNonEmptyList`
- `should_returnFalse_when_lockActiveAdminAssignmentReturnsEmptyList`
- `should_mapLockedRowsToTheirIds_when_lockingActiveAssignmentIds`
- `should_delegateWithTenantThenRoleArgumentOrder_when_lockingActiveAssignmentIds`
- `should_delegateToRepository_when_findingActiveAssignmentRef`
- `should_delegateToRepository_when_findingActiveAssignmentView`
- `should_delegateToRepository_when_findingActiveAssignmentViews`
- `should_saveAndFlushNewUserRoleAndReturnItsId_when_noConstraintViolation`
- `should_throwDuplicateRoleAssignmentException_when_saveAndFlushThrowsDataIntegrityViolation`
- `should_delegateToRepositoryRevokeById_when_revoking`
- `should_returnZero_when_revokeByIdAffectsNoRows`

`nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentIT.java` (added):
- `should_allowExactlyOneWinner_when_eightConcurrentAssignsRaceForSameUserAndRole` — 8-thread `CyclicBarrier` race of `RoleAssignmentService.assign()` for the same `(user, role)` pair; asserts exactly one `SUCCESS`, all others `DuplicateRoleAssignmentException` (409 RBAC_004), never an unhandled exception, and exactly one active row survives.

`nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java` (added):
- `should_includeAssignedBy_when_callerIsActiveTenantAdmin`
- `should_omitAssignedBy_when_callerIsNotActiveTenantAdmin`

## Bug found and fixed (not a test-only change)

`nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` — `assign()` changed from `userRoleRepository.save(userRole)` to `userRoleRepository.saveAndFlush(userRole)`. Justification: `save()` alone only queues the INSERT in Hibernate's persistence context; under this codebase's actual call shape, the very next operation in `RoleAssignmentService.assign()` is the M4a re-read (`findActiveAssignmentView`), which triggers Hibernate's auto-flush and is where the `uq_user_role_active` constraint violation was actually surfacing — one call frame away from the adapter's own `try/catch (DataIntegrityViolationException)`, escaping the translation to `DuplicateRoleAssignmentException` entirely. `saveAndFlush` forces the INSERT (and any violation) to happen synchronously, inside the intended `try/catch`. Verified by the new `RoleAssignmentIT` concurrency test (was red before the fix, reproducing exactly this escape against real Testcontainers MySQL; green after).

## Run results

Backend (`./mvnw.cmd -o verify`, Testcontainers MySQL 8.4 + Redis 7.4, Docker):
- **Unit tests: 226/226 passing**
- **Integration tests: 203/203 passing**
- **Total: 429/429 passing**
- JaCoCo bundle + package gates (`*.domain.*` 0.90, `*.application.*` 0.85, `*.interfaces.rest.*` 0.80, `*.infrastructure.*` 0.70, bundle 0.80): all met
- `JpaUserRoleAssignmentAdapter` coverage after the added unit test: **100% lines (was 12%), 4/4 branches (was 0/4)**
- SpotBugs: 0 bugs, 0 errors
- Checkstyle: passed
- **BUILD SUCCESS**

Frontend: not applicable — `02-impact.md` §1.6 confirmed (and this audit re-confirms by inspection: no files under `nexus-frontend/` appear in `git status`/`git diff --stat` for this branch) zero frontend impact for US-012. `npm test` not run; nothing to run against.

## Load scenarios

Not added, per the task's own scope note: no story AC requires >10 RPS for these three endpoints (`docs/features/US-012/01-requirements.md`'s Non-Goals explicitly exclude rate limiting/bulk assignment; `03-design.md` §1 goal 4 is "add nothing to the platform" — no capacity target was set for this story). Skipped, consistent with skill guidance to add load scenarios only where a story AC calls for it.

## Flaky tests

None identified as flaky by inspection or by re-running the two touched IT classes twice (once red investigating the real bug, once green after the fix) plus a full-suite run. Specific notes on the tests most likely to raise flakiness concerns, and why they don't, based on reading them:

- **`LastAdminLockoutIT#should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins`** and the newly added **`RoleAssignmentIT#should_allowExactlyOneWinner_when_eightConcurrentAssignsRaceForSameUserAndRole`** both use a real `ExecutorService` + `CyclicBarrier` against Testcontainers MySQL — the canonical shape for a timing-sensitive test. Neither asserts a specific interleaving or timing value; both assert only structural invariants (`exactly one winner`, `every outcome is one of N safe categories`, `final DB state is consistent`) that hold regardless of thread-scheduling order, so they are non-flaky in the sense that matters (no assertion depends on *which* thread wins, only that *exactly one* does). Both ran clean across three separate executions in this session.
- **`RoleAssignmentSecurityIT`**'s denial-reason-counter assertions (`assertDenialReasonIncrementedByOne`) read a shared, cumulative `MeterRegistry` across the whole test class and explicitly use before/after deltas rather than absolute counts for exactly this reason — already correctly guarded against cross-test-method ordering, confirmed by reading the helper.
- **`RoleAssignmentAuditIT`**'s T-R3 forced-failure test relies on a specific Hibernate `merge()`-vs-`persist()` mechanism (pre-inserting a colliding `@Id` row) rather than timing — deterministic, not flaky.
- No test in this feature uses `Thread.sleep`, wall-clock timing assertions, or unseeded randomness; all IT fixtures use freshly generated UUIDs per test (no shared mutable fixture state across tests, apart from `LastAdminLockoutIT`'s explicitly-documented and explicitly-cleaned-up bootstrap-tenant scenarios).
