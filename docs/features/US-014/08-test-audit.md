# Test Coverage Audit — US-014: Audit role assignment and revocation events

**Phase:** 8 (`/test-validate`) · **Branch:** `feature/US-014` · **Scope:** the 9 US-014-scoped files listed in the task brief only. Unrelated staged build-cache/CI/dependency changes on this branch are out of scope and were not touched (per T-T9 in `03b-threat-model.md`, already flagged and deferred).

**Inputs read in full:** `03-design.md` (§0, §3, §4.2, §8, §9, §11, §12, §13, §14, §15), `03b-threat-model.md` (all findings T-R5, T-D6, T-D7, T-I6, T-E14, T-T8/S5, T-T9), `04-tasks.md` (§0 scope resolution, Task 1/2 subtasks and DoDs), all 5 production files, all 4 pre-existing test files.

---

## Coverage audit for Task US-014

### Existing tests (before this audit)

- `identity/domain/AuthEventTypeTest.java` — all 23 `AuthEventType` constants, `wireName()` parity, the 6-member `PRIORITY` set (positive + `EXCLUDE`-mode negative), `ROLE_ASSIGNMENT_DENIED` explicitly asserted non-priority, unique wire names, enum-constructor delegation.
- `identity/infrastructure/audit/RbacAuthEventAdapterTest.java` — field-mapping for all three port methods (`recordRoleAssigned`, `recordRoleRevoked`, `recordRoleAssignmentDenied`), null-`traceId`/null-`reason`/null-`roleName` key-omission, the full adversarial-`roleName` matrix (quote, backslash, newline, control char, JSON-shaped, lone surrogate, duplicate-key-vs-`traceId` injection), the `reason`-vs-`roleName` duplicate-key ordering characterisation test, T-R3 never-throws + ERROR log + per-operation counter tag (`assign`/`revoke`/`deny`) for all three methods.
- `rbac/RoleAssignmentAuditIT.java` — real-MySQL round-trip for `ROLE_ASSIGNED`/`ROLE_REVOKED`/`ROLE_ASSIGNMENT_DENIED` rows (JSON validity, field values, key extraction), adversarial-`roleName` round-trip against real MySQL, no-row-on-rollback for 403/409/404, both AC4 denial rows read **post-throw** (T1/T2 cross-tenant, T3 not-tenant-admin), append-only trigger enforcement, AC5 ordered assign→revoke history with a cross-tenant decoy and a strict-ordering flake control, and the T-R3 forced real-MySQL-commit-boundary-failure scenario.
- `rbac/application/RoleAssignmentServiceTest.java` — happy path, every 404/403/409 branch for `assign`/`revoke`, T1/T2/T3 denial emission with value-equal `RbacAuditEvent` matchers, `equalsIgnoreCase` case-variant proof for the AC8 guard, actor-agnostic AC5 lockout (self-revoke and different-admin-revoke), the inline-vs-`afterCommit` side-effect fallback, and the `listActive` `verifyNoInteractions(rbacAuditPort)` pin (T-E14's binding control).

**Assessment:** this file set was authored against an unusually detailed design/threat-model/task-breakdown chain, and every test the design's own §12 test plan called for was already present and passing before this audit began. The gaps below are genuinely new findings from an independent pass, not re-derivations of the design's own plan.

### Gaps identified

- **[HIGH]** `RoleAssignmentService.recordDenial`'s own defense-in-depth `catch (RuntimeException)` (`RoleAssignmentService.java:373-382`) — guarding against `RbacAuditPort` violating its "must never throw" contract — was completely untested. Every existing test mocks `rbacAuditPort` to succeed silently; none exercises the branch that must (a) still let the *original* denial exception (`CROSS_TENANT_TARGET`/`NOT_TENANT_ADMIN`) win, uncorrupted, and (b) log `RBAC_AUDIT_DENIAL_CALL_SITE_FAILED` at ERROR. This is exactly the kind of "error path for a defensive catch block" gap the audit brief calls out, and a regression here (e.g. an accidental `throw` instead of `log`) would silently turn every 403 into a 500 the moment the audit port ever misbehaves. Added in `RoleAssignmentServiceTest.java`.
- **[MED]** Concurrent access on the `REQUIRES_NEW` audit write was completely unexercised. The threat model's T-D6 finding (Medium) is specific and quantified — the nested `REQUIRES_NEW` transaction holds two pooled connections per denial, and the design's own mitigation is *observability* (a watch-list + rollback trigger), not a test. But no test at any level proved the functional-correctness side of this: that concurrent, independently-suspended TX1/TX2 pairs never cross-contaminate each other's audit row (id collision, field bleed between threads, deadlock). Added a deterministic 8-thread concurrency IT in `RoleAssignmentAuditIT.java`, using this codebase's own established `CyclicBarrier`/`ExecutorService` pattern (`LastAdminLockoutIT`'s `should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins`) rather than inventing a new one.
- **[LOW]** No load-test coverage exists anywhere in the repo (`nexus-backend/src/test/load/` did not exist) for the pool-pressure shape T-D6 documents. The endpoints themselves don't meet `docs/TESTING.md`'s literal ">10 RPS" trigger (they are `user:write`-gated, `TENANT_ADMIN`-only traffic today — design §0 decision 5a), so a load test is not *mandated* by that bar. It is still the right tool for validating a documented Medium-severity **concurrency-burst** finding (as opposed to sustained-RPS), which is not something a fast, deterministic Maven test should attempt to reproduce (it would be inherently timing-dependent — exactly the flakiness this audit is instructed to avoid). Added a k6 script; see "Load scenarios" below.
- **[LOW, no action needed — recorded for completeness]** `DenialReason.PERMISSION_ABSENT`, `MALFORMED_AUTHENTICATION`, and `MISSING_TENANT` are not exercised by `RoleAssignmentServiceTest`/`RoleAssignmentAuditIT` in the `ROLE_ASSIGNMENT_DENIED` context. This is **correct, not a gap**: the design (§0 decision, threat-model T-R5) deliberately scopes AC4 to exactly `CROSS_TENANT_TARGET`/`NOT_TENANT_ADMIN` — the other three `DenialReason` values are thrown upstream of `RoleAssignmentService` (`@RequiresPermission`) and never reach `recordDenial`. Confirmed by reading `RoleAssignmentService.java` end-to-end: no code path can construct a denial audit event with any of those three reasons. No test is missing; a test asserting their *absence* would just be re-testing that the three throw sites are exhaustively enumerated, which the existing T1/T2/T3 coverage already does by construction.

### Tests added

`RoleAssignmentServiceTest.java` (+2, mirroring `RbacAuthEventAdapterTest`'s existing never-throws/ERROR-log pattern):
- `should_stillThrowOriginalDenialException_when_rbacAuditPortViolatesNeverThrowContract`
- `should_logErrorWithCallSiteFailedMarker_when_rbacAuditPortViolatesNeverThrowContract`
(plus `startLogCapture`/`stopLogCapture`/`keyValueMap` helpers, copied from the established `RbacAuthEventAdapterTest`/`RoleAssignmentAuditIT` idiom, and the `doThrow` static import.)

`RoleAssignmentAuditIT.java` (+1):
- `should_writeOneCorrectlyAttributedDenialRowPerThread_when_eightConcurrentCrossTenantDenialsRace` — 8 threads, each with its own tenant/actor/target/role fixture, racing a T1 cross-tenant `assign` denial via `CyclicBarrier`; asserts no deadlock (bounded `awaitTermination`) and that each thread's `ROLE_ASSIGNMENT_DENIED` row is exactly-one and correctly attributed to its own actor — never another thread's.

No changes were made to `AuthEventType.java`, `AuthEventTypeTest.java`, `RbacAuthEventAdapterTest.java`, or any production file — all were already complete against the design's own test plan (§12) and threat-model requirements.

### Run results

**Backend:** `./mvnw.cmd verify -Dmaven.build.cache.enabled=false` (Docker up, build cache disabled, full run — unit + slice + architecture + Testcontainers-MySQL integration tests, no ITs skipped):

```
Unit/slice/architecture (surefire): Tests run: 777, Failures: 0, Errors: 0, Skipped: 1
Integration (failsafe):             Tests run: 232, Failures: 0, Errors: 0, Skipped: 0
Total:                               1009 run, 0 failures, 0 errors, 1 skipped
JaCoCo per-package LINE gates:       All coverage checks have been met.
SpotBugs:                            0 bugs, 0 errors.
BUILD SUCCESS (Total time: 09:33 min)
```

US-014-scoped files specifically, from the same run:
```
AuthEventTypeTest            — 55/55 passing
RbacAuthEventAdapterTest     — 21/21 passing
RoleAssignmentServiceTest    — 29/29 passing (27 pre-existing + 2 new)
RoleAssignmentAuditIT        — 14/14 passing (13 pre-existing + 1 new), 3.9s
```

The 1 skipped test is `JpaAuthEventAdapterFailurePathBenchmarkTest` (`identity.infrastructure.persistence`) — pre-existing, unrelated to US-014, and conditionally skipped by its own design (a benchmark, not a correctness test). Not touched by this story and not investigated further per the "don't touch anything outside this file set" instruction.

**Frontend:** not run. US-014's design (§6) states a verified zero-line frontend diff — no `nexus-frontend/` file changed by this story or by this audit, so there is nothing new for Vitest/Angular TestBed to cover.

### Load scenarios

`nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js` — new file, new directory (neither existed before).

**Decision: added, but framed as a targeted regression check for threat-model finding T-D6, not as a ">10 RPS" endpoint-sizing scenario.** `docs/TESTING.md`'s literal trigger ("any endpoint expected to handle > 10 RPS") does not apply here: POST/DELETE `/api/v1/users/{userId}/roles` are `user:write`-gated and reachable only by an active `TENANT_ADMIN` today (design §0 decision 5a) — realistic steady-state RPS is low. However, the threat model's own T-D6 finding is a **concurrency-burst** risk, not a throughput risk: US-014's denial path adds a second, nested `REQUIRES_NEW` transaction that holds two of the default 10-connection HikariCP pool's connections per in-flight denial, and the threat model's own arithmetic states **~5 concurrent denials saturate the pool**. That is a documented Medium-severity finding with zero test coverage of any kind (unit, IT, or load) — a functional-correctness IT (added above) proves the writes don't corrupt each other, but nothing validates the pool-pressure claim itself, which can only be observed under genuine concurrent load against a realistically-sized connection pool. The script drives a short 10-VU concurrency burst (not a sustained soak) against the cheapest denial path (T2, `CROSS_TENANT_TARGET`, per T-D7), checks for non-403 responses (which would indicate pool exhaustion rather than the expected, by-design denial), and documents the exact Actuator/Prometheus signals from the design's own §11 watch list to inspect during the run (`hikaricp_connections_pending`, `hikaricp_connections_acquire_seconds`, `nexus.rbac.audit_write_failed{operation="deny"}`). It is explicitly **not** wired into `./mvnw verify` or CI — it requires a staging-like environment with realistic HikariCP sizing and a real `TENANT_ADMIN` JWT, and is meant to be run manually ahead of the US-015 entry-criterion decision the threat model already forwards (T-D6 item 4).

### Flaky tests

**None identified in the US-014-scoped files**, including the two new concurrency-adjacent additions:
- The new `RoleAssignmentAuditIT` concurrency test uses `CyclicBarrier` (not `Thread.sleep`) to synchronize thread start and a generous, one-time `awaitTermination(15, TimeUnit.SECONDS)` bound only to catch a genuine deadlock — it does not assert on relative timing or thread interleaving order, only on the final DB state per (independent, non-shared) fixture. It ran in 3.9s for all 14 methods in the class in the full-suite run above, with no retries needed. This mirrors the pattern `LastAdminLockoutIT`'s own concurrency test already established and vouches for in this codebase.
- The two new `RoleAssignmentServiceTest` methods are plain Mockito unit tests with no timing, ordering, or external-state dependency.
- The new k6 script is explicitly out of the deterministic-suite gate (documented above) precisely because a genuine pool-pressure observation *is* timing/load-dependent by nature — keeping it out of `./mvnw verify` is what keeps the Maven suite itself non-flaky.

**Pre-existing, out of scope for this story:** none newly observed. The one skipped test (`JpaAuthEventAdapterFailurePathBenchmarkTest`) is a benchmark, not a flake, and was already skipped before this audit began.

---

## Files touched by this audit (all under the in-scope US-014 file set, or net-new test infrastructure)

- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java` — +2 test methods, +3 log-capture helper methods, +imports (`doThrow`, logback `ListAppender`/`Logger`/`Level`/`ILoggingEvent`, `HashMap`/`Map`, `LoggerFactory`).
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java` — +1 concurrency test method, +imports (`ArrayList`, `java.util.concurrent.*`).
- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js` — new file, new directory.
- `docs/features/US-014/08-test-audit.md` — this report.

No production file under the US-014 scope was modified — this was a test-only audit, as expected for Phase 8.
