# US-019 test audit (Phase 8, single pass over `feature/US-019`)

**Date:** 2026-10-22 · **Diff base:** `origin/main...HEAD` (333 files, 28 tasks plus the review fix pass) · **Auditor:** qa-engineer.
Load tests: none, by decision O-1 in `04-tasks.md` (no latency budget, so no load test). Noted, not added.

## Coverage audit for Feature US-019

### Existing tests (by area)
- RBAC logic: `RoleManagementServiceTest` (175), `RoleAssignmentServiceTest` (152), `PiiPermissionGrantRuleTest`, `IfMatchHeaderTest`, `RolePermissionSetVersionTest`, `BootstrapAdminServiceTest`, `CallerAuthorizationServiceTest`, controller slices (`RoleControllerTest` 65 cases, `PermissionControllerTest`).
- RBAC integration (Testcontainers MySQL, app connects as `nexus_app`): `RolePermissionReplaceIT`, `RolePermissionReplaceConcurrencyIT`, `LastAdminLockoutIT` (21), `AttachProvenanceRaceIT`, `AttachSerialisationIT`, `SelfAssignDemotionRaceIT`, `AssignRoleContentionIT`, `PiiPermissionGrantIT`, `CrossTenant*IT`, `RoleManagement*IT`, privilege ITs.
- Identity directory: `UserDirectoryServiceTest`, `UserDirectoryControllerTest`, `UserDirectoryFeatureFlagTest`, `DirectoryAccessGuardTest`, `UserDirectoryIT`, `...CeilingIT`, `...LookupThrottleIT`, `...LogScanIT`, `...ConnectionPoolIT`, audit adapter tests.
- Architecture rules (tenant isolation, containment of existence/count/sensitivity sets).
- Frontend: `safe-return-url.spec`, `app-config.spec`, `access-denied` / `not-found` specs, guards, interceptors, shell; 31 Playwright tests in 10 files; `e2e/tools/tools.selftest.mjs` (14).

### Mutation spot-checks (production code mutated, targeted tests run, code restored with `git checkout`)
All 8 behaviours went red. After each run `git status` showed no production change.

| # | Mutation | Result (killed by) |
|---|---|---|
| 1 | `IfMatchHeader.parse(null)` returns `""` instead of 428 | RED: `IfMatchHeaderTest` (1), `RoleControllerTest.should_return428WithoutCallingTheService_when_ifMatchIsAbsent` |
| 2 | 412 check replaced by `if (false)` | RED: 2 unit tests, `RolePermissionReplaceIT.should_return412WithNoStateInTheBody_when_ifMatchIsAnOldETag` |
| 3 | 412 check moved before `authorizeReplace` (403-before-412 order) | RED: `should_throw403Not412_when_anUnauthorisedRemoverSendsAStaleTag`, `RolePermissionReplaceIT.should_return403ForEveryRemovingCombination...` |
| 4a | PII rule: `enforced ? DENIED : DELEGATED` becomes `DELEGATED` | RED: `PiiPermissionGrantIT` (2), 3 service-test failures in management, 4 in assignment |
| 4b | PII rule: administrator check forced true | RED: `PiiPermissionGrantIT` (2), 4 + 6 unit failures |
| 5a | attach RBAC_010 pre-lock and locked checks disabled | RED: 10 unit tests, `LastAdminLockoutIT` |
| 5b | attach locked re-check only disabled | RED: `AttachProvenanceRaceIT.should_refuseTheAttachWithRbac010_when_aNonAdministratorAssignCommittedAfterItsPreLockRead` (the R1-1 fix is pinned at IT level) |
| 5c | assign RBAC_012 post-insert classification disabled | RED: 2 unit tests, `LastAdminLockoutIT.should_return409Rbac012ForTheAssign_when_itQueuedBehindAPromotionOfTheRole` |
| 6a | assign set-lock path reverted to the pre-lock read (R1-2) | RED: `SelfAssignDemotionRaceIT`, 3 unit tests |
| 6b | replace demotion check disabled | RED: `LastAdminLockoutIT` (one caller demoting both admin roles), 2 unit tests |
| 6c | replace promotion RBAC_010 check disabled | RED: `RolePermissionReplaceIT.should_return409Rbac010AndChangeNothing_when_promotingARoleWithANonAdministratorAssignedHolder`, 2 unit tests |
| 7a | by-id read without tenant predicate (`findById`) | RED: `UserDirectoryIT.should_answerByteIdenticalNotFound_when_theIdIsForeignOrMissing` |
| 7b | batch read without tenant predicate | RED: `UserDirectoryIT.should_returnAnUnchangedResponseAndWarnBatch_when_aBatchCarriesAForeignId` |
| 7c | 404 body differs for foreign vs missing id | RED: `UserDirectoryIT` byte-identical test, 2 `UserDirectoryServiceTest` tests |
| 8 | `safeReturnUrl`: drop `//`, drop `:` rule, drop `\`/control rule, drop `/auth` loop rule; `parseSupportContact`: allow `javascript:` | RED each time (the reject-case tests). Caveat: a bare `npx vitest run safe-return-url` fails 4 "accepts" cases at baseline (no jsdom origin outside `ng test`); the red results above come from the reject cases, and the full gate runs under `ng test` and is green |

No tautological test found among the 8 behaviours. Mutations were run as `mvnw test -Dtest=...` (the ITs run via surefire with Docker).

### Gaps identified
- [HIGH] Frontend `npm run test:ci` exited 1 with 4 unhandled `NG0205 Injector has already been destroyed` rejections although all 515 tests passed. Cause: the `it.each` "should cap Retry-After" cases fire a 503 AUTH_005, which raises the availability toast through a lazy `import()` that resolved after TestBed teardown (`service-availability-notifier.ts:37`). Reproduced twice, so a red gate. Fixed in `nexus-frontend/src/app/core/http/api-error.interceptor.spec.ts` (the cases now `await vi.dynamicImportSettled()`); two further runs exit 0 with 0 errors. No production change.
- [MED] Authorization matrix for the directory routes was incomplete: only `POST /users/lookup` had a 403 pin; list, batch and by-id had no 401/403 test, and 401 was unpinned on all four. Added to `UserDirectoryIT` (below).
- [MED] Open gap 3: no IT forced an audit-write failure through the stack. Added `UserDirectoryAuditFailureIT`. Finding while writing it: on a store outage `SecureEventService.recordEvent` is already best-effort and buffers for retry, so `DirectoryReadAuthEventAdapter`'s own catch and the counter `nexus.identity.directory.audit_write_failed` are NOT reached; the counter only covers serialisation failures. The runbook or alert should not expect that counter to fire on a DB outage (first attempt asserted it and was red; the test now asserts the real contract: 200 with data, save attempted).
- [LOW] The dev-persona `assigned_by`, label and naming deviations in the brief have no test and no behavioural risk; left.

### Tests added
- `UserDirectoryIT.should_return403Rbac001OnEveryGetRoute_when_theCallerLacksDirectoryRead`
- `UserDirectoryIT.should_return401OnEveryRoute_when_noTokenIsSent` (list, batch, by-id, lookup)
- `UserDirectoryAuditFailureIT.should_answer200WithTheData_when_theAuditStoreRejectsTheRowWrite`
- Fixed (not added): `ApiErrorInterceptor` spec "should cap Retry-After" now awaits the lazy toast import.

### Run results (final gates, sequential, Docker up)
- Backend `sh ./mvnw -B verify -Ddependency-check.skip=true`: BUILD SUCCESS, 15:26 min. Surefire: 2626 run, 0 failures, 0 errors, 2 skipped. Failsafe ITs: 693 run, 0 failures, 0 errors, 0 skipped. Checkstyle, JaCoCo ("All coverage checks have been met") and SpotBugs (BugInstance size is 0) pass. The 2 skips are pre-existing `@Disabled` tests: `ThrottleSharedStoreStartupAssertionTest` (needs the human `application-prod.yml` edit) and `JpaAuthEventAdapterFailurePathBenchmarkTest`. The new ITs ran inside this build.
- Frontend: `npm run test:ci` 57 files, 515/515 passing, 0 errors, exit 0 (run twice after the fix); `npm run lint` all pass; `npm run format:check` clean; `npm run build` succeeded.

### Flaky tests
None observed in the full run. Reviewed and judged acceptable:
- `Thread.sleep(5/50)` in `AttachSerialisationIT`, `RolePermissionReplaceConcurrencyIT`, `LastAdminLockoutIT`: deadline-bounded polling of `performance_schema.data_lock_waits` to observe a queued lock, not a fixed wait. Fails only if MySQL never queues, as an explicit `AssertionError`. The orderings are forced (gates/spies), not raced; `AttachSerialisationIT` and `AssignRoleContentionIT` run 50 iterations.
- `AssignRoleContentionIT`: the p95 delta is now logged, not asserted (review R1-4 fixed).
- `RolesPrivilegeIT:120` `Thread.sleep(20)` before asserting `updated_at` moves: safe because the column is `DATETIME(6)`; wall-clock dependent in principle, Low.
- Log-capture ITs (`UserDirectoryIT`, `...LogScanIT`, `...LookupThrottleIT`): the appender is attached to one class logger and detached in `finally`; surefire runs sequentially. Low.

### Load scenarios
None, by decision O-1.

### E2E / CI path (as far as it runs locally)
- `node --test e2e/tools/tools.selftest.mjs`: 14/14 pass (assert-executed zero-test/one-skip fixtures, scan-pii log/case/zip/clean).
- `npx playwright test --list`: 31 tests in 10 files, equal to `E2E_MIN_TESTS: "31"` in `.github/workflows/e2e-full-stack.yml`, so the floor has no slack: one skipped test turns the check red (intended).
- `docker compose -f docker-compose.yml -f docker-compose.e2e.yml config` parses. The browsers and the full stack were not run (no Playwright browsers installed here, no network image builds): the compose path stays unproven.

### The five open gaps
1. Unentitled user to `/access-denied` has no e2e: LEFT OPEN (no gated route exists yet). Covered by `permission.guard.spec`, `permission-guard-contract.spec` and `access-denied.component.spec` (9 cases, including 10 unsafe contact variants).
2. By-id 404 writes no audit row: DECIDED, already pinned by `UserDirectoryIT.should_notAudit_when_aByIdReadFindsNoUser` (and the service test); no change. Design says one row per request, so either amend the design or change both the code and that test together.
3. Audit-write failure through the stack: CLOSED (see above), with the counter caveat.
4. Compose path unproven: LEFT OPEN (config parses; end-to-end run needs CI).
5. `replaced` vs `applied` metric label: LEFT OPEN; `RoleManagementServiceTest` pins `replaced` (lines ~3124-3434). Align design §17 or the label in one change with those assertions.

### Not covered
Visual review of the contrast-token retune (~20 style files) and a real-browser axe run; `application-prod.yml` PII switch (human edit); Redis-down behaviour beyond existing ITs.
