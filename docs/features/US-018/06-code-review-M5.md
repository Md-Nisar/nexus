# Code review: US-018 M5 / T-007, T-008 (A7 break-glass first-administrator grant and CLI)

**Verdict: APPROVE WITH NITS.** Reviewed 2026-10-15 by the `code-reviewer` agent (fresh context). Scope: `git diff origin/main...HEAD -- nexus-backend` on `feature/US-018/M5` at `8085c49`. The diff spans commits `7805c25` (T-007), `bccd846` (T-008), `c1a6b38` (D-31 cache eviction) and `4efdcd7` (security-review fixes), plus docs commits and the merge of `main`. It touches 47 files, +3023/-33. The security audit was done separately (`07-security-review-M5.md`) and is not repeated here. Deviations D-15..D-37 (`09-technical.md` §13) are accepted and were checked only for agreement between code and text; they all match.

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 0 |
| Low | 2 (L-1, L-2) |
| Nit | 5 (N-1 .. N-5) |

Nothing blocks merge. L-1, L-2, N-1, N-4 and N-5 are fixed on the branch; N-2 and N-3 are left as they are (see Fix status).

## Gates run by the reviewer

- None; the review was read-only, without Maven. The branch's full `verify` is recorded in `08-test-audit-M5.md`.
- Checked by reading: `V5__rbac_schema.sql` (`uq_user_role_active` on the generated `active_key`, `fk_user_roles_role`), `V2__identity_schema.sql` (`auth_events` has no FK, so a `USER_NOT_FOUND` refusal row with an unknown `user_id` inserts cleanly; `idx_auth_events_event_type_created_at`), and `JpaUserRoleRepository.lockActiveAssignmentHoldersByRoles` (M11, `FORCE INDEX (fk_user_roles_role)`, `FOR UPDATE`).

## Matches the design

- **§7.1 order:** `BootstrapAdminService.grantFirstAdmin` runs the checks in this order: replay check (exit 6, before any user lookup), target missing or not ACTIVE (exit 3), system `TENANT_ADMIN` with tenant and `is_system_role` check (exit 4), M10 prime, M11 lock, zero-administrator check (exit 5), INSERT with `assigned_by = target`, then the atomic audit. Unit tests pin the order (`should_lookUpTheExactChangeRefBeforeResolvingTheUser_when_granting`, `should_primeThenLockThenInsertThenAudit_when_granting`).
- **Same population and lock as assign and revoke (ADR-0018 D6):** the service calls the shared `AdminEquivalentRoles.resolve` and `buildAscendingAdminEquivalentLockSet` (D-15) instead of re-deriving them. The precedent check uses `callerQualifyingIds()`, a subset of the lock set. A holder of a role with one dangerous permission does not block recovery (`should_grant_when_onlyHolderIsOfARoleThatCannotPassTheCallerGate`).
- **Audit groups:** the grant row is Group A, written inside the grant transaction, and rethrows (`RbacAuthEventAdapter.recordBreakGlassGranted`). A refusal row uses `REQUIRES_NEW` + `saveAndFlush` and never reaches the retry buffer (D-35). The GRANTED page and then the cache eviction run after commit (D-31). A failed atomic audit raises no GRANTED page (`should_neverAlertGranted_when_theAtomicAuditWriteFails`).
- **RC-54(a):** `refuseInvalidArgument()` takes no arguments, so a rejected value cannot reach the row, the page or a log line. The IT checks this against real MySQL with the padded `PAD-000n` value, both in the metadata and in the captured log.
- **Packaging:** `application-break-glass.yml` sets `web-application-type: none` and `flyway.enabled: false`. The guard checks both the property and the actual context type, and it is `@Lazy(false)`. `BreakGlassContextSmokeTest` boots the real context with the servlet override and with lazy initialisation. `DevDataInitializerTest.should_notOverlapTheBreakGlassProfile` evaluates the real profile expression.
- **Replay lookup:** bound parameter, exact match on the unquoted JSON value, global scope (D-28), bounded by the `event_type` index prefix. `should_matchOnlyTheExactChangeRef_when_lookupGetsWildcardOrQuoteCharacters` covers `%`, a quote injection and lower case.

Good decisions:
- A refusal returns an outcome instead of throwing (D-23), so the exit-code mapping lives in one enum.
- `BreakGlassExit` is a seam (D-25), so the runner can be tested without calling `System.exit`.
- `should_grantExactlyOnce_when_twoInvocationsRaceOnAZeroAdministratorTenant` would fail if the M11 lock were removed, because both inserts would commit. It is the real proof of T-007's locking claim, and it records the deadlock-victim outcome (D-30) instead of hiding it.
- `@ConditionalOnWebApplication` on the five web-only beans was found by booting the real non-web context (D-24), not by guessing.
- The change-ref pattern is ASCII-only, and the parameterised tests include a non-ASCII digit case.

## Findings

### [LOW] L-1: A lost break-glass refusal row was logged without its cause or identifiers

`nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java` (`recordBreakGlassRefused`).
- The catch block logged `RBAC_AUDIT_WRITE_LOST` with only `tenantId` and a fixed message, dropping the exception and the `reason`, `targetUserId` and `changeRef`. The older Group B path in the same class (`recordDenied`) passes the exception and the identifiers.
- Runbook §11.4 relies on that line as evidence when a refusal row is missing. `tenantId` is null for the replay and `USER_NOT_FOUND` refusals, so the line carried no identifier at all. The `nexus.rbac.audit_write_failed` counter is incremented in a process that is never scraped (D-18), so the log line is the only signal.
- **Fix:** log the cause and the event's fields. This is safe for RC-54(a), because `refuseInvalidArgument()` passes all three identifiers as null. Add a unit test that asserts the throwable and the key-values.

### [LOW] L-2: The "revoke races the CLI" IT passes whatever the interleaving, so it does not prove serialization

`nexus-backend/src/test/java/com/example/nexus/rbac/BreakGlassAdminIT.java` (TS-6 revoke race).
- The tenant starts with one administrator, and the revoke of that administrator is always refused by the last-admin lockout. The CLI therefore always returns `TENANT_HAS_ADMIN`, whether or not the transactions overlap and whether or not the service takes the M11 lock.
- What the test covers is "no hang and no deadlock between revoke and the CLI", which is worth keeping. The locking itself is proven only by the two-CLI race test.
- **Fix:** make the blocking observable with a held lock and a timeout, or rename the test to say what it proves and point to `should_grantExactlyOnce_...` for serialization.

### Nits

- **N-1: Profile name written two ways.** `BreakGlassAdminRunner`, `BreakGlassWebContextGuard` and `SpringBreakGlassExit` used the literal `@Profile("break-glass")`; `BootstrapAdminService` and both adapters use `Profiles.BREAK_GLASS`. **Fix:** use the constant everywhere.
- **N-2: Duplicated after-commit helper.** `BootstrapAdminService.afterCommit` (`:181`) copies `RoleAssignmentService.registerPostCommitSideEffects` (`:1346`) line for line, including the inline fallback when no synchronization is active. **Fix:** make the latter static and package-private and share it.
- **N-3: The alert outcome is a string, not a type.** `BreakGlassAlert` (`rbac/application/port/out/BreakGlassAlert.java:14-19`) models `outcome` as `String` with three constants, so nothing stops a caller passing another string to the page. **Fix:** a nested `enum Outcome { GRANTED, REFUSED, ERROR }`.
- **N-4: A test name claims a wait it does not check.** `BreakGlassAdminRunnerTest.should_decideBeforeWaitingAndWaitBeforeExit` verifies only that the grant happens before `exit`; `should_waitOneFlushIntervalBeforeExiting` already covers the wait. **Fix:** rename it to `should_decideBeforeExiting`.
- **N-5: A guard regression in the smoke test would crash the test JVM instead of failing an assertion.** `BreakGlassContextSmokeTest`'s two builder-started contexts do not get the class-level `@MockitoBean BreakGlassExit` or the `0s` flush interval. If the guard ever stopped throwing, the real `SpringBreakGlassExit` would sleep 15 s and call `System.exit(2)` inside the Surefire fork. **Fix:** pass `log-flush-interval=0s` and add a `@Primary` no-op `BreakGlassExit` source to both builders.

### Not raised (checked, fine as is)

- **The IT comment on the replay row** says it has a null `tenant_id`, but the IT query does not assert it. The unit test `BootstrapAdminServiceTest` does.
- **An inactive administrator still counts as an administrator.** `lockActiveAssignmentHoldersByRoles` does not filter on user status, so a tenant whose only administrator is deactivated is refused with exit 5. This is the shipped ADR-0018 population that the lockout also uses (design §7.2 "Precondition", A-6); T-019 revisits it.
- **The `REQUIRES_NEW` refusal write runs while the `TENANT_HAS_ADMIN` path holds the M11 `FOR UPDATE` rows.** It inserts only into `auth_events`, which has no FK, so the two cannot wait on each other. It needs a second pool connection, which the default Hikari pool has for a single-invocation process.
- **`BootstrapAdminService` has 6 dependencies,** above the skill's limit of 4. Accepted by the story owner with D-31.

## Fix status (2026-10-15, branch `feature/US-018/M5`)

- **L-1 fixed.** `recordBreakGlassRefused` logs the cause plus `tenantId`, `targetUserId`, `changeRef` and `reason`. New unit test `RbacAuthEventAdapterTest.should_logCauseAndIdentifiers_when_refusalWriteFails`.
- **L-2 fixed by renaming.** The test is now `should_neitherDeadlockNorHang_when_revokeOfLastAdminRacesTheCli`, and its Javadoc points to the two-invocation race test as the proof of the set lock. The atomic rollback is now also proven end to end by `should_leaveNoAdministratorAndNoPage_when_theAtomicSuccessAuditWriteFails` (test audit gap 1).
- **N-1 fixed.** All break-glass beans use `Profiles.BREAK_GLASS`.
- **N-4 fixed.** Renamed to `should_decideBeforeExiting`.
- **N-5 fixed.** Both builder-started contexts pass `log-flush-interval=0s` and add a `@Primary` no-op `BreakGlassExit` (`NoExit`).
- **N-2 not changed.** Sharing the helper means changing `RoleAssignmentService`, which is outside M5's scope; the duplicate is 12 lines with identical behaviour.
- **N-3 not changed.** Changing the record's type ripples through the port, the adapter and their tests for a value only this module constructs; the three constants are the only values used.
