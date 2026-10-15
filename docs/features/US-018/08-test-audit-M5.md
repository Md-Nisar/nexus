# Coverage audit for Tasks T-007 and T-008 (US-018, M5: A7 break-glass CLI)

Branch `ccr-047fcb60-fqvz6w`, commits `e43b347`, `4dee024`, `d5b50c8`, `70ea2f1`. Audited against `03-design.md` §7, `04-tasks.md` T-007/T-008, the A7 rows of `03b-threat-model.md`, `06-code-review-M5-T007.md`, `06-code-review-M5-T008.md` and `07-security-review-M5.md`. Production code was not changed; only tests and this document. Committed as `0c66f99`.

## Existing tests (before this audit)

| File | Covers |
|---|---|
| `rbac/application/BootstrapAdminServiceTest` (42) | every refusal (exits 3, 4, 5, 6, 2), grant path, `assigned_by = target`, lock before check before insert, ascending lock set, SUCCESS row inside the transaction, GRANTED page after commit and best effort, refusal rows only after the grant transaction ended, exits 7 and 1 (lock failure, other failure, failed SUCCESS write, failed commit, TENANT_HAS_ADMIN plus failed commit gives one row), lost refusal row still pages, `Error` propagates, null arguments, `recordInvalidArgument()` takes no parameter |
| `rbac/interfaces/cli/BreakGlassAdminRunnerTest` (40) | exit code per `BreakGlassRefusalReason` (pinned table), exit 1 reset per run, UUID canonical-form and ChangeRef validation, missing and repeated options, no argument echo in alert or log, web-context guard (servlet, reactive, none, flush wait before throw), flush wait and interrupt handling, raw YAML pin of the profile file |
| `rbac/interfaces/cli/BreakGlassCliProfileRuleTest` (5), `BreakGlassNoAssignOrRevokeRuleTest` (3), `rbac/interfaces/rest/BootstrapAdminContainmentRuleTest` (2) | the three EC2 / profile ArchUnit rules with failing fixtures |
| `identity/infrastructure/persistence/BreakGlassGrantLookupAdapterTest` (4) | adapter mapping; query text is global, SUCCESS-only, bound parameter, no lock (string inspection only) |
| `identity/infrastructure/seed/DevDataInitializerTest` (+2 for M5) | `dev & !break-glass` expression evaluated for `break-glass` and `dev,break-glass` |
| `ChangeRefTest` (20), `BreakGlassAlertAdapterTest` (4), `RbacAuthEventAdapterTest`, `AuthEventTypeTest` | canonical pattern, page fields, audit rows |
| `rbac/BreakGlassAdminIT` (17, Testcontainers MySQL, runs as the container user `test`) | grant, exits 2 to 7, re-run, rollback on failed SUCCESS write, replay same and other tenant, padded replay value-free, deadlock exit 7 via trigger, servlet guard before the web server starts, `SpringApplication.exit` of a non-web context, two races |

## Coverage matrix: acceptance criteria and mitigated A7 threats

Legend: U = unit, A = ArchUnit, IT = integration, **new** = added by this audit.

| Requirement | Covered by |
|---|---|
| FR-A7.a/b/c grant on zero-admin tenant, `assigned_by = target`, SUCCESS row atomic, page after commit | U (service), IT `should_grantTenantAdmin_...`, IT rollback test |
| Refusals 3/4/5 audited and paged | U, IT (`exit5`, `exit4`, `exit3` x3 statuses, unknown user) |
| Precondition counted under the set lock, same population as ADR-0018 | U (ordering, named admin, custom full-admin role, single-permission role); **new** IT against real data: custom role with all three dangerous permissions refuses, two of three grants, other tenant's admin does not block, LOCKED admin refuses |
| Non-system `TENANT_ADMIN` look-alike not a grant target (security review, Role resolution) | U; **new** IT (exit 4, nothing granted) |
| Idempotency (re-run exit 5) | IT |
| Last-admin revoke vs CLI race | IT (no deadlock/500; Javadoc already states it does not prove lock order) |
| Two CLIs race on one tenant | IT (exit sets `{0,5}` or `{0,7}`, one row) |
| Exit 7 and exit 1, audited and paged after rollback | U, IT (trigger-driven 1213 and failed SUCCESS write) |
| **T-S9 / RC-37.2 replay, exit 6**, global | U, IT same tenant, IT other tenant; **new** IT: FAILURE rows do not burn a reference (exit 3, fix, re-run same ref grants); exact-match only (prefix and superstring refs unaffected); **new** `BreakGlassGrantLookupIT` against MySQL: SUCCESS only, event type exact, case-sensitive, SQL/JSON syntax is data |
| **T-S11 / RC-47** canonical pattern, padded replay | `ChangeRefTest`, runner U, IT padded replay (exit 2, one value-free row, value absent from row and logs) |
| **RC-54(a) / L-6** no argument echo | U (captors, log scan), IT (row metadata exact, captured logs) |
| **RC-37.6 / RC-50(d)** web-context guard | U (servlet, reactive, none, flush wait), IT in-process context (refresh fails, web server never initialized); **new** real-JVM test: exit 1, "refusing to start" in output, nothing granted |
| **T-R15 / RC-37.4** flush wait before exit and before the guard throws | U (50 ms real wait, lower bound only). Drill and daily reconciliation are merge-checklist items, not tests |
| Profile config: `web-application-type=none`, Flyway off, pool 4, flush-wait default | raw YAML pin (U); **new** `BreakGlassProfileConfigTest`: values as Spring's config-data loader resolves them, default 15 s, `NEXUS_RBAC_BREAK_GLASS_LOG_FLUSH_WAIT` override, no leakage into a non-break-glass profile |
| `NexusApplication.main` exit handling | **new** real child JVM (`java -cp` without test classes): exit 6 propagates through `System.exit(SpringApplication.exit(...))`, exit 0 on a grant, exit 1 on a failed refresh |
| Runs with the production credential `nexus_app` (design: "no grant change needed") | **new**: the child JVM tests connect as `nexus_app`; every other IT connects as the container user and cannot catch a missing grant (the `LastAdminLockoutIT` Javadoc names this risk) |
| Lost refusal row is signalled, not thrown, exit and page survive | U; **new** IT with a trigger rejecting FAILURE break-glass rows (exit 3, one page, `RBAC_AUDIT_WRITE_LOST`) |
| `DevDataInitializer` never active with `break-glass` | U (both profile combinations, both beans) |
| Containment: service only from CLI; CLI never calls assign/revoke; CLI beans `@Profile("break-glass")` only | A (3 rules with failing fixtures, one with an explicit non-vacuity test) |
| **L-3** the global lookup port and query contained | **new** A rules, section below |

## Gaps identified

- [HIGH] The break-glass flow had never run as `nexus_app` (the credential the design says it uses with no grant change) and `NexusApplication.main`'s exit handling was untested (excluded from JaCoCo, `SpringApplication.exit` only called from a test). Added real child-JVM tests in `BreakGlassAdminIT`.
- [HIGH] Lookup semantics were proven only by string inspection of the query. A FAILURE row also carries the `changeRef`; nothing proved it does not burn the approval, nor exactness (case, prefix) against MySQL's `utf8mb4_0900_ai_ci` table collation. Added `BreakGlassGrantLookupIT` (5) and two `BreakGlassAdminIT` cases. Result: the comparison is case-sensitive and exact today.
- [HIGH] L-3: the allowlisted global lookup was not contained. Added two ArchUnit rules and fixture tests.
- [MED] Zero-admin precondition against real rows: only unit-mocked for custom roles; no IT for cross-tenant isolation, partial dangerous-permission role, LOCKED holder, non-system look-alike role. Added 6 ITs.
- [MED] Resolved profile configuration (flush-wait default and env override, no leakage into other profiles) was only a raw-YAML pin. Added `BreakGlassProfileConfigTest` (3).
- [MED] Refusal-row write failure (`RBAC_AUDIT_WRITE_LOST`) only unit-mocked. Added an IT on real MySQL.
- [MED] M-1 / O-7 (DISABLED sole administrator) had no test of the current behaviour. Added a characterization IT, clearly named `..._pendingO7Decision`.
- [LOW] ITs lacked a LOCKED-holder case (stays counted under either O-7 option). Added.

## Tests added

`architecture/BreakGlassLookupContainmentRuleTest` (6): `should_failPortRule_when_anotherClassHoldsThePort`, `..._anotherClassImplementsThePort`, `should_passPortRule_when_onlyTheServiceAndItsAdapterTouchThePort`, `should_failQueryRule_when_anotherClassCallsTheGlobalQueryDirectly`, `should_passQueryRule_when_anotherClassCallsADifferentRepositoryMethod`, `should_passQueryRule_when_onlyTheAdapterCallsTheGlobalQuery`.

`rbac/interfaces/cli/BreakGlassProfileConfigTest` (3): `should_resolveNonWebNoFlywayAndDefaultFlushWait_when_breakGlassProfileActive`, `should_takeTheEnvironmentOverrideForTheFlushWait_when_breakGlassProfileActive`, `should_notApplyAnyBreakGlassSetting_when_breakGlassProfileInactive`.

`identity/infrastructure/persistence/BreakGlassGrantLookupIT` (5): `should_findTheReference_when_aSuccessGrantRowInAnyTenantCarriesIt`, `should_notFindTheReference_when_onlyAFailureRowCarriesIt`, `should_notFindTheReference_when_anotherEventTypeCarriesItInMetadata`, `should_matchExactly_notByPrefixSuperstringOrCase`, `should_treatTheReferenceAsDataOnly_when_itCarriesSqlOrJsonSyntax`.

`rbac/BreakGlassAdminIT` (+12, now 29): `should_grantWithTheSameChangeRef_when_theEarlierAttemptLeftOnlyAFailureRow`, `should_grantOtherReferences_andRefuseOnlyTheIdenticalOne_when_similarReferenceWasUsed`, `should_grantInTenantB_when_onlyTenantAHasAnAdministrator`, `should_refuseWithExit5_when_aCustomRoleCarryingAllThreeDangerousPermissionsIsHeld`, `should_grant_when_theOnlyHeldCustomRoleCarriesTwoOfTheThreeDangerousPermissions`, `should_refuseWithExit4_when_theTenantAdminRoleIsNotASystemRole`, `should_refuseWithExit5_when_theSoleAdministratorIsLocked`, `should_refuseWithExit5_when_theSoleAdministratorIsDisabled_pendingO7Decision`, `should_keepExitCodeAndPage_andLogWriteLost_when_theRefusalRowCannotBeWritten`, `should_exitProcessWith0_andGrant_when_mainRunsBreakGlassAsNexusApp`, `should_exitProcessWithTheRefusalCode_when_mainRunsAReplayedChangeRef`, `should_exitProcessWith1_andGrantNothing_when_mainRunsBreakGlassWithServletWebType`. Helper changes: shared `containerArgs`, `runMainInChildJvm`, `seedCustomRole`, `setUserStatus`, extra trigger drop in `@AfterEach`.

## L-3 implementation (security finding)

`ArchitectureRules` gains two rules, wired into `HexagonalArchitectureTest` (23 to 25 tests) next to the other US-018 rules, and referenced from the allowlist comment in `TenantIsolationArchitectureTest`:
- `BREAK_GLASS_GRANT_LOOKUP_PORT_IS_CONTAINED`: no class other than `BootstrapAdminService`, `BreakGlassGrantLookupAdapter` (and the port) depends on `BreakGlassGrantLookupPort`.
- `GLOBAL_BREAK_GLASS_REPLAY_QUERY_IS_CALLED_ONLY_BY_ITS_ADAPTER`: no class other than `BreakGlassGrantLookupAdapter` calls `JpaAuthEventRepository.existsSuccessfulBreakGlassGrantWithChangeRef` (closes the bypass of injecting the repository directly).
Tests are outside the production ArchUnit import (`DoNotIncludeTests`), which is how "and tests" is allowed. Both rules use `allowEmptyShould(true)` like their siblings; non-vacuity is shown by the failing fixtures in `BreakGlassLookupContainmentRuleTest`.

## Run results

`cd nexus-backend && sh ./mvnw -o verify` (JDK 25, Docker running, ITs included):

- Surefire: **2032 run, 0 failures, 0 errors, 1 skipped** (`JpaAuthEventAdapterFailurePathBenchmarkTest`, conditional skip, pre-existing and unrelated).
- Failsafe (Testcontainers MySQL and Redis): **497 run, 0 failures, 0 errors, 0 skipped**.
- JaCoCo: "All coverage checks have been met". SpotBugs: BugInstance size 0. Checkstyle passed. **BUILD SUCCESS**, 7 min 36 s.
- Frontend: not run; no frontend file is touched by M5 or this audit.

## Load scenarios

None. A7 is a CLI run by an operator (a handful of invocations a year), not an endpoint; the >10 RPS rule in `docs/TESTING.md` does not apply.

## Flaky tests

None found in the M5 set. Notes:
- `BreakGlassAdminRunnerTest#should_waitConfiguredFlushInterval_beforeThrowing_when_contextIsServletWeb` and the sibling flush-wait test use a real 50 ms `Thread.sleep` inside production code, asserting a lower bound only; it cannot fail on a slow machine.
- The race ITs depend on a `CyclicBarrier` but assert outcome sets, not timing. `should_grantExactlyOnce_when_twoCliRunsRaceOnTheSameZeroAdminTenant` accepts exit 5 or 7 for the loser by design.
- The three new child-JVM tests take about 30 s each (a full application boot, justified: they test the process boundary). They need `java.class.path` to list real entries; under Failsafe it does (verified). Run from an IDE launcher that uses an argfile or a manifest-only jar, they would need the entries expanded.
- Fresh random change references everywhere (`BGIT-`, `LKUP-`, random prefix), because `auth_events` is append-only and the lookup is global. The random values are never an assertion target.

## Residual gaps (not closed, with reason)

1. **O-7 / M-1 (DISABLED sole administrator) remains an owner decision.** The characterization IT pins exit 5 and will need a deliberate flip if option (b) is chosen. The pin is in the suite so the decision cannot be changed silently.
2. **Production bug candidates: none found.** Specifically verified against MySQL: lookup is case-sensitive and exact; SUCCESS-only; FAILURE rows do not block a retry.
3. `main`'s non-break-glass branch (the serving app must not call `System.exit`) is not tested: it cannot be asserted without starting a long-lived server in a child JVM, which would need a timing-based wait. It is exercised by every other boot, and the branch is a single `matchesProfiles` guard.
4. T-R15 page capture end to end (log shipper, `--rm`), RC-37.3 Kubernetes audit logging, the daily reconciliation alert, RES-6 retention, and the zero-admin recovery drill are operational merge-checklist items, not testable here.
5. T-S11's accepted race (two concurrent runs, one reference, two different zero-admin tenants) is accepted by Security and has no test by design.
6. Review findings L-1 (refusal page not best effort) and L-2 (target ACTIVE check outside the transaction) are open in production code; no test pins either, because a test would assert behaviour the reviewers asked to change.
7. A06 (OWASP dependency-check) is left to CI; not runnable offline.

## Files touched

Modified: `nexus-backend/src/test/java/com/example/nexus/architecture/ArchitectureRules.java`, `.../architecture/HexagonalArchitectureTest.java`, `.../architecture/TenantIsolationArchitectureTest.java` (comment only), `.../rbac/BreakGlassAdminIT.java`.
Created: `.../architecture/BreakGlassLookupContainmentRuleTest.java`, `.../identity/infrastructure/persistence/BreakGlassGrantLookupIT.java`, `.../rbac/interfaces/cli/BreakGlassProfileConfigTest.java`, `docs/features/US-018/08-test-audit-M5.md`.
