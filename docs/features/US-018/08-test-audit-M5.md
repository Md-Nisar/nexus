# Coverage audit for Tasks T-007 and T-008 (US-018, M5 - A7 break-glass first-administrator CLI)

Branch `feature/US-018/M5`, audited diff `origin/main...HEAD` (`nexus-backend`) plus the uncommitted `BreakGlassAdminIT` change. Accepted deviations D-15..D-37 (`09-technical.md` section 13) are treated as the spec where they amend the task text. No production code was edited.

## Existing tests

- `rbac/application/BootstrapAdminServiceTest` (28): each refusal writes one FAILURE row, alerts and returns its exit code (user missing 3, not ACTIVE 3, no `TENANT_ADMIN` 4, role not system 4, role of another tenant 4, has admin 5, holder of the three dangerous permissions 5); a holder of a role that cannot pass the caller gate does not block the grant (A-6 population); grant inserts with `assigned_by = target`, SUCCESS row with `changeRef` and no reason; lock over ascending admin-defining ids plus `TENANT_ADMIN`; `InOrder` prime, lock, insert, audit; no insert before the lock on a refusal; cache evicted after commit only on grant (D-31); alert only after commit and never when the atomic audit write fails; no `assign()` by construction (EC2); exit 6 before any user lookup, lookup uses the exact reference (D-27); `INVALID_ARGUMENT` row carries nothing else.
- `rbac/interfaces/cli/BreakGlassAdminRunnerTest` (11 methods, several parameterised): every outcome maps to its exit code (0, 2 to 6); exit 1 with a page carrying the identifiers after validation and none before it (D-26, D-36); missing or malformed arguments and non-canonical references exit 2 without granting (RC-47 shapes); canonical references accepted; no raw argument reaches the audit or alert port (L-6); the runner never touches the alert port for an invalid argument; waits exactly one flush interval and decides before the wait, waits before exit (RC-37.4).
- `rbac/interfaces/cli/BreakGlassWebContextGuardTest` (6): throws and pages for any web type other than `none`, and for unset; passes for `none`; throws for a servlet or web-server context even when the property reads `none` (D-33); `@Lazy(false)`.
- `BreakGlassContextSmokeTest` (3, H2, no Docker): context refreshes without a web application under `break-glass`; refresh fails as a servlet application; refresh still fails with `spring.main.lazy-initialization=true` (D-29).
- `architecture/HexagonalArchitectureTest` rules plus `BreakGlassContainmentRuleFixturesTest` (7) and `BreakGlassCliProfileRuleFixturesTest` (9): REST class calling the service fails; field-only reference fails; unrelated class passes; subclass outside the cli fails and the exact class is exempt (D-34); nothing outside the cli depends on it; every cli bean is `@Profile("break-glass")` exactly (missing, extra, negated, meta-annotated all fail); the service and the break-glass-only adapters are profile-gated (D-32).
- `identity/infrastructure/seed/DevDataInitializerTest.should_notOverlapTheBreakGlassProfile` (T-008 (e)).
- `identity/infrastructure/audit/BreakGlassAlertAdapterTest` (4): one ERROR with marker and all fields, reason on a refusal, target, change reference and tenant omitted when null, marker as structured key-value (D-18).
- `identity/infrastructure/audit/BreakGlassGrantLookupAdapterTest` (3): hit, miss, exact reference passed as the bound parameter.
- `identity/infrastructure/audit/RbacAuthEventAdapterTest` (+3): atomic SUCCESS row with `actorType` and `changeRef`; failure of the atomic write propagates; refusal written independently with its reason (D-19, D-35). Also `AuthEventTest`, `AuthEventTypeTest` (27 constants), `SecureEventServiceTest` (+1, `recordEventInNewTransactionOrThrow`), `JpaUserDirectoryAdapterTest` (+1), `TenantIsolationArchitectureTest` (D-28 allowlist entry).
- `rbac/BreakGlassAdminIT` (15, Testcontainers MySQL, profiles `test` + `break-glass`, D-37): see the map below.

## Coverage map

### T-007 acceptance criteria

| Criterion | Proven by |
|---|---|
| (a) grant on a zero-admin tenant: `user_roles` row, `assigned_by = target`, SUCCESS audit row with `{actorType, changeRef}`, page | IT `should_grantTenantAdminWithAssignedByTargetAuditAndPage_when_tenantHasZeroAdministrators`; unit `should_grantWithAssignedByTarget_...`, `should_writeSuccessAuditWithChangeRefAndNoReason_when_granted` |
| (a) order: resolve user, resolve system role, prime, lock, precondition under lock, insert, audit; alert after commit | unit `should_primeThenLockThenInsertThenAudit_when_granting`, `should_lockSetOverAscendingAdminDefiningIdsPlusTenantAdmin_...`, `should_notInsertBeforeLock_...`, `should_alertGrantedOnlyAfterCommit_...` |
| (a) missing or non-ACTIVE target: exit 3 | unit `...Exit3...` (2); IT `should_refuseWithExit3_when_targetUserIsNotActive`, `should_refuseWithExit3AndNullTenantRow_when_targetUserDoesNotExist` |
| (a) no system `TENANT_ADMIN`: exit 4 | unit (3, incl. other-tenant role); IT `should_refuseWithExit4_when_tenantHasNoSeededTenantAdminRole`, `should_refuseWithExit4_when_theTenantAdminRoleIsNotASystemRole` |
| (a) tenant already has an administrator: exit 5, checked under the lock | unit (3); IT `should_refuseWithExit5_when_anAdministratorAlreadyExists`; ordering by `should_notInsertBeforeLock_...` |
| (a) never calls `RoleAssignmentService.assign()` (EC2) | unit `should_notCallAssignOnRoleAssignmentService_by_construction`; ArchUnit containment |
| (b) each refusal: own-transaction FAILURE row with reason, and a page | unit per refusal; `RbacAuthEventAdapterTest` independent write; IT per refusal asserts row and page |
| (b) caller-qualifying population before M3 (A-6) | unit `should_grant_when_onlyHolderIsOfARoleThatCannotPassTheCallerGate`, `should_refuseWithExit5_when_holderOfAllThreeDangerousPermissionsRoleExists` |
| (c) ERROR `RBAC_BREAK_GLASS_USED` with the five fields on every invocation | `BreakGlassAlertAdapterTest` (4); IT `pagedMessages()` assertions in grant and refusal cases |
| (d) `AuthEventType.ROLE_BREAK_GLASS_GRANT`, not PRIORITY | `AuthEventTypeTest`, `AuthEventTest` |
| (e) containment: only `rbac.interfaces.cli` may call the service | `HexagonalArchitectureTest` rules; `BreakGlassContainmentRuleFixturesTest` (rule is proven to fail on a REST caller) |
| Outcome value carries the exit code | `BreakGlassAdminRunnerTest.should_mapEveryDocumentedExitCode`; IT `outcome.exitCode()` |
| IT: revoke of the last admin racing the CLI, exactly one outcome | IT `should_neitherDeadlockNorHang_when_revokeOfLastAdminRacesTheCli` (no deadlock or hang; it passes whatever the interleaving, so set-lock serialization is proven by `should_grantExactlyOnce_when_twoInvocationsRaceOnAZeroAdministratorTenant`, code review L-2) |
| IT: re-run after success is refused (idempotency) | IT `should_refuseWithExit5AndAuditAndPage_when_rerunAfterSuccess` (exit 5 on a different reference, D-27) |
| D-30 concurrent first-grant: one grant, loser exits 1 and pages | IT `should_grantExactlyOnce_when_twoInvocationsRaceOnAZeroAdministratorTenant` |
| D-31 permission cache evicted after commit | unit `should_evictNewAdministratorsCachedPermissionsAfterCommit_when_granted`, `should_notEvictCache_...` (unit only, gap 3, accepted) |

### T-008 acceptance criteria

| Criterion | Proven by |
|---|---|
| (a) `ApplicationRunner`, `@Profile("break-glass")`, exit codes 0, 2 to 6 through `SpringApplication.exit` | `BreakGlassAdminRunnerTest`; profile rule in ArchUnit; `SpringBreakGlassExit` is the bean behind the `BreakGlassExit` seam (D-25) |
| (a) waits one flush interval before exit (RC-37.4) | `should_waitOneFlushIntervalBeforeExiting`, `should_decideBeforeExiting` |
| (a) `application-break-glass.yml`: `web-application-type=none`, Flyway off | `none` proven by `BreakGlassContextSmokeTest`; Flyway off, `none` and the 15 s flush pinned by `BreakGlassProfileConfigTest` (gap 2) |
| (b) web-context guard fails the refresh before the server starts (RC-37.6, RC-50(d)) | `BreakGlassWebContextGuardTest`, `BreakGlassContextSmokeTest` (3 cases incl. lazy-init) |
| (c) `--target-user-id` must be a UUID: exit 2 | runner unit; IT `should_exit2_when_targetUserIdIsNotAUuid` |
| (c) `--change-ref` canonical pattern `^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$`, no leading zeros | runner unit `should_exit2_when_changeRefIsNotTheCanonicalTicketShape`, `should_accept_when_...`; IT padded case |
| (c) invalid argument: FAILURE row, reason `INVALID_ARGUMENT`, null `tenant_id`, metadata without the value; page omits `targetUserId` and `changeRef` | unit `should_writeInvalidArgumentRowWithNothingElse_...`, `should_passNoRawArgumentToAuditOrAlertPort_...`; IT padded case asserts null tenant, no value in the row, and no value in any log event |
| (d) replay refusal exit 6, global, SUCCESS only, before the user lookup, bound parameter | unit `should_refuseWithExit6BeforeAnyUserLookup_...`, `should_lookUpTheExactChangeRefBeforeResolvingTheUser_...`; adapter test (bound parameter); IT `should_refuseWithExit6AuditedAndPaged_when_exactChangeRefWasUsedOnASuccessfulGrant`, `should_refuseWithExit6_when_changeRefWasUsedOnASuccessfulGrantInAnotherTenant` (global), plus the two ITs added below |
| (e) every cli bean gated to `break-glass`; `DevDataInitializer` does not overlap | `BreakGlassCliProfileRuleFixturesTest`, `DevDataInitializerTest.should_notOverlapTheBreakGlassProfile` |

### Threat-model controls

| Control | Proven by |
|---|---|
| RC-37.1 / T-S9 requester spoofing: one-shot, zero-admin precondition under the lock | exit 5 tests; race ITs |
| RC-37.2 / RC-47 / T-S11 replay and injection: global, exact, bound, SUCCESS only | exit 6 tests; added `should_matchOnlyTheExactChangeRef_...` and `should_grantWithTheSameChangeRef_...`; padded-replay IT (asserts "never grants", exit 2, per the `03b` note on RC-47) |
| RC-37.3 / T-R14 attribution via `changeRef` in the row and page | grant IT (row and page carry `changeRef`); the Kubernetes audit-log sign-off is an Ops merge-checklist item, not testable here |
| RC-37.4 / T-R15 page capture | flush-wait unit tests; the staging drill is an Ops checklist item |
| RC-37.5 reviewer join: `assigned_by = target`, `actorType = BREAK_GLASS_CLI` | grant IT |
| RC-37.6 / RC-50(d) / L-1 web-context guard | guard test, smoke test |
| RC-54(a) / L-6 no raw argument in audit or logs | padded IT, runner unit tests |
| L-2, M-1 (D-32, D-34) containment and profile gating of the service itself | ArchUnit rules and their fixtures |
| L-3 (D-35) refusal row never reaches the retry buffer | `SecureEventServiceTest`, `RbacAuthEventAdapterTest` |
| L-4 (D-36) exit-1 page identifiers | `should_exit1AndPageWithTheValidatedIdentifiers_...`, `should_exit1AndPageWithoutIdentifiers_...` |
| EC2 structural | no `assign()` call; ArchUnit |

## Gaps identified

- [MED] A change reference on a REFUSED attempt must not be burned: only a SUCCESS row counts for replay (T-008 (d) filters on `outcome = 'SUCCESS'`; nothing proved it end to end) - added in `BreakGlassAdminIT`.
- [MED] Replay lookup exactness: LIKE wildcard (`IT-%`), quote injection and a lowercase variant must all miss; only the exact string hits (T-S11, bound parameter, unquoted compare) - added in `BreakGlassAdminIT`.
- [MED, closed] **Gap 1: real rollback of the atomic grant.** The unit test proved only that the alert is not sent when the SUCCESS audit write throws; no IT proved the `user_roles` insert rolls back with it (the FR-A7 "atomically audited" claim, T-007 (a)). Added `BreakGlassAdminIT.should_leaveNoAdministratorAndNoPage_when_theAtomicSuccessAuditWriteFails`: a `@MockitoSpyBean RbacAuditPort` throws on `recordBreakGlassGranted`, and the test asserts the exception propagates (the runner maps it to exit 1), no active `TENANT_ADMIN` holder, no audit row, no page, and the reference is not burned.
- [LOW, closed] **Gap 2: `application-break-glass.yml` values were not asserted.** `BreakGlassAdminIT` forces `spring.flyway.enabled=true` (D-37) and the smoke test supplies `web-application-type` itself, so a deleted `flyway.enabled: false` or a changed 15 s flush default would have passed. Added `BreakGlassProfileConfigTest.should_disableFlywayAndWebAndWaitFifteenSeconds_when_breakGlassProfileFileIsLoaded` (loads the YAML with `YamlPropertySourceLoader`).
- [LOW, open, accepted] **Gap 3: D-31 cache eviction is unit-level only.** Left at unit level: the eviction runs after commit through the shared Redis adapter, which already has its own IT coverage, never throws, and fails closed (the new administrator keeps the empty set until the TTL). Proposed: `BreakGlassAdminIT.should_evictTheNewAdministratorsCachedPermissions_when_granted` (seed a cached permission set for the target, grant, assert the cache entry is gone).

None of the gaps was a defect in the shipped behaviour; the new tests passed on first run.

## Tests added

- `BreakGlassAdminIT.should_grantWithTheSameChangeRef_when_itWasOnlyOnRefusedAttempts` (exit 4 refusal, role seeded, same reference then grants with exit 0 and one administrator).
- `BreakGlassAdminIT.should_matchOnlyTheExactChangeRef_when_lookupGetsWildcardOrQuoteCharacters` (exact reference true; `IT-%`, `<ref>' OR '1'='1` and the lowercase reference false; also adds an autowired `BreakGlassGrantLookupPort` to the IT).

- `BreakGlassAdminIT.should_leaveNoAdministratorAndNoPage_when_theAtomicSuccessAuditWriteFails` (gap 1; adds a `@MockitoSpyBean RbacAuditPort`, reset before each test).
- `BreakGlassProfileConfigTest.should_disableFlywayAndWebAndWaitFifteenSeconds_when_breakGlassProfileFileIsLoaded` (gap 2, unit).

## Run results

- Added tests: `BreakGlassAdminIT` 16/16 and `BreakGlassProfileConfigTest` 1/1 green on 2026-10-15.
- Last full `./mvnw verify` before the two additions: 2004 unit tests (1 skipped), 475 IT, 0 failures, 0 errors; SpotBugs 0; JaCoCo gate met.
- Full `verify` on JDK 25 with Docker after all M5 fixes (2026-10-15): 2006 unit (1 skipped), 478 IT, 0 failures, Checkstyle 0, SpotBugs 0, JaCoCo met, BUILD SUCCESS.
- Frontend `npm run test:ci`: not run, the M5 diff has no frontend change.

## Load scenarios

None added. The CLI runs once per recovery, by hand, and exposes no endpoint, so the more-than-10-RPS rule does not apply.

## Flaky tests

None observed. Points to watch, none changed by this audit:
- `should_neitherDeadlockNorHang_when_revokeOfLastAdminRacesTheCli` and `should_grantExactlyOnce_when_twoInvocationsRaceOnAZeroAdministratorTenant` are concurrent by design; the assertions are on the invariant (exactly one outcome, exactly one grant), not on which thread wins, which is the right shape. D-30 means the loser is a deadlock victim, so the assertion must stay tolerant of exit 1 or 5 for the loser.
- `BreakGlassAdminRunnerTest.should_waitOneFlushIntervalBeforeExiting` really sleeps 200 ms (real wall clock, lower bound 190 ms). It cannot flake early because the runner sleeps at least the interval; it is within the 1 s budget but is the one timing-based test in the diff. The other runner tests use a 5 ms interval.
- The two new ITs use `uniqueRef()` and do not depend on time or order.

## Not covered, reported only

- RC-37.3 (Kubernetes audit logging), RC-37.4 (page capture from a Job), the daily reconciliation alert and RES-6 retention are Ops merge-checklist items in `04-tasks.md`, not testable in this repo.
- Gap 3 above (D-31 eviction end to end) stays at unit level, as accepted.
