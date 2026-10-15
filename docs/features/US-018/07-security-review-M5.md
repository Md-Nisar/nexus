# Security Review: US-018 M5 (A7 break-glass first-administrator CLI, T-007 and T-008)

**Verdict: APPROVED.** Nothing Critical or High. The review raised 2 Medium and 4 Low findings; all six are fixed on `feature/US-018/M5` (see Fix status). The approval depends on these conditions:

1. **The environment items stay required before any production traffic**: RC-37.3 (Kubernetes API audit logging), the RC-37.4 staging drill, the daily reconciliation alert and RES-6 retention. No environment exists (Decision 2026-10-05), so they are deferred to the first deployment and tracked as P-3 to P-7 in `14-pending-items.md`, owned by the story owner.
2. **A06 is closed by CI.** The OWASP dependency-check could not run here (NVD 403), as for M6 and M7.

**Reviewed:** 2026-10-15, read-only, on `feature/US-018/M5` at `c1a6b38` (T-007, T-008 and D-31). Fixes landed in `4efdcd7` (code) and `99ff85a` (runbook); the fixed branch was reviewed against each finding and the full `verify` re-run.

## Verification run

- `./mvnw dependency:tree`: no pom or package changes in the diff. No `spring-webflux` or `reactor-netty` on the classpath (`reactor-core` comes only through the Redis client), which matters for the D-24 question below.
- `npm audit --omit=dev`: 7 issues (6 moderate, 1 high: `@angular/router`, SSR DoS, fixed in 22.2.3). All already exist on `main`; none come from M5. Out of scope, needs its own ticket.
- OWASP dependency-check: not run (NVD 403), left to CI.
- After the fixes, the full `verify` on JDK 25 with Docker, merged with `main` at `66a9a30`: 2004 unit (1 skipped), 475 IT, 0 failures, Checkstyle 0, SpotBugs 0, JaCoCo met.

## Findings

### [MEDIUM] M-1: `BootstrapAdminService` was a live bean in every serving JVM (OWASP A01, A04). **Fixed in `4efdcd7`.**

- **Where:** `rbac/application/BootstrapAdminService.java` (`@Service`, no `@Profile`); `BreakGlassGrantLookupAdapter` the same.
- **Issue:** only the beans in `rbac.interfaces.cli` were gated to the `break-glass` profile. The service that grants the administrator was created in every production pod, so the threat-model row "REST reaches BootstrapAdminService: ArchUnit containment plus profile gating" held only for the runner. Anything ArchUnit cannot see (`getBean` by name, reflection, a SpEL bean reference) could reach a working grant path. No SpEL is built from user input today; this needs a code change that gets past review.
- **Fix:** `@Profile(Profiles.BREAK_GLASS)` on `BootstrapAdminService`, `BreakGlassGrantLookupAdapter` and `BreakGlassAlertAdapter`. New ArchUnit rule `break_glass_only_beans_must_be_profile_gated_to_break_glass`, with negative fixtures. `NexusSmokeTest.should_notRegisterBreakGlassBeans_when_servingContextRuns` proves a servlet context has none of them. `BreakGlassAdminIT` now runs under `test,break-glass` with `web-application-type=none`.

### [MEDIUM] M-2: The runbook controls the accepted risks depend on had not landed (OWASP A04). **Fixed in `99ff85a`.**

- **Where:** M5 merge checklist in `04-tasks.md`.
- **Issue:** T-S9's "Low after RC-37" residual assumes requester verification against the contractual contact of record and a second Platform Security approver (RC-37.1). The accepted T-S11 replay TOCTOU is bounded only by the "one invocation at a time per reference" rule. Until US-012 runbook step 4 was replaced, the only recovery path was a manual SQL `INSERT` with no audit row and no page.
- **Fix:** `runbook.md` §11 (verify, approve, record; the Job spec; exit codes; post-run checks; daily reconciliation; drill). `docs/features/US-012/runbook.md` step 4 now points to §11 and says manual SQL is not a supported path. Story-owner decisions of 2026-10-15 are in the runbook: the second approver is the Platform Security on-call engineer, the Job keeps `ttlSecondsAfterFinished: 3600`, and the flush wait stays at 15 s.

### [LOW] L-1: The web-context guard could be skipped with lazy initialisation, and checked a property rather than the context (OWASP A05). **Fixed in `4efdcd7`.**

- **Where:** `rbac/interfaces/cli/BreakGlassWebContextGuard.java`.
- **Issue:** the guard was an `InitializingBean` nothing depended on. With `spring.main.lazy-initialization=true` it was never created, while the runner still was (Spring Boot fetches `ApplicationRunner` beans by type). With `web-application-type=servlet` as well, the CLI would run inside a serving process, which RC-37.6 forbids. Two misconfigurations or a deliberate operator were needed, and the HTTP side stays secured.
- **Fix:** the guard is `@Lazy(false)` and also fails when the context is a `WebApplicationContext` or `WebServerApplicationContext`, whatever the property says. Tests: context-type and not-lazy cases in `BreakGlassWebContextGuardTest`; a lazy-initialisation servlet case in `BreakGlassContextSmokeTest`.

### [LOW] L-2: The ArchUnit containment rules could be bypassed (OWASP A04). **Fixed in `4efdcd7`.**

- **Where:** `architecture/HexagonalArchitectureTest.java`.
- **Issue:** (a) `.areNotAssignableTo(BootstrapAdminService.class)` exempted every subclass, so a `@RestController` extending the service passed. (b) A non-bean helper in `rbac.interfaces.cli` could fetch the service from the context, and a controller depending only on the helper passed both rules.
- **Fix:** the exemption is the exact class (`doNotHaveFullyQualifiedName`); new rule `nothing_outside_the_cli_may_depend_on_it`. Negative fixtures cover both bypasses (`clifixture/CliHelperFixture`). M-1 also makes both harmless in a serving pod.

### [LOW] L-3: Refusal audit rows could go to the in-memory retry buffer and be lost when the CLI exits (OWASP A09). **Fixed in `4efdcd7`.**

- **Where:** `identity/infrastructure/audit/RbacAuthEventAdapter.recordBreakGlassRefused`, `identity/domain/AuthEventType.java`.
- **Issue:** `JpaAuthEventAdapter.record` catches `DataAccessException` and enqueues on the STANDARD lane, which drains every 10 s with no drain on exit. The CLI exits about 15 s after the write, so a buffered refusal row could vanish with no `RBAC_AUDIT_WRITE_LOST` line. The SUCCESS row was unaffected (`MANDATORY` + `saveAndFlush`, rethrows).
- **Fix:** new `SecureEventService.recordEventInNewTransactionOrThrow` (`REQUIRES_NEW`, `saveAndFlush`, never enqueues). On failure the adapter logs `RBAC_AUDIT_WRITE_LOST`, counts `nexus.rbac.audit_write_failed{operation=breakGlassRefused,mode=best_effort}` and does not throw. The `AuthEventType` comment is corrected.

### [LOW] L-4: The ERROR page carried no identifiers, so an ambiguous commit could not be correlated (OWASP A09). **Fixed in `4efdcd7`.**

- **Where:** `rbac/interfaces/cli/BreakGlassAdminRunner.java` (D-26).
- **Issue:** on a lost COMMIT acknowledgement the grant may persist while the runner exits 1 and pages ERROR with no tenant, target or reference.
- **Fix:** the exit-1 page carries `targetUserId` and `changeRef` once both have passed validation (D-36). A failure before validation still pages without identifiers, so RC-54(a) and L-6 (never echo a rejected value) hold. Both cases are tested in `BreakGlassAdminRunnerTest`.

## Focus areas

1. **D-24 (`@ConditionalOnWebApplication(SERVLET)` on `SecurityConfig` and the web filters): no fail-open.** The condition is true in every context that can serve HTTP: the embedded Tomcat context and the MockMvc / `@WebMvcTest` mock environment. `web-application-type=reactive` cannot serve anything without `spring-webflux` (no `HttpHandler`; the refresh fails). In `none` mode there is no server and no management child context. Tomcat opens connectors in `finishRefresh`, after the guard has run.
2. **Containment.** No HTTP path, `@Scheduled` job or other bean references `BootstrapAdminService`. The only other `ApplicationRunner` is `DevDataInitializer`; the only `@PreAuthorize` is `@RequiresPermission`'s static template. Activating `break-glass` in a serving pod fails closed: the profile forces `none`, the runner refuses (exit 2, audited and paged) and the pod crash-loops.
3. **Grant logic.** The tenant comes from the target user, never from input; `findRole` also requires `role.tenantId == tenantId`; the lock and insert use that tenant. A custom role named `TENANT_ADMIN` is refused (`NO_SYSTEM_ADMIN_ROLE`): clients cannot set the system flag, and `uq_roles_tenant_name` allows one such name per tenant. The zero-admin check runs on M10/M11 state after the `FOR UPDATE` lock. `assigned_by = target` is by design (Decision 10). D-30 (concurrent first grants deadlock; the loser rolls back, exit 1) is safe under REPEATABLE READ, the existing ADR-0018 assumption; accepted by the story owner.
4. **Replay check.** The value is bound (`:changeRef`). `metadata` is a JSON column written by Jackson; the reference pattern is ASCII and anchored, so there are no case, padding or Unicode variants. `auth_events` is append-only with no purge, so used references stay blocked. Exact matching (no wildcard, quote or case variant) is pinned by `BreakGlassAdminIT.should_matchOnlyTheExactChangeRef_when_lookupGetsWildcardOrQuoteCharacters`. The accepted T-S11 TOCTOU needs two concurrent operator runs in two different zero-admin tenants; the operator already holds `nexus_app` credentials, so this control targets honest mistakes. The D-28 tenant-isolation allowlist entry is signed off: it returns existence only, and the refusal row has a null tenant.
5. **Audit and alert integrity.** SUCCESS is atomic with the grant. The GRANTED page fires after commit; a crash between commit and the log line loses the page, and the daily reconciliation is the backstop (P-6). Invalid arguments leak nothing: `refuseInvalidArgument()` takes no arguments, and the row and page hold no identifiers. Only UUIDs, the pattern-checked reference and enum reasons reach logs; no PII. Full UUIDs in the page go against SECURITY.md §7 masking, which the threat model accepts and other RBAC logs share.
6. **D-31 (cache eviction after the grant): neutral to positive.** It runs after commit, never throws, and on failure the new administrator keeps the old empty set until the TTL (fail-closed). No epoch bump is needed: a grant only adds permissions.

## OWASP Top 10 checklist (SECURITY.md §12)

| Category | Result |
|---|---|
| A01 Broken access control | M-1, L-2 fixed. Containment is by profile and ArchUnit; no network entry point |
| A02 Cryptographic failures | No change |
| A03 Injection | Bound parameter; anchored ASCII pattern; no SpEL from input |
| A04 Insecure design | M-2 fixed (runbook); environment items deferred (P-3 to P-7) |
| A05 Security misconfiguration | L-1 fixed; the profile forces `web-application-type=none` and no Flyway |
| A06 Vulnerable components | No dependency change; dependency-check left to CI |
| A07 Identification and authentication | The target must exist and be ACTIVE; the operator's identity comes from the Kubernetes audit log (P-3) |
| A08 Software and data integrity | `auth_events` is append-only; the SUCCESS row is atomic with the grant |
| A09 Logging and monitoring | L-3, L-4 fixed; page on every outcome; daily reconciliation (P-6) |
| A10 SSRF | Not applicable |

## Residual risk

- **T-S9** (social engineering of the operator): Low once RC-37.1 is followed (runbook §11.2).
- **T-S11** (replay TOCTOU across tenants): accepted, bounded by one invocation at a time per reference.
- **D-30** (concurrent first grants in one tenant): accepted; relies on REPEATABLE READ.
- **Lost page after commit:** covered by the daily reconciliation alert, which is not live until the first deployment (P-6).
- **The Job's command override is untested** until the staging drill (P-7).

## Relevant files

All under `nexus-backend/src/`:
- `main/java/com/example/nexus/rbac/application/BootstrapAdminService.java`
- `main/java/com/example/nexus/rbac/interfaces/cli/BreakGlassAdminRunner.java`
- `main/java/com/example/nexus/rbac/interfaces/cli/BreakGlassWebContextGuard.java`
- `main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `main/java/com/example/nexus/identity/application/service/SecureEventService.java`
- `main/java/com/example/nexus/identity/domain/AuthEventType.java`
- `test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- `test/java/com/example/nexus/rbac/BreakGlassAdminIT.java`
