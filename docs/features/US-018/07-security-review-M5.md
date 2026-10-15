# Security Review: US-018 M5 (A7 break-glass first-administrator CLI)

**Verdict: APPROVED, with conditions.** No Blocker or High findings. There is 1 Medium and 3 Low findings, plus informational notes.

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 1 (M-1, the O-7 owner decision) |
| Low | 3 |

**Conditions for the M5 PR to merge:**
1. **O-7 / M-1 gets an owner decision.** The Architect and the Platform Security Owner either record it as a residual with an owner, or change the definition of "administrator". The decision must be in place before the M5 PR merges, not after.
2. **Every unticked item on the M5 merge checklist in `04-tasks.md` is closed.** These are RC-37.3 (Kubernetes audit logging), the RC-37.4 page-capture drill, the daily reconciliation alert, the RES-6 retention sign-off and the runbook content. These are the non-code half of the T-S9, T-R14 and T-R15 mitigations. The code half is verified below.
3. **A06 is closed by CI.** The OWASP dependency-check could not run here (see Verification).

**Scope:** commits `e43b347` (T-007), `4dee024` (T-007 fixes), `d5b50c8` (T-008) and `70ea2f1` (T-008 review fixes) on `ccr-047fcb60-fqvz6w`. Every changed `src/main` file was read in full at `70ea2f1`, along with the changed ArchUnit tests, `BreakGlassAdminIT`, `BreakGlassAdminRunnerTest` and `DevDataInitializerTest`. Cross-referenced against: `03-design.md` §7 and §16 item 6, `03b-threat-model.md` (M5 STRIDE row, T-S9, T-R14, T-R15, T-S11, RC-37, RC-47, RC-50(d), RC-54(a), L-6), ADR-0025, the `04-tasks.md` M5 section and O-7, `SECURITY.md` §3, §7 and §10, and `06-code-review-M5-T007.md` / `06-code-review-M5-T008.md`. This review modified no application code, test or config.

**Authorization, audit integrity, authentication-boundary and PII concerns were reviewed explicitly.** This milestone is a privileged authorization path: it grants `TENANT_ADMIN` with no authenticated caller. It also changes the configuration of the HTTP authentication chain (`SecurityConfig`). The concerns checked:
- containment of the unauthenticated grant
- the zero-administrator predicate and the set lock
- audit atomicity and durability
- alert behaviour
- argument handling and the absence of argument echo (L-6)
- exit-code fidelity
- the web-context guard
- profile isolation (`DevDataInitializer`)
- the break-glass profile configuration
- the cross-tenant replay lookup
- whether HTTP security can be absent in a serving process

There is no cryptography in this diff. There are no credentials in this diff: the profile reuses the service's `nexus_app` datasource configuration, and nothing is hardcoded.

---

## Verification run

| Check | Result |
|---|---|
| Unit and architecture tests, offline (`mvnw -o test`, jacoco/spotbugs/checkstyle skipped): `BootstrapAdminServiceTest` (42), `BreakGlassAdminRunnerTest` (40), `BreakGlassCliProfileRuleTest` (5), `BreakGlassNoAssignOrRevokeRuleTest` (3), `BootstrapAdminContainmentRuleTest` (2), `BreakGlassAlertAdapterTest` (4), `RbacAuthEventAdapterTest` (56), `BreakGlassGrantLookupAdapterTest` (4), `DevDataInitializerTest` (7), `ChangeRefTest` (20), `TenantIsolationArchitectureTest` (1), `HexagonalArchitectureTest` (23), `SecurityConfigWebTest` (18), `AuthEventTypeTest` (66), `SecureEventServiceTest` (22) | **313 run, 0 failures, 0 errors** |
| `BreakGlassAdminIT` (Testcontainers MySQL, Docker available): `mvnw -o verify -Dit.test=BreakGlassAdminIT` | **17 run, 0 failures, BUILD SUCCESS**. Covers the grant, every refusal and exit code 2 to 7, the replay in another tenant, the padded replay with no value in the row or the logs, the servlet-context guard (web server never initialized), the deadlock leading to exit 7, the race with a last-admin self-revoke, and two CLIs racing on one tenant |
| `sh ./mvnw -o -Psecurity dependency-check:check` | **Not runnable offline:** `Goal requires online mode for execution but Maven is currently offline.` Left to CI. The M5 diff changes no `pom.xml` and adds no dependency |
| `mvnw -o dependency:tree -Dscope=runtime` | Ran. **No `spring-webflux` or `reactor-netty` on the runtime classpath.** This is the evidence for sign-off 2 |
| `npm audit --omit=dev --audit-level=high` (`nexus-frontend`) | 7 vulnerabilities (6 moderate, 1 high). All are pre-existing and identical to the set triaged in `07-security-review-M7.md`. M5 has no frontend or lockfile change |

---

## Explicit sign-offs requested

### Sign-off 1: `TenantIsolationArchitectureTest` allowlist entry `JpaAuthEventRepository#existsSuccessfulBreakGlassGrantWithChangeRef`: **SIGNED OFF**

**Reason for the entry:** the lookup is global by design (RC-37.2, RC-47, T-S11), because one change reference approves one grant anywhere. A tenant-scoped lookup would let one approval be replayed in a second tenant.

**Cross-tenant exposure is acceptable.** Evidence:
- **Output is existence only.** `JpaAuthEventRepository.java:18-24` is `SELECT EXISTS(...)` and returns `long` 0 or 1. `BreakGlassGrantLookupAdapter.java:20-22` maps that to a `boolean`. No tenant id, user id, row or timestamp leaves the query. The refusal it produces (`CHANGE_REF_REUSED`) carries a null tenant id in both the row and the page (`BootstrapAdminService.java:109-110`), so the refusal path leaks no other tenant's identity either.
- **No injection.** The only variable is the bound named parameter `:changeRef`. The JSON path `'$.changeRef'` and both filters are literals. Before the query runs, the value has already passed `ChangeRef`'s canonical pattern `^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$` (`ChangeRef.java:17,25-29`).
- **Who can ask.** The only caller is `BootstrapAdminService.grantFirstAdmin`. That service is reachable only from `rbac.interfaces.cli` (ArchUnit `BOOTSTRAP_ADMIN_SERVICE_IS_REACHABLE_ONLY_FROM_THE_CLI`), and the CLI runs only under the `break-glass` profile (`CLI_BEANS_ARE_BREAK_GLASS_PROFILE_ONLY`). The asker is an operator who already holds infra access and the `nexus_app` credentials, and so can already read `auth_events` directly. The oracle gives that operator nothing new.
- **No poisoning.** A tenant user cannot plant a matching row to block break-glass. `ROLE_BREAK_GLASS_GRANT` is written only by `RbacAuthEventAdapter.recordBreakGlassGrant` (SUCCESS) and `recordBreakGlassRefusal` (FAILURE). The lookup matches SUCCESS only, and no request path can emit that event type.
- **Bounded cost.** The lookup is bounded by `idx_auth_events_event_type_created_at` (V2:90). It reads `ROLE_BREAK_GLASS_GRANT` rows only and takes no lock.

One defense-in-depth gap: the port itself is not contained. See L-3.

### Sign-off 2: `@ConditionalOnWebApplication(SERVLET)` on `SecurityConfig` and `PublicEndpointRequestMatcher`: **SIGNED OFF. Security cannot be silently off in the serving app**

- **The serving app is always SERVLET.** The runtime dependency tree has no WebFlux or Reactor Netty, so Spring Boot cannot deduce REACTIVE, and forcing `reactive` would fail startup for lack of a `ReactiveWebServerFactory`. The only file in `src/main/resources` that sets `spring.main.web-application-type` is `application-break-glass.yml`, and it sets `none`.
- **A `NONE` context has no HTTP listener,** so there is nothing for the filter chain to protect. That covers break-glass and any misconfigured `none` deployment.
- **No partial chain is possible.** `JwtAuthenticationFilter` is not a standalone `@Component`. It is a `@Bean` inside `SecurityConfig` (`SecurityConfig.java:159-166`), and the matcher's other consumer is `JwtAuthenticationFilter` itself. So the matcher, the JWT filter and the chain appear or disappear together. A servlet context cannot load the filter without the chain, or the chain without the matcher.
- **Method security is unaffected.** `@EnableMethodSecurity` (`MethodSecurityConfig`) is unconditional, so `@RequiresPermission` still guards service calls in every context type.
- **Tests confirm the servlet case.** `SecurityConfigWebTest` (18) and `EndpointClassificationWebTest` load the chain under the annotation. The whole `*IT` suite, which asserts 401 and 403 through MockMvc in a servlet `@SpringBootTest`, would fail if the chain were absent.

### Sign-off 3: authorization, locking and audit integrity: **reviewed, sound apart from the findings below**

| Concern | Evidence | Result |
|---|---|---|
| Containment of the unauthenticated grant | ArchUnit: `BootstrapAdminService` is reachable only from `rbac.interfaces.cli`; break-glass never calls `RoleAssignmentService.assign`/`revoke`; CLI beans are `@Profile("break-glass")` only. All pass | ✅ |
| Set lock | `BootstrapAdminService.java:181-186`. The same M10 and M8 resolution (`resolveAdminEquivalentRolesFor`), the same ascending lock set (`buildAscendingAdminEquivalentLockSet`) and the same single-statement `lockActiveAssignmentHolders` as `assign()`/`revoke()`, inside the grant transaction. No second lock and no retry (ADR-0018) | ✅ |
| Zero-administrator check | `:188-191` uses the revoke guard's own predicate (`RoleAssignmentService.java:825`) with `revokedAssignmentId = null`, which excludes no row, over the caller-qualifying population (literal `TENANT_ADMIN` plus every role that carries all three dangerous permissions). It is evaluated on the rows the lock returned, so it cannot race a concurrent assign or revoke. A tenant with an administrator is refused, so break-glass is not a general backdoor | ✅ (see M-1 for DISABLED holders) |
| Role resolution | `:171-179`. `findRoleIdByName(tenantId, TENANT_ADMIN)` is tenant-scoped, then filtered on `isSystemRole`, so a tenant-created custom role named like the admin role cannot be the grant target | ✅ |
| Tenant of the grant | Taken from the target user's own row (`findUser`), never from an argument. The `user_roles` insert carries that tenant | ✅ |
| Audit: SUCCESS inside the grant transaction | `:193-195` → `RbacAuthEventAdapter.recordBreakGlassGrant` → `SecureEventService.recordEventInCurrentTransaction` (`MANDATORY`) → `recordOrThrow` (flush). A failure is rethrown, so the grant rolls back. Proven by IT `should_rollBackGrant_when_successAuditInsertFails` | ✅ |
| Audit: FAILURE in `REQUIRES_NEW`, never buffered | `recordBreakGlassRefusal` → `recordEventOrThrowInNewTransaction`, so the row never goes to the retry buffer that this process would never drain. A failure is logged as `RBAC_AUDIT_WRITE_LOST` (without `changeRef`) and counted, and the method never throws. Every refusal, including one decided inside the grant transaction, is written after `execute()` returns, so no `REQUIRES_NEW` write runs while the set lock is held, and an invocation commits at most one row | ✅ |
| Audit immutability | `auth_events` keeps its BEFORE UPDATE and BEFORE DELETE triggers (V2:98-109) | ✅ |
| Failed grant transaction | `PessimisticLockingFailureException` → exit 7. Any other `RuntimeException` → exit 1. Each is audited and paged only after the rollback. An `Error` propagates (fail closed, no grant) | ✅ |
| Alert never throws | The GRANTED page is best effort: `alertGranted`, `:204-222`, catches a failure, logs `RBAC_BREAK_GLASS_ALERT_FAILED` and keeps exit 0. The refusal page is not wrapped; see L-1 | ⚠️ L-1 |
| PII and argument leakage (L-6) | The runner never logs an argument value (`BreakGlassAdminRunner.java`). `recordInvalidArgument()` takes no parameter, so a rejected value cannot reach the row or the page. Both `ChangeRef` and the UUID parse reject without echoing the value. The page and row fields are UUIDs, a bounded enum and a canonical ticket id. IT `should_refuseWithExit2_writeOneValueFreeRow_andLogNoArgument_...` asserts `ABC-0001` is in neither the row nor the captured logs. The WARN lines on a failed transaction carry only `tenantId` and the cause | ✅ |
| Web-context guard | `BreakGlassAdminRunner.java:84-102`, in `afterPropertiesSet`. The servlet web server is created in `onRefresh` but its connector binds only in `finishRefresh`, so throwing during singleton instantiation fails the refresh before any port is bound (IT asserts `webServerInitialized == false`). It also checks the actual context class, not the property, and covers REACTIVE. It pages `WEB_CONTEXT` and waits the flush interval first (T-008 review Low 2 is fixed). Note: because `application-break-glass.yml` forces `none`, a serving pod that wrongly activates `break-glass` does not serve at all. It runs the CLI with no arguments, refuses with exit 2 and pages. That is fail-closed | ✅ |
| Exit codes | `exitCode` starts at 1 and is reset to 1 at the start of every `run()`, so a failed run cannot report 0. Codes 0 and 2 to 7 are pinned in `BreakGlassRefusalReason`. `NexusApplication.main` calls `System.exit(SpringApplication.exit(ctx))` only when `break-glass` is active, so the serving app's behaviour is unchanged. Exit 1 is ambiguous; the runbook covers it (design §7.1) | ✅ |
| `DevDataInitializer` exclusion | `@Profile("dev & !break-glass")` (`DevDataInitializer.java:41`), pinned by `DevDataInitializerTest` (7). It is the only other `ApplicationRunner` in `src/main` | ✅ |
| Break-glass profile config | `web-application-type: none` (no web port, so no management child context either), `flyway.enabled: false` (`ddl-auto=validate` still checks the schema), Hikari `maximum-pool-size: 4`. The flow needs one connection at a time, and the pool is not reachable from outside the process, so the pool size has no security impact. `log-flush-wait` defaults to 15 s and can be overridden by env, which only an operator can set; the daily reconciliation is the backstop | ✅ |

### Threat-model cross-reference (A7 threats claimed mitigated)

| Threat / RC | Claimed mitigation | Visible in code? |
|---|---|---|
| M5 **T** (schema mutation or mismatch) | Flyway off, `ddl-auto=validate` | ✅ `application-break-glass.yml:10-12` |
| M5 **I** (operator identity in tenant data) | `assigned_by = target` | ✅ `BootstrapAdminService.java:193` |
| M5 **D** (profile in a serving pod), RC-37.6 / RC-50(d) | Bean-initialization guard; refresh fails before the server starts | ✅ `BreakGlassAdminRunner.java:84-102`, IT |
| M5 **E** (general backdoor) | Zero-admin precondition under the set lock; a re-run refuses | ✅ `:181-191`; IT exit 5 after a re-run |
| M5 **E** (REST reaches the service) | ArchUnit plus profile gating | ✅ three rules, passing |
| T-S9 / RC-37.2 (replay) | Global SUCCESS-row lookup, exit 6 | ✅ `:109-110`; ITs for same-tenant and other-tenant replay |
| T-S9 / RC-37.1 (requester spoofing) | Runbook (contact of record, second approver) | ⏳ Docs. Merge-checklist item, not code |
| T-S11 / RC-47 (padded replay) | Canonical pattern with no leading zeros; bound parameter; global | ✅ `ChangeRef.java:17`; IT padded replay → exit 2, nothing granted |
| T-R14 / RC-37.3, RC-37.5 | K8s audit logging; reviewer note | ⏳ Ops sign-off and runbook (merge checklist). ADR-0025 item 5 records RC-37.5 |
| T-R15 / RC-37.4 | Flush wait (also before the guard throws); no `--rm`; daily reconciliation | ✅ wait is in `run()`'s `finally` and before the guard throws; ⏳ drill and reconciliation alert are on the merge checklist |
| RC-54(a), L-6 | Exit 2; value-free row and page | ✅ see the PII row above |
| Audit of every invocation (ADR-0025 item 6) | Every refusal and every grant writes a row and pages | ✅, except crashes before or outside the grant transaction (no row, no page; documented in design §7.1 and the runbook) and L-1 |

---

## Findings

```
[MEDIUM] M-1: A DISABLED sole administrator makes break-glass refuse, so the tenant cannot be recovered without manual SQL (O-7)
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java:185-191
      (predicate at nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:825)
Issue: "Zero administrators" counts every active caller-qualifying assignment, whatever the
       holder's user status. A tenant whose only administrator is DISABLED gets exit 5
       (TENANT_HAS_ADMIN). In-app recovery is also blocked: revoking that assignment needs an
       administrator caller, and the last-admin guard refuses to revoke the last holder anyway.
OWASP: A04 Insecure Design (the recovery path fails for a realistic incident state).
Risk: Not exploitable for privilege gain; it fails closed. But the most likely reason to need
      break-glass is incident response: the sole administrator's account is compromised or
      the person leaves, and Platform DISABLES the account. That state cannot be recovered by
      the audited tool, which pushes operators back to the unaudited, unpaged manual
      production INSERT that A7 / FR-A7.d exists to remove (and T-R14 / T-R15 are about).
      Rated Medium because it disables a security-recovery control in its most likely use
      case; it is not Low hygiene.
Fix: Owner decision (Architect + Platform Security Owner), recorded before the M5 PR merges.
     Either:
     (a) accept it as a named residual with an owner and a documented manual procedure that
         is itself audited (for example the operator writes the ROLE_BREAK_GLASS_GRANT row by
         hand under the change reference); or
     (b) define "administrator" as holders whose user is not DISABLED, consistently in the
         last-admin lockout, RbacZeroActiveAdminsHealthIndicator and A7. In that case:
         - read the holders' status under the same lock (for example a FOR SHARE on the
           holders' users rows, taken after the set lock in a fixed order), so a concurrent
           re-enable cannot race the grant;
         - keep temporarily LOCKED (lockout) holders counted as administrators;
         - add an IT for a DISABLED sole admin leading to a grant.
     Do not add a CLI override flag. That would turn the precondition into an operator choice
     and reopen the "general backdoor" threat (M5 E).
```

```
[LOW] L-1: The refusal page is not best effort. If it throws, exit 1 hides the refusal code
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java:233-242
Issue: refuse() calls breakGlassAlertPort.alert(...) unguarded, but the GRANTED page
       (alertGranted, :204-222) is wrapped. If alert() throws, the exception leaves
       grantFirstAdmin. The runner keeps exitCode = 1, and Spring reports a startup failure.
OWASP: A09 Security Logging & Monitoring Failures (minor).
Risk: Low. Nothing is ever granted on this path (refusals only), and the FAILURE row is
      already committed. The BreakGlassAlertPort contract says MUST NOT throw, and the only
      implementation is an SLF4J/Logback call whose appenders swallow their own failures. So
      the realistic probability is very low. If it happens, the operator sees exit 1 with no
      RBAC_BREAK_GLASS_USED line, and the runbook already says to page Platform Security
      manually and check auth_events. The asymmetry is defensible: only a grant must keep
      exit 0, to reflect a committed state.
Fix (optional): wrap the refusal alert like alertGranted (log RBAC_BREAK_GLASS_ALERT_FAILED
     with tenantId and reason, and return the Refused outcome) so the specific refusal exit
     code survives. Or record the asymmetry in the class Javadoc and design §7.1.
```

```
[LOW] L-2: The target's ACTIVE check is outside the grant transaction (TOCTOU)
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java:112-120 (check) vs :127-128 (grant transaction)
Issue: findUser() is a plain non-locking read before the transaction. A target DISABLED
       between that read and the insert still receives TENANT_ADMIN.
OWASP: A04 Insecure Design (race).
Risk: Very low. In a zero-admin tenant, nobody in the tenant can disable the target, so the
      race needs a concurrent platform-side status change. A DISABLED user cannot log in, so
      no privilege is usable. The real effect is availability: under the current M-1
      semantics, that disabled holder then blocks every later break-glass on the tenant.
Fix: Accept and note it in design §7.1. Alternatively, re-read the target's status inside the
     grant transaction after the set lock (FOR SHARE on the users row) and refuse
     TARGET_USER_NOT_ACTIVE there. If M-1 option (b) is chosen, do this as part of it.
```

```
[LOW] L-3: The global replay-lookup port is not ArchUnit-contained
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/BreakGlassGrantLookupPort.java:277
      (rule file: nexus-backend/src/test/java/com/example/nexus/architecture/ArchitectureRules.java:37-50)
Issue: The allowlist signed off above relies on the lookup being reachable only from the
       break-glass flow. Today that is true by inspection: its only consumer is
       BootstrapAdminService. But no rule enforces it. BootstrapAdminService is contained;
       BreakGlassGrantLookupPort and JpaAuthEventRepository#existsSuccessfulBreakGlassGrantWithChangeRef
       are not.
OWASP: A01 Broken Access Control (defense in depth).
Risk: A future REST or service consumer would turn the deliberately unscoped query into a
      cross-tenant existence oracle reachable by tenant users. TenantIsolationArchitectureTest
      would not catch it, because the method is now allowlisted.
Fix: Add an ArchUnit rule: no class other than BootstrapAdminService (and its adapter)
     depends on BreakGlassGrantLookupPort, and no class other than
     BreakGlassGrantLookupAdapter calls existsSuccessfulBreakGlassGrantWithChangeRef. Reference
     the rule in the allowlist comment.
```

---

## Informational notes (no action required)

- **Spring Boot's own argument handling can echo values of options the runner does not own.** Examples: Spring's "Invalid argument syntax" error for `--=x`, or a property-binding failure analysis for a bad `--nexus.*`/`--spring.*` value. RC-54(a) and L-6 cover only `--target-user-id` and `--change-ref`, and the runner meets them. The remaining path is operator-typed only and is out of scope.
- **The break-glass grant does not evict the target's Redis permission cache** (`assign()` does, post-commit). This fails toward fewer privileges: the new administrator may see the old permission set until the cache TTL expires or the next login re-mints. It has no security impact, but the runbook's "verify" step should allow for it.
- **Background schedulers run inside the break-glass process.** These are the `PermissionFreshnessService` 1 s poll and the `AuthEventRetryBuffer` drain. No break-glass row ever enters the retry buffer, and neither job touches `user_roles`. There is no security impact. It is noted only because the Hikari comment names them as the reason for the headroom.
- **`changeRef` (an internal ticket id) is visible to the tenant's `audit:read` holders** on SUCCESS rows and on tenant-scoped FAILURE rows, once C3 makes `audit:read` live. This is by design (Decision 10, the attribution join) and is not PII.
- **T-S11's accepted race** (two concurrent runs with one reference, two different zero-admin tenants) still holds as accepted. The runbook allows one invocation at a time per reference.

## Residual risk

- RES-35 (social engineering anchored in infra access, Low) is unchanged. It depends on the RC-37.1 runbook content and RC-37.3 Ops sign-off on the merge checklist.
- M-1 / O-7 remains until the owner decision.
- A06 is unverified locally and left to CI.
