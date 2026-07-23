# US-011 — Task Breakdown

**Feature:** Enforce permission checks on API endpoints via Spring Security
**Epic:** EPIC-002 (RBAC Foundation)
**Step:** 4 — Task Breakdown (Gate 3)
**Binding inputs (not reopened):** `01-requirements.md` (FR1–FR10, Gate 1), `02-impact.md` (Gate 2 input), `03-design.md` (approved solution, §F class list, §E test plan), `03b-threat-model.md` (verdict *APPROVE WITH CONDITIONS* — 5 required + 1 recommended condition, all promoted to explicit tasks below).

**Gate locks carried in (do NOT re-open in any task):**
- `@RequiresPermission("resource:action")` takes **only** the permission string; no `tenantId` method parameter; no tenant-to-tenant comparison (Gate 1). The cross-tenant guarantee holds *by construction* via mint-time scoping (design §B5).
- The 403 body uses RFC-7807 **`detail`** (not `message`) and camelCase **`requiredPermission`** (not `required_permission`). AC3 is amended; this reconciliation is approved (design §C.1).
- The evaluator is a **named-bean SpEL** method, not Spring's `PermissionEvaluator` interface (design §B3).

**Jira sync:** Not applicable — no Atlassian/Jira MCP is connected in this session. No sub-tasks were pushed to a tracker; this document is the authoritative breakdown.

---

## Scope confirmation — groups deliberately empty

- **Database:** *No tasks.* This story adds no table, column, index, constraint, or Flyway migration. Enforcement reads only the JWT `permissions[]`/`tenant_id` claims already on the request `Authentication` (FR7); `ddl-auto=validate` is unaffected. Confirmed in `02-impact.md` §2 and `03-design.md` §D. Stated explicitly so the reader knows it was assessed, not overlooked.
- **Frontend:** *No tasks.* The story's Technical Notes state "Angular: no changes in this story." The 403 contract is consumed by a *future* frontend guard (US-013), out of scope here. Confirmed in `01-requirements.md` §3 (Accessibility: "backend-only story") and `02-impact.md` §3. Stated explicitly for the same reason.

---

## Task map

```
Epic: US-011
├─ Backend
│   ├─ Cross-cutting security (common.security)
│   │     T-001  InsufficientPermissionException
│   │     T-002  AuthenticatedRequestDetails (fail-closed reader)
│   │     T-003  @RequiresPermission + TenantAwarePermissionEvaluator
│   ├─ Configuration
│   │     T-004  MethodSecurityConfig
│   │     T-005  GlobalExceptionHandler denial branch (RBAC_001)
│   └─ Test fixtures
│         T-006  GuardedTestController + GuardedTestControllerConfig
├─ Cross-cutting (threat-model conditions — first-class tasks)
│         T-007  Cond 1  Tenant-provenance invariant (Javadoc + ADR + contract + sole-producer guard)
│         T-008  Cond 5  Denial-reason discriminator + structured denial log fields
│         T-009  Cond 6  Single-source Authentication detail keys + producer/consumer contract test
│         T-010  Cond 2  Formalise CrossTenantPermissionIT as hard CI merge gate
│         T-011  Cond 3  Track deferred "controller-must-be-annotated" rule as Epic-3 entry criterion
├─ Tests
│         T-012  Unit — evaluator + reader
│         T-013  Slice/MockMvc — wiring, 401-vs-403, RBAC_001 shape
│         T-014  CrossTenantPermissionIT — Testcontainers cross-tenant boundary
├─ Architecture governance
│         T-015  ArchUnit — Spring-Security-ban in domain/application (§B8 ADD)
└─ Documentation
          T-016  Cond 4  Step-9 developer-guide entry (self-invocation warning)
```

**Condition → task coverage:** Cond 1 → T-007; Cond 2 → T-010; Cond 3 → T-011; Cond 4 → T-016; Cond 5 → T-008; Cond 6 (recommended) → T-009. None left as follow-up debt.

**Suggested execution order (respects all dependencies):**
T-001 → T-002 → T-003 → T-004 → T-005 → T-006 → T-009 → T-008 → T-007 → T-015 → T-012 → T-013 → T-014 → T-010 → T-011 → T-016.

---

## Backend — Cross-cutting security (`common.security`)

### T-001 — `InsufficientPermissionException`

- **Description:** Create the RBAC denial exception that carries the required permission and routes denials to the `RBAC_001` contract. `extends org.springframework.security.access.AccessDeniedException` (ADR-0013 D3) — deliberately **not** `common.domain.DomainException`. Carries `requiredPermission` (String) exposed via a getter. Lives in `common.security` so `common.web.GlobalExceptionHandler` can import it without `common` depending on `rbac` (design §B1). Base shape only — the `DenialReason` discriminator is added in T-008.
- **Dependencies:** none.
- **Files created:** `nexus-backend/src/main/java/com/example/nexus/common/security/InsufficientPermissionException.java`
- **Complexity:** S
- **Risks:** R5 (novel exception-placement pattern — first cross-context exception not extending `DomainException`). Mitigation: include the divergence note as a class Javadoc so future contributors do not assume a shared base.
- **Testing requirements:** Covered indirectly by T-012 (thrown by evaluator/reader) and T-013 (mapped to `RBAC_001`). If `toString()`/getter is overridden, add a companion assertion to avoid the known JaCoCo coverage-gap on security records (per project memory).
- **Definition of Done:** Class compiles; extends `AccessDeniedException`; exposes `requiredPermission`; Javadoc records the intentional non-`DomainException` divergence; no import of any `rbac` type.

### T-002 — `AuthenticatedRequestDetails` (fail-closed reader)

- **Description:** Single choke point for reading the untyped `Authentication.getDetails()` `Map<String,Object>` produced by `JwtAuthenticationFilter`. A `record(String tenantId, Set<String> permissions)` with a static `fromAuthentication(Authentication)` factory and a `hasPermission(String)` helper. **Fail-closed** per design §B4: throw `InsufficientPermissionException` when `Authentication` is null/unauthenticated, `getDetails()` is absent or not a `Map`, `tenantId` is absent/blank/non-String, or `permissions` is absent/not a `List<String>`. `tenantId` is treated as an opaque String — no UUID re-parse, no case-folding (design §B5). `permissions` normalised to a `Set` once for O(1) membership. Do **not** modify `JwtAuthenticationFilter` (frozen producer, design §B2). This task may use string-literal detail keys; T-009 replaces them with shared constants.
- **Dependencies:** T-001.
- **Files created:** `nexus-backend/src/main/java/com/example/nexus/common/security/AuthenticatedRequestDetails.java`
- **Complexity:** M
- **Risks:** R4 / T-06 — untyped-map cast is the first non-logging consumer; a missing/mistyped key is not caught at compile time. Mitigation: exhaustive fail-closed unit tests (T-012) and the producer/consumer contract test (T-009).
- **Testing requirements:** Unit (T-012) covering every deny branch in §B4 plus the happy path; assert it throws `InsufficientPermissionException` (never returns null, never 500, never allows).
- **Definition of Done:** All §B4 malformed/absent/wrong-type conditions throw `InsufficientPermissionException`; happy path returns a populated record; `permissions` is a `Set`; `JwtAuthenticationFilter` untouched.

### T-003 — `@RequiresPermission` annotation + `TenantAwarePermissionEvaluator`

- **Description:** The developer-facing contract and its backing bean.
  - **Annotation** `@RequiresPermission` — `@Target(METHOD)`, `@Retention(RUNTIME)`, single `String value()`, meta-annotated `@PreAuthorize("@permissionEvaluator.hasPermission(authentication, '{value}')")` with `{value}` template substitution (design §B3, §B9 — exactly one permission, no AND/OR).
  - **Evaluator** `@Component("permissionEvaluator")` with `boolean hasPermission(Authentication authentication, String permission)`. Delegates to `AuthenticatedRequestDetails.fromAuthentication(...)` then set-membership; **throws** `InsufficientPermissionException(permission)` on absence (fail-closed, §B4) rather than returning `false` — this is what routes denials to `RBAC_001` instead of the generic `ACCESS_DENIED`. Does **not** implement Spring's `PermissionEvaluator` interface (§B3).
- **Dependencies:** T-001, T-002.
- **Files created:** `nexus-backend/src/main/java/com/example/nexus/common/security/RequiresPermission.java`, `nexus-backend/src/main/java/com/example/nexus/common/security/TenantAwarePermissionEvaluator.java`
- **Complexity:** M
- **Risks:** R7 (first custom annotation/method-security mechanism — no prior test pattern); T-11 templating (`{value}`) requires the defaults bean from T-004, else `{value}` is treated literally → fail-closed always-403. Bean name `permissionEvaluator` must match the SpEL reference exactly.
- **Testing requirements:** Evaluator logic in T-012 (present → true; absent/empty → throws). Annotation wiring proven in T-013 (positive+negative pair). SpEL string must be validated by the slice test, not just compilation.
- **Definition of Done:** Annotation compiles and carries `@PreAuthorize` with `{value}`; evaluator bean named `permissionEvaluator`; `hasPermission` throws on deny (never returns false); neither class resides in `..domain..`/`..application..`; no `rbac` import.

---

## Backend — Configuration

### T-004 — `MethodSecurityConfig`

- **Description:** New `@Configuration` in the root `config` package (sibling to `SecurityConfig`, not merged into it — design §B1). Adds `@EnableMethodSecurity` (global, FR10) and an `AnnotationTemplateExpressionDefaults` bean enabling `{value}` meta-annotation substitution. **Confirm the exact defaults class name against the pinned Spring Security version at implementation time** — the capability (meta-annotation attribute templating) is stable but the class was renamed across 6.3→6.4 (design §B3). `SecurityConfig.java` is intentionally **not** modified — the filter chain, `permitAll` list, and filter-chain `AccessDeniedHandler` stay untouched (design §F note).
- **Dependencies:** T-003.
- **Files created:** `nexus-backend/src/main/java/com/example/nexus/config/MethodSecurityConfig.java`
- **Complexity:** S
- **Risks:** T-10 (A05 misconfiguration). Realistic failure mode is fail-closed (missing defaults bean → `{value}` literal → always 403), caught by T-013's positive control. The dangerous fail-open mode (composed `@PreAuthorize` not detected at all) does not occur on the pinned version; the positive+negative test pair in T-013 is the guard.
- **Testing requirements:** Exercised by T-013 (annotation must both allow with the permission and deny without it — proves method security is genuinely active and templating resolves).
- **Definition of Done:** `@EnableMethodSecurity` active platform-wide; defaults bean registered with the version-correct class name; `SecurityConfig` unchanged; existing `SecurityConfigTest` and all current auth-endpoint tests still green (no regression on `permitAll` endpoints).

### T-005 — `GlobalExceptionHandler` denial branch (`RBAC_001`)

- **Description:** Add `@ExceptionHandler(InsufficientPermissionException.class)` to the existing `@RestControllerAdvice`, returning **403 + `code=RBAC_001`** via the existing `problem(...)` builder with `detail = "You do not have permission to perform this action"` and extension member `requiredPermission = ex.getRequiredPermission()` (design §C.1 — `detail`/camelCase reconciliation, approved). Emit the base WARN log and increment a Micrometer counter `nexus.rbac.permission_denied` tagged `permission=<required>` (low cardinality; **never** tag `userId`/`tenantId`). The pre-existing generic `@ExceptionHandler(AccessDeniedException.class)` (`ACCESS_DENIED`) stays untouched as the fallback — Spring's most-specific dispatch selects the new subtype handler (design §A.2). Structured `reason`/`userId`/`tenantId` log fields are added in T-008.
- **Dependencies:** T-001.
- **Files impacted:** `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java`
- **Complexity:** S
- **Risks:** Ordering vs. the generic handler — verify the subtype handler wins for `InsufficientPermissionException` while non-RBAC `AccessDeniedException` still returns `ACCESS_DENIED`. T-09 (echoing `requiredPermission`) is an accepted, non-secret disclosure — no change.
- **Testing requirements:** T-013 asserts full `RBAC_001` body shape (`status`, `code`, `detail`, `traceId`, `requiredPermission`); update `GlobalExceptionHandlerTest` (if present) with the `RBAC_001` mapping case; assert the generic `AccessDeniedException` path is unchanged.
- **Definition of Done:** `InsufficientPermissionException` → 403 `RBAC_001` with `detail` + `requiredPermission`; generic handler untouched and still returns `ACCESS_DENIED`; counter increments once per denial; no PII in log or body (UUIDs only, per org policy).

---

## Backend — Test fixtures

### T-006 — `GuardedTestController` + `GuardedTestControllerConfig`

- **Description:** Test-only fixture proving AC5/AC7 (annotation compiles and enforces on an arbitrary method with zero bespoke wiring) and giving the slice/IT tiers a concrete endpoint to call (design §B6; the `rbac` context has no production controller). `GET /internal-test/guarded` annotated `@RequiresPermission("tenant:write")` returning a trivial 200; a second method `GET /internal-test/guarded-user-read` annotated `@RequiresPermission("user:read")` for the "has one permission, not the other" case. Registered via an `@Import`ed `@TestConfiguration` so it is **never** component-scanned in production and cannot ship. Test sources only.
- **Dependencies:** T-003, T-004.
- **Files created:** `nexus-backend/src/test/java/com/example/nexus/support/web/GuardedTestController.java`, `nexus-backend/src/test/java/com/example/nexus/support/web/GuardedTestControllerConfig.java`
- **Complexity:** S
- **Risks:** A fixture accidentally reachable in production would create an unguarded surface. Mitigation: keep strictly under `src/test/java`, register only via `@TestConfiguration`/`@Import`, never `@ComponentScan`-visible.
- **Testing requirements:** Consumed by T-013 and T-014; no standalone test of its own beyond compilation.
- **Definition of Done:** Both endpoints exist under `src/test/java`; annotated; reachable only in the test context; confirmed absent from any production component scan.

---

## Cross-cutting — Threat-model conditions

### T-007 — (Condition 1) Tenant-provenance invariant: document, contract-test, and guard the sole producer

- **Description:** The epic's Critical property (no cross-tenant escalation) rests entirely on an upstream invariant this story neither asserts nor guards (T-02). Make it explicit and defended:
  1. **Javadoc** on `TenantAwarePermissionEvaluator` stating: the evaluator assumes `permissions[]` on the `Authentication` were resolved for the same tenant as the `tenant_id` detail; this invariant is guaranteed **only** by `JwtRs256Service.issue` + `RoleResolutionService`; any new code constructing an authenticated `Authentication` with a `permissions` detail MUST reuse that tenant-scoped resolution.
  2. **ADR-0013 amendment note** recording (a) this tenant-provenance invariant and (b) the §B3 deviation — enforcement uses a named-bean SpEL method, not Spring's `PermissionEvaluator` interface, with a `{value}`-templated meta-annotation.
  3. **Contract regression test** locking `JwtRs256Service.issue` to source both the `permissions[]` resolution and the `tenant_id` claim from the *same* `user.getTenantId()` — a future refactor that decouples them must fail this test.
  4. **Sole-producer guard** (test or ArchUnit) asserting `JwtAuthenticationFilter` is the only production code that builds an authenticated `Authentication` carrying a `permissions` detail; a second producer must fail the guard and force an explicit B5 re-review.
- **Dependencies:** T-003.
- **Files created:** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTenantProvenanceTest.java` (or add the case to an existing `JwtRs256Service` test), and the sole-producer guard either in `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java` (**Mod**) or a dedicated `.../architecture/AuthenticationProducerGuardTest.java` (**New**).
- **Files impacted:** `nexus-backend/src/main/java/com/example/nexus/common/security/TenantAwarePermissionEvaluator.java` (Javadoc), `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` (amendment note).
- **Complexity:** M
- **Risks:** The sole-producer guard must be phrased to match the real construction pattern (`setDetails(...)` with a `permissions` key), else it either false-passes or false-fails. Do **not** modify `JwtRs256Service`/`JwtAuthenticationFilter` behaviour — this task only documents and asserts existing behaviour.
- **Testing requirements:** Provenance contract test green against current mint path; sole-producer guard green today and demonstrably red if a second producer is introduced (verify with a scratch second producer, then remove).
- **Definition of Done:** Javadoc present and references ADR-0013; ADR-0013 amended with both notes; provenance contract test asserts same-tenant sourcing; sole-producer guard passes and is proven to fail on a second producer.

### T-008 — (Condition 5) Denial-reason discriminator + structured denial log fields

- **Description:** Two very different events currently collapse into one signal (T-08): routine "user lacks permission" vs. security-interesting "malformed/foreign Authentication." Distinguish them:
  1. Add a `DenialReason` discriminator (e.g. `PERMISSION_ABSENT`, `MALFORMED_AUTHENTICATION`, `MISSING_TENANT`) to `InsufficientPermissionException`; set it at each throw site in `AuthenticatedRequestDetails` and `TenantAwarePermissionEvaluator`.
  2. In `GlobalExceptionHandler`, emit `reason` as a structured field on the denial WARN log, and **explicitly emit `userId` and `tenantId` as structured fields** — confirmed available because the denial is thrown inside `JwtAuthenticationFilter`'s try/`finally` around `chain.doFilter`, so MDC is still populated; but the existing `logHandledException` helper emits only `correlationId`, so the new handler must add them or the forensic value is lost (T-07 caveat).
  3. Optionally add a low-cardinality counter tag or separate counter for the fail-closed (`malformed`/`missing_tenant`) branch so a spike in malformed denials is independently alertable.
- **Dependencies:** T-001, T-002, T-003, T-005.
- **Files impacted:** `nexus-backend/src/main/java/com/example/nexus/common/security/InsufficientPermissionException.java`, `.../common/security/AuthenticatedRequestDetails.java`, `.../common/security/TenantAwarePermissionEvaluator.java`, `.../common/web/GlobalExceptionHandler.java`
- **Complexity:** M
- **Risks:** Keep counter tags low-cardinality (reason is a closed enum; never add `userId`/`tenantId` tags). Confirm the log-encoder pattern actually renders the new structured fields (per project logback pattern conventions).
- **Testing requirements:** T-012 asserts each throw site carries the correct `DenialReason`; T-013 (or a focused log-capture test) asserts the WARN log carries `reason`, `userId`, `tenantId`, `requiredPermission`, `correlationId`/`traceId`. Verify UUIDs only — no PII.
- **Definition of Done:** Exception carries a reason; every throw site sets the correct value; denial WARN log emits `reason` + `userId` + `tenantId` as structured fields (verified, not merely in MDC); malformed vs. routine denials are separable in logs.

### T-009 — (Condition 6, recommended) Single-source `Authentication` detail keys + producer/consumer contract test

- **Description:** Nothing binds the filter's string-literal detail keys to the reader's at compile time (T-06); a rename on either side silently fails-closed every guarded endpoint. Introduce a shared constants holder for the four detail keys (`tenantId`, `emailVerified`, `tokenVersion`, `permissions`) and reference it from **both** `JwtAuthenticationFilter` (producer) and `AuthenticatedRequestDetails` (consumer). Add a contract test asserting the reader successfully parses an `Authentication` built by the **real** `JwtAuthenticationFilter` (not a hand-built map), so a future filter-side key change breaks a test rather than production.
- **Dependencies:** T-002, T-003.
- **Files created:** `nexus-backend/src/main/java/com/example/nexus/common/security/AuthenticationDetailKeys.java` (**New** — beyond the original §F list; introduced to satisfy Condition 6), `nexus-backend/src/test/java/com/example/nexus/common/security/AuthenticationDetailsContractTest.java` (**New**).
- **Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java` (replace string literals with constant references — a **mechanical, no-behaviour-change** edit; note this is the one sanctioned touch of the otherwise-frozen filter, limited to literal→constant substitution).
- **Complexity:** S
- **Risks:** Editing the frozen `JwtAuthenticationFilter` — keep strictly to literal→constant substitution; run the filter's existing contract tests to confirm no behaviour change. The constant holder must live in `common.security` (no `identity`→`common` inversion issue; `common` is the shared home).
- **Testing requirements:** Existing `JwtAuthenticationFilter` tests still green (no behaviour change); new contract test proves reader parses a real-filter-produced `Authentication`.
- **Definition of Done:** All four keys sourced from one holder used by filter and reader; filter behaviour unchanged (existing tests green); contract test green and would fail on a filter-side key rename.

### T-010 — (Condition 2) Formalise `CrossTenantPermissionIT` as a hard CI merge gate

- **Description:** The cross-tenant IT (authored in T-014) is the only end-to-end proof of the epic's Critical property. Make it a **hard CI merge gate** that must be green before any Epic-3 endpoint work begins: ensure it runs in the Failsafe `*IT` phase under the standard `./mvnw verify` (Testcontainers) CI job, is not excluded from the merge-blocking workflow, and is documented as a release gate. Add a note to EPIC-002 tracking that this suite gates Epic 3. No new production code — this is CI/governance wiring and documentation.
- **Dependencies:** T-014.
- **Files impacted:** CI workflow under `.github/workflows/` (confirm the `*IT`/Testcontainers job is merge-blocking; adjust if the IT would otherwise be skipped), `docs/story/2-rbac/EPIC-002.md` (record the gate).
- **Complexity:** S
- **Risks:** `*IT` needs Docker/Testcontainers — confirm the CI runner provides it and that the suffix-`IT` Failsafe binding picks the test up (per project CI conventions). Do not let it land in a `-DskipITs` path that merges bypass.
- **Testing requirements:** Confirm a deliberately-broken cross-tenant assertion fails the merge-blocking job (verify the gate has teeth, then revert).
- **Definition of Done:** `CrossTenantPermissionIT` runs in the merge-blocking CI job; a failure blocks merge; EPIC-002 records it as an Epic-3 entry gate.

### T-011 — (Condition 3) Track the deferred "controller-must-be-annotated" rule as an Epic-3 entry criterion

- **Description:** The ArchUnit rule requiring every `@RestController` method to carry `@RequiresPermission` or an explicit opt-out (`@PublicEndpoint`) is **deferred** (design §B8, T-03) — there are no protected production controllers yet. This task does **not** build the rule. It records it as a named Epic-3 entry criterion so the first protected controller cannot merge before the rule + opt-out convention exist, and (per T-05) so a same-class self-invocation lint check is folded into that future rule. Lightweight: a forward-looking note plus a one-line addition to EPIC-002 tracking. No ArchUnit code in this story.
- **Dependencies:** none.
- **Files impacted:** `docs/story/2-rbac/EPIC-002.md` (add the Epic-3 entry-criterion line), optionally a short note in `docs/features/US-011/` cross-references.
- **Complexity:** S
- **Risks:** Being forgotten is the only risk — hence tracking it now. Explicitly note it is intentionally not built here to avoid false-positives on today's deliberately-`permitAll` auth endpoints.
- **Testing requirements:** None (documentation/governance).
- **Definition of Done:** EPIC-002 tracking carries an explicit Epic-3 entry criterion: "first protected controller cannot merge until the annotate-or-opt-out ArchUnit rule + `@PublicEndpoint` convention + same-class-call lint exist"; no ArchUnit code added in US-011.

---

## Tests

### T-012 — Unit: evaluator + reader

**Status: Complete (no new code required).** Audited after T-001/T-002/T-003/T-008/T-015 landed: every scenario below is already covered by `AuthenticatedRequestDetailsTest.java` and `TenantAwarePermissionEvaluatorTest.java` as a byproduct of those tasks' test-first implementation, including the `DenialReason` assertions T-008 added on every throw site. Confirmed via `./mvnw verify -DskipITs` (T-015's run: 661 tests, 0 failures, JaCoCo coverage gates met). No gaps found; no additional test methods were written for this task specifically.

- **Description:** JUnit 5 + Mockito, no Spring context (design §E.1). `TenantAwarePermissionEvaluatorTest` and `AuthenticatedRequestDetailsTest` covering: permission present → allow (FR1); present-but-missing → throws with `PERMISSION_ABSENT` (FR2); empty `permissions[]` → throws (Edge 1); `getDetails()` null/not-a-Map → throws `MALFORMED_AUTHENTICATION` (B4, Edge 5); `tenantId` absent/blank/non-String → throws `MISSING_TENANT` (B4/B5); `permissions` absent/wrong type → throws (B4/R4); `Authentication` null/unauthenticated → throws (B4). Assert the `DenialReason` on each throw (T-008).
- **Dependencies:** T-002, T-003, T-008.
- **Files created:** `nexus-backend/src/test/java/com/example/nexus/common/security/TenantAwarePermissionEvaluatorTest.java`, `nexus-backend/src/test/java/com/example/nexus/common/security/AuthenticatedRequestDetailsTest.java`
- **Complexity:** M
- **Risks:** R7 — no prior pattern for unit-testing this mechanism; budget exploration time. Ensure every deny branch is exercised (fail-closed coverage is the point).
- **Testing requirements:** Full branch coverage of §B4 deny conditions + happy path; assert exception type and reason, never a silent false/allow/500.
- **Definition of Done:** All §E.1 rows implemented and green; each deny branch asserts the correct `DenialReason`; meets the project JaCoCo gate.

### T-013 — Slice/MockMvc: wiring, 401-vs-403, `RBAC_001` shape

- **Description:** `RequiresPermissionMockMvcTest` reusing the `SecurityConfigTest` harness (`@SpringBootTest(webEnvironment=MOCK)` + H2 + `MockMvc` + `springSecurity()`, no Docker) targeting the T-006 fixture (design §E.2). Cases: authenticated **with** `tenant:write` → 200 (FR1/AC1); authenticated **without** → 403 + `RBAC_001` + `requiredPermission=tenant:write` + `detail` sentence (FR2/FR4); **no** JWT → 401 `AUTH_003`, evaluator never invoked (FR5/AC4); tampered JWT → 401 (filter rejects before evaluator, FR5, Scenario 5); `permitAll` endpoint (e.g. `/actuator/health`) still reachable with method security enabled (Edge 9/Gap 7); annotation on a fresh fixture method enforces with no extra wiring (FR6/AC5/AC7). The **positive+negative pair is a non-negotiable assertion** — it is the only proof the annotation is genuinely processed (neither fail-open nor always-fail-closed; T-10).
- **Dependencies:** T-004, T-005, T-006 (soft: T-008 if asserting log fields here).
- **Files created:** `nexus-backend/src/test/java/com/example/nexus/common/security/RequiresPermissionMockMvcTest.java`
- **Complexity:** M
- **Risks:** Getting `springSecurity()` + method-security proxying to activate in the slice; nested `@SpringBootTest` config inheritance gotcha (apply `@NestedTestConfiguration(OVERRIDE)` if nesting, per project memory). Confirm the templating defaults bean is present so the positive control actually 200s.
- **Testing requirements:** All §E.2 rows; the with/without pair mandatory; assert the full `RBAC_001` body shape and the 401-before-evaluator precedence.
- **Definition of Done:** All §E.2 rows green; positive+negative pair present; `permitAll` reachability asserted; `RBAC_001` body shape matches §C.1 exactly (`detail`, `requiredPermission`, `code`, `traceId`).

### T-014 — `CrossTenantPermissionIT` (Testcontainers)

- **Description:** The R1-Critical suite (design §E.3, Scenario 3, AC2/FR3) on Testcontainers MySQL 8.4 with real seeded RBAC data and real minted tokens. Seed user U with `user:read` via a role in Tenant A and `tenant:write` **only** via a role in Tenant B (reuse the second-tenant seeding pattern from `RoleResolutionServiceIT`). Mint U's real token in the Tenant-A context (`JwtRs256Service` + `RoleResolutionService`) → `permissions=[user:read]`, `tenant_id=A`. Call `GET /internal-test/guarded` (requires `tenant:write`) → assert **403 + `RBAC_001`** (Tenant-B grant absent from the Tenant-A token). Positive control: same user, token minted for the tenant where they *do* hold `tenant:write` → 200.
- **Dependencies:** T-005, T-006 (and the existing real mint path).
- **Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/security/CrossTenantPermissionIT.java`
- **Complexity:** L
- **Risks:** Requires Docker/Testcontainers (MySQL 8.4, `nexus_app` grants callback); BINARY(16) UUID seeding correctness; two-tenant seed setup. Must be the `*IT` suffix so Failsafe runs it. This is the single end-to-end proof of the Critical property — correctness of the seed is load-bearing.
- **Testing requirements:** Both rows (403 cross-tenant + 200 positive control) green against real MySQL; no H2 (per project convention `*IT` = Testcontainers only).
- **Definition of Done:** Cross-tenant call returns 403 `RBAC_001`; positive control returns 200; runs under `./mvnw verify`; ready to be wired as the T-010 merge gate.

---

## Architecture governance

### T-015 — ArchUnit: ban Spring Security in `domain`/`application` (§B8 ADD)

- **Description:** Add the rule mirroring the existing Redis ban: `noClasses().that().resideInAnyPackage("..domain..", "..application..").should().dependOnClassesThat().resideInAnyPackage("org.springframework.security..").allowEmptyShould(true)`. Prevents `@PreAuthorize`/`Authentication` types leaking inward as the pattern spreads across contexts. Verified safe today — zero `domain`/`application` classes import Spring Security (design §B8, grep). This is the rule to **ADD**; the controller-must-be-annotated rule is the **deferred** one (tracked in T-011, not built).
- **Dependencies:** none.
- **Files impacted:** `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- **Complexity:** S
- **Risks:** Use `allowEmptyShould(true)` to avoid ArchUnit failing on an empty match set. Confirm the rule does not flag `common.security` (which matches no layer pattern) or the new config.
- **Testing requirements:** Rule green on the current tree; prove it fails on a scratch Spring Security import inside a `domain`/`application` class, then revert.
- **Definition of Done:** Rule added and green; demonstrated to catch an inward Spring Security dependency; does not false-flag `common.security` or `config`.

---

## Documentation

### T-016 — (Condition 4) Step-9 developer-guide entry — hard deliverable

- **Description:** A developer-facing guide for the first custom security annotation, made a **hard deliverable of this story** (Condition 4), not deferred as optional `/docs` debt. Must cover: `@RequiresPermission("resource:action")` usage; the permission-string-only shape (single permission, no AND/OR — §B9); the `RBAC_001` 403 response shape (`detail` + `requiredPermission`); the 401-vs-403 boundary (no/invalid JWT → 401 at the filter, before the evaluator); that a typo'd permission string is **not** validated at startup and manifests as a permanent 403 (fail-closed — §B9/Edge 6); and — prominently — the **Spring AOP self-invocation caveat** (annotated methods called from within the same bean bypass the proxy and are silently unenforced; annotate the entry point, not an internal helper, or split beans — T-05/Edge 7/R8).
- **Dependencies:** T-003, T-005, T-006.
- **Files impacted:** the developer-facing guide (confirm exact home with the `/docs` owner — likely `SECURITY.md` §Authorization or `docs/coding-standards.md`; the `.claude/skills/spring-boot-standards` skill may also warrant a pointer).
- **Complexity:** S
- **Risks:** The self-invocation warning is the highest-value content (EoP-class limitation) — it must be prominent, not a footnote. Confirm the canonical guide location rather than creating an orphan doc.
- **Testing requirements:** None (documentation). Content review against the six required topics above.
- **Definition of Done:** Guide entry exists in the canonical developer-facing location, covers all six topics, and gives the self-invocation warning prominent placement with the correct annotate-the-entry-point pattern.

---

## Traceability summary

| Requirement / AC | Task(s) |
|---|---|
| FR1/FR2 (allow/deny) | T-003, T-012, T-013 |
| FR3/AC2 (cross-tenant 403) | T-014 (+ upstream invariant T-007) |
| FR4/AC3 (`RBAC_001` shape, amended `detail`/`requiredPermission`) | T-005, T-013 |
| FR5/AC4 (401 before check, tampered JWT) | T-013 |
| FR6/AC5/AC7 (usable anywhere, no extra wiring) | T-003, T-006, T-013 |
| FR7 (no DB per request) | T-002, T-003 (design-enforced; no DB task exists) |
| FR8/AC6 (<5ms) | Met by construction (in-memory `Set.contains`); no perf task (design §E) |
| FR9 (distinct exception → distinct contract) | T-001, T-005 |
| FR10 (`@EnableMethodSecurity` global) | T-004 |
| Cond 1 / T-02 | T-007 |
| Cond 2 / T-02 | T-010 (gate) + T-014 (test) |
| Cond 3 / T-03 | T-011 |
| Cond 4 / T-05 | T-016 |
| Cond 5 / T-08 | T-008 |
| Cond 6 / T-06, T-10 | T-009 (+ positive/negative pair in T-013) |
| ArchUnit ban (§B8 ADD) | T-015 |

---

**Files touched across the story** (exact paths, for the review checklist):

*Production (new):* `common/security/InsufficientPermissionException.java`, `common/security/AuthenticatedRequestDetails.java`, `common/security/RequiresPermission.java`, `common/security/TenantAwarePermissionEvaluator.java`, `common/security/AuthenticationDetailKeys.java` (Condition 6 — beyond original §F), `config/MethodSecurityConfig.java`.
*Production (modified):* `common/web/GlobalExceptionHandler.java`, `identity/infrastructure/web/JwtAuthenticationFilter.java` (Condition 6 — literal→constant only, no behaviour change). `SecurityConfig.java` is intentionally **not** modified.
*Test (new):* `support/web/GuardedTestController.java`, `support/web/GuardedTestControllerConfig.java`, `common/security/TenantAwarePermissionEvaluatorTest.java`, `common/security/AuthenticatedRequestDetailsTest.java`, `common/security/RequiresPermissionMockMvcTest.java`, `common/security/AuthenticationDetailsContractTest.java`, `rbac/security/CrossTenantPermissionIT.java`, `identity/infrastructure/security/JwtRs256ServiceTenantProvenanceTest.java` (or added to existing), optional `architecture/AuthenticationProducerGuardTest.java`.
*Test (modified):* `architecture/HexagonalArchitectureTest.java`, `common/web/GlobalExceptionHandlerTest.java` (if present).
*Docs/governance:* `docs/adr/0013-rbac-data-model-and-enforcement-contract.md`, `docs/story/2-rbac/EPIC-002.md`, developer-facing guide (T-016), CI workflow under `.github/workflows/` (T-010).

---

Two flags worth attention before implementation begins: T-004 requires confirming the `AnnotationTemplateExpressionDefaults` class name against the pinned Spring Security version (renamed 6.3→6.4), and T-016's canonical guide location should be confirmed with the `/docs` owner rather than assumed.
