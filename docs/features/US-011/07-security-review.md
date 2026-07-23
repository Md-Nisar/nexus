# US-011 — Security Review (Step 7 / Code Audit)

_Output of Step 7 (`/security-review` in **code-audit mode**). Diff-based, hostile-mindset OWASP Top 10 / STRIDE audit of the **shipped, tested** implementation on branch `feature/US-011`. Distinct from the Gate-2 design-phase STRIDE analysis (`03b-threat-model.md`), which reviewed the design. This review verifies each design-phase condition against real code and independently hunts for implementation-level bugs the design review could not have caught._

**Verdict: PASS (no Blockers).** All five required + one recommended conditions from the Gate-2 threat model are present and correctly implemented in code. Fail-closed is genuinely achieved on every branch. No new exploitable defect found. Two **Low** items (one doc gap, one residual guard-scope note) are recorded for completeness — neither blocks the gate.

---

## 0. Scope and method

**Changeset audited** (`git diff` + untracked, working tree, no commits):

- **New production:** `common/security/{AuthenticatedRequestDetails, TenantAwarePermissionEvaluator, AuthenticationDetailKeys, DenialReason, InsufficientPermissionException, RequiresPermission}.java`, `config/MethodSecurityConfig.java`.
- **Modified production:** `common/web/GlobalExceptionHandler.java`, `identity/infrastructure/web/JwtAuthenticationFilter.java`, `identity/interfaces/rest/UserProfileController.java`, `spotbugs-exclude.xml`.
- **Test infra (security-relevant):** `support/web/GuardedTestController{,Config}.java`, `rbac/security/CrossTenantPermissionIT.java`, `architecture/HexagonalArchitectureTest.java` (2 new rules), `common/security/*Test.java`, `identity/.../JwtRs256ServiceTest.java` (provenance contract test), `.github/workflows/maven.yml`.
- **Confirmed unchanged:** `nexus-backend/pom.xml` (zero diff) - no new dependency (A06 baseline below).

**Every file above was read in full.** Dependency scan run (`./mvnw -o dependency:tree`) - results in section A06.

**Explicit review attestation (per policy - auth / crypto / PII code is never approved silently):**
- **Authentication:** the whole model rests on the upstream RS256 verify path (`JwtRs256Service.verify`, US-010). This story does not touch it; the tampered-token MockMvc test proves an invalid-signature/injected-claims token is rejected at the filter with 401 `AUTH_003` **before** the evaluator runs (`verifyNoInteractions(permissionEvaluator)`). Reviewed - sound and load-bearing.
- **Cryptography:** no new crypto introduced by this story. `SecureRandom`/`Math.random` - not applicable; the only randomness in the touched code is `UUID.randomUUID()` in test seeding, never a security token. Nothing to flag.
- **PII (org policy - never include customer PII):** every new/modified log field and metric tag was traced end to end (see Logging). All are UUIDs, enum names, closed-vocabulary permission strings, or `correlationId`. No email, name, or free text is logged or returned. Policy satisfied.

---

## 1. Verification of the Gate-2 threat-model conditions against shipped code

The design-phase review (`03b-threat-model.md`) closed with **APPROVE WITH CONDITIONS** - 5 required + 1 recommended. Each is verified below against the real implementation.

| # | Condition (from 03b section 6) | Shipped implementation | Verified |
|---|---|---|---|
| 1 (T-02) | Document the tenant-provenance invariant on the evaluator + ADR-0013; contract-test that `JwtRs256Service.issue` sources `permissions[]` and `tenant_id` from the same tenant; ArchUnit guard that the filter is the sole producer | Class Javadoc on `TenantAwarePermissionEvaluator` L15-29 states the invariant verbatim; `JwtRs256ServiceTest.should_sourcePermissionsResolutionAndTenantClaim_fromSameTenantId` captures the `RoleResolutionService.resolve` tenant arg and asserts it equals `user.getTenantId()` and the minted `tenant_id` claim; ArchUnit rule `only_jwtAuthenticationFilter_sets_authentication_details` in `HexagonalArchitectureTest` | **Yes** (see A01 for the guard scope caveat) |
| 2 (T-02) | Make `CrossTenantPermissionIT` a hard, merge-blocking CI gate; seed grants in both tenants | `CrossTenantPermissionIT` runs on `RANDOM_PORT` through the **real** embedded server + production filter chain (not MockMvc), seeds U with `user:read` in tenant A and `tenant:write` only in tenant B, mints a real tenant-A token, asserts 403 `RBAC_001`; positive control mints for tenant B returns 200. `maven.yml` documents the full-`verify` (no `-DskipITs`) merge-blocking step | **Yes - genuine, non-theatrical proof** |
| 5 (T-08) | Add a `reason` discriminator separating malformed/fail-closed denials from routine "lacks permission" | `DenialReason{PERMISSION_ABSENT, MALFORMED_AUTHENTICATION, MISSING_TENANT}`, carried on the exception, emitted as a structured log field and a low-cardinality counter tag `reason=` | **Yes** |
| 6 (T-06) | Single-source the detail-map keys; add a producer-side contract test | `AuthenticationDetailKeys` (keys + MDC keys) referenced by the filter, reader, and `UserProfileController`; `AuthenticationDetailsContractTest` drives the **real filter** and feeds the resulting `Authentication` to the reader | **Yes** |
| 4 (T-05) | Make the self-invocation developer-guide warning a hard deliverable | Documented in `RequiresPermission` Javadoc L24-26 (self-invocation not intercepted) + T-016. (Distinct final/private gap - see F-1 below) | **Yes** (self-invocation); partial (final/private) |
| 3 (T-03) | Track the deferred "every controller annotated" ArchUnit rule as an Epic-3 entry criterion | Deferred by design; no live exposure (only the test fixture is annotated) - out of scope for this story code | N/A this story |

**Conclusion:** the implementation did not merely accept the conditions - it landed all of them. T-09 (`requiredPermission` echo) and T-10 (templating) are re-confirmed below; T-13 remains a pre-existing, non-US-011, non-attacker-reachable latency item.

---

## 2. Adversarial OWASP Top 10 pass (independent of the design review)

### A01 - Broken Access Control / cross-tenant escalation (the epic top risk)

**Traced independently: can `permissions[]` and `tenant_id` on one `Authentication` originate from different tenants?**

- **Mint path (only current producer):** `JwtAuthenticationFilter` copies `claims.tenantId()` and `claims.permissions()` off a single verified `JwtClaims` onto one `Map.of(...)` details object (L80-84). Both come from the same signed token; they cannot diverge in the filter. Upstream, `JwtRs256Service.issue` resolves both from the same `user.getTenantId()` - now **locked by a regression test** (condition 1). The double tenant predicate in `findActivePermissionNames` remains the defense-in-depth backstop. **No divergence path in current code.**
- **Fail-closed on the consumer side:** every branch of `AuthenticatedRequestDetails.fromAuthentication` throws `InsufficientPermissionException` (403) rather than returning/allowing - null/unauthenticated auth, non-`Map` details, absent/blank/non-`String` `tenantId`, absent/non-`List`/non-`String`-element `permissions`. The evaluator only ever returns `true`; every negative path throws. Confirmed by 20+ unit assertions across `AuthenticatedRequestDetailsTest` + `TenantAwarePermissionEvaluatorTest` covering exactly these type-confusion / empty-vs-null / wrong-collection-type inputs.
- **Sole-producer guard:** the ArchUnit rule prevents a second production class from calling `Authentication.setDetails(...)`. This closes the most likely future regression (a new `AuthenticationProvider` or filter). **Residual scope caveat: see F-2.**

**Assessment:** the Critical property holds by construction today and is now documented, contract-tested, and structurally guarded - exactly the state the threat model demanded. No new access-control defect. **No IDOR / object-level concern applies** - this story issues no queries and reads no request-supplied identifiers; object-level tenant matching remains each consuming story service-layer job (correctly out of scope).

### A02 - Cryptographic failures
No new crypto. Token integrity rests on the reviewed RS256 path. No key material, no algorithm choice, no randomness introduced by the diff. Nothing to flag.

### A03 - Injection (SQL / JPQL / command / SpEL)
- **No queries** issued by any new/modified class - enforcement reads JWT claims already on the `Authentication`. No SQL/JPQL surface added.
- **SpEL injection:** the `@PreAuthorize("@permissionEvaluator.hasPermission(authentication, '{value}')")` template `{value}` is substituted **only** from the annotation compile-time `String value()` literal, via Spring Security `AnnotationTemplateExpressionDefaults`. Grepped all `@RequiresPermission` usages - every one is a hard-coded literal (`"tenant:write"`, `"user:read"`); there is **no** dynamic/reflective construction of the annotation or runtime assembly of the permission string anywhere. No request-derived data can reach the SpEL. **No injection, and no per-request parse (expression compiled + cached).**

### A04 - Insecure design
The named-bean SpEL shape (not Spring `PermissionEvaluator` interface) is honest to the two values actually used and avoids a misleading `null` target. Fail-closed-by-throwing is the correct default. Design is sound as built.

### A05 - Security misconfiguration
- **`@EnableMethodSecurity` default:** `prePostEnabled` defaults to `true`, so `@PreAuthorize` is enforced by the `AuthorizationManagerBeforeMethodInterceptor` **before** method execution - verified this is Spring Security actual default (not `@PostAuthorize`-only). The positive MockMvc control (200 with permission) proves the annotation is genuinely processed, not silently fail-open; the negative (403 without) proves it is not always-fail-closed. This positive/negative pair is the T-010 verification requirement - **present and green.**
- **Templating class name:** the design flagged uncertainty over `AnnotationTemplateExpressionDefaults` across Spring Security 6.3 to 6.4. Dependency tree confirms **Spring Security 7.1.0**; the import `org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults` resolves and the 200 positive control confirms substitution works. Correct.
- **Proxy mode:** default Boot CGLIB proxies; `GuardedTestController` methods are `public` and non-`final`, so they are proxied and the guard applies. (See F-1 for the final/private caveat as a forward doc item.)

### A06 - Vulnerable and outdated components
`pom.xml` has **zero diff** - this story adds **no new dependency**. `@EnableMethodSecurity`, `@PreAuthorize`, `AnnotationTemplateExpressionDefaults`, and `MeterRegistry`/`Counter` all ship with already-present starters. Dependency tree (offline): `spring-security-* 7.1.0`, `micrometer-core 1.17.0` - both current for the Boot 4.1 line, no known applicable critical CVE. A story-specific `dependency-check:check` re-run for **new** dependencies is not warranted; the scheduled OWASP dependency-check job covers the transitive baseline. **Frontend: no changes in this story, so `npm audit` is not applicable.**

### A07 - Identification & authentication failures
Unchanged. The filter token validation, 401-before-evaluator behaviour, and MDC lifecycle (`finally` clears `userId`/`tenantId` around `chain.doFilter`) are intact; the only diff is swapping string literals for `AuthenticationDetailKeys` constants - behaviour-preserving. No replay/expiry/refresh logic touched.

### A08 - Software & data integrity failures
No deserialization, no plugin/update mechanism, no unsigned-artifact path introduced. The `Authentication.getDetails()` map is produced and consumed in-process; the reader validates its shape defensively rather than trusting it. No concern.

### A09 - Security logging & monitoring failures
Materially **improved**: the `DenialReason` discriminator (log field + counter tag) lets operators separate a probing/malformed-authentication spike (`MALFORMED_AUTHENTICATION` / `MISSING_TENANT`) from benign `PERMISSION_ABSENT` noise - closing threat-model T-08. The WARN denial log now emits `userId`/`tenantId` (from MDC, still populated because the denial is thrown inside the filter `try` before its `finally`), `requiredPermission`, `reason`, `errorCode`, `correlationId`, `errorType`. Forensic context is complete. (No audit-stream event - accepted scope call, T-07.)

### A10 - SSRF
No outbound requests, URL fetching, or user-controlled destinations anywhere in the diff. Not applicable.

---

## 3. Focused adversarial angles (from the tasking)

- **Type confusion / unusual `Authentication`:** attempted - `getDetails()` returning a non-`Map`, a `Map` with wrong-typed `tenantId` (Integer), `permissions` as a `Set` instead of `List`, a `List` containing a non-`String` element, empty vs. null, unauthenticated token. **Every one is covered by an explicit unit test and fails closed** (throws, 403). The `instanceof` pattern-match guards (`instanceof Map<?,?>`, `instanceof String`, `instanceof List<?>` + `allMatch(String.class::isInstance)`) reject all of these before any cast. No type-confusion bypass.
- **SpEL injection:** no dynamic annotation construction exists - confirmed by reading every usage. Closed.
- **Information disclosure:** the 403 body sets only `code`, `traceId`, static `detail` sentence, and `requiredPermission`. Critically, the internal `reason` enum is emitted to **logs only**, never to the response body - verified in `handleInsufficientPermission` (response gets `requiredPermission` only). `problem()` never serializes a stack trace, class name, or SQL. `InsufficientPermissionException` message embeds only the fixed annotation literal and is never rendered to the client (the client sees the static sentence). `requiredPermission` is a closed 7-item, code-defined vocabulary - non-sensitive (T-09 re-confirmed acceptable). No leak.
- **DoS / resource exhaustion:** the hot path is `Set.copyOf` (n <= 7) + `Set.contains` - O(n) build, O(1) lookup, no I/O, no reflection per request, SpEL compiled once and cached. Unauthenticated callers are stopped at the filter (401) and never reach the evaluator. An attacker cannot inflate `permissions[]`: the claim is RS256-signed and tamper-rejected before the evaluator (proven by the tampered-token test). No amplification.
- **Logging/PII:** every field re-traced - all UUID / enum / closed-vocabulary / correlationId. `MDC.get` returning `null` (e.g. a foreign `Authentication` where the filter never set MDC) is safely handled (`LinkedHashMap` + slf4j fluent `addKeyValue` both accept null) - no NPE, no leak. `CrossTenantPermissionIT` seeds a synthetic example.com address only in the test DB; it is never logged. Org PII policy satisfied.

---

## 4. Findings

### [Low] F-1 - `@RequiresPermission` on a `final`/`private` method silently fails **open**, and this is not documented alongside the self-invocation warning
**File:** `nexus-backend/src/main/java/com/example/nexus/common/security/RequiresPermission.java:24-26`
**Issue:** Spring AOP cannot proxy `final` or `private` methods. A `@RequiresPermission` annotation placed on such a method is **silently ignored** - the interceptor never runs and the method executes unguarded (fail-**open**), unlike the self-invocation case which the Javadoc does document. The annotation Javadoc and T-016 cover self-invocation but not this distinct proxy-shape gap.
**Risk:** A future contributor marks a guarded controller method `final` (or a private handler helper) and ships an endpoint that appears protected but is reachable by any authenticated user of any tenant. Not exploitable in this story (the only annotated methods - the test fixture - are `public` non-`final`, verified), but it is a real, distinct EoP-class footgun on the epic core control.
**Fix:** Add one sentence to the `RequiresPermission` Javadoc and the T-016 developer-guide entry: `@RequiresPermission` must be placed on a `public`, non-`final` method of a Spring-managed bean; on a `final`/`private` method it is silently not enforced. Fold a same-class-call / non-public-method lint into the Epic-3 "every controller annotated" ArchUnit rule (already tracked as an Epic-3 entry criterion per T-03).

### [Low] F-2 - ArchUnit sole-producer guard is a tripwire on `setDetails(...)`, not a proof; an overridden `getDetails()` or reflection would evade it
**File:** `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java` (`only_jwtAuthenticationFilter_sets_authentication_details`)
**Issue:** The rule is correctly scoped (`ImportOption.DoNotIncludeTests` - so test fixtures that call `setDetails` do not false-trip it, and only production producers are guarded) and it does catch the realistic future regression: a second production class calling `Authentication.setDetails(...)`. It does **not** catch two narrow paths to populate `Authentication.getDetails()` without a `setDetails` call: (a) a bespoke `Authentication` subclass overriding `getDetails()` to return a permissions-bearing map, and (b) reflective population. Both would carry a `permissions` detail past the evaluator without tripping the guard.
**Risk:** Purely theoretical for now - both require a deliberate, unusual new class that would itself demand review; and the evaluator class-Javadoc invariant already binds any such author to reuse the tenant-scoped path. Consistent with the threat model own framing of the guard as a tripwire, not a formal proof. No path to this exists in current code.
**Fix:** None required for this story. Optionally, when the Epic-3 rule lands, broaden the guard to also flag production classes that override `Authentication.getDetails()` or subclass `AbstractAuthenticationToken` outside `identity.infrastructure.web`. Record as residual risk, not an action item.

---

## 5. Threats confirmed adequately handled (no action)

| Ref | Concern | Why adequate (verified in code) |
|---|---|---|
| T-01 / A02 | Forged / injected-`permissions` JWT | RS256 verify + alg pinning reject before the evaluator; tampered-token MockMvc test asserts `verifyNoInteractions(evaluator)` |
| T-04 | Anonymous / foreign `Authentication` at a guarded method | Non-`Map` details give fail-closed 403; unit-tested |
| T-09 | `requiredPermission` echoed in 403 body | Closed 7-item non-secret vocabulary; caller already authenticated |
| T-10 / A05 | Meta-annotation templating misconfig | Positive+negative MockMvc pair proves genuine processing; class name correct for SS 7.1 |
| T-11 / A03 | SpEL injection | `{value}` is a compile-time literal; no dynamic annotation construction anywhere |
| T-12 / DoS | Enforcement-path amplification | In-memory `Set.contains`, n <= 7, no I/O; unauth stopped at filter |
| PII | Logs & 403 body | Only UUIDs / enum / closed vocabulary / correlationId; `reason` is log-only, never in the response |
| A06 | New vulnerable dependency | `pom.xml` unchanged; no new dependency |

**Pre-existing, not this story (forward-flag only):** T-13 - a validly-signed token missing `tenant_id` NPEs into a 500 inside the frozen `JwtAuthenticationFilter` (`Map.of` rejects null), before the evaluator. Not attacker-reachable (only the server mints signed tokens; `issue()` always sets `tenant_id`). Belongs to a future EPIC-001 hardening ticket, unchanged by US-011.

---

## 6. Verdict

### PASS

- **Blockers: 0.** Nothing in this changeset is exploitable.
- **High: 0. Medium: 0.**
- **Low: 2** (F-1 documentation gap on final/private fail-open; F-2 residual ArchUnit guard-scope note) - neither blocks the Step-7 gate (which requires only *no Blockers*).

This is a clean bill of health on an already-hardened implementation. The Gate-2 threat model Critical concern (T-02 cross-tenant escalation) was not merely acknowledged - the code documents the invariant on the evaluator, locks it with a `JwtRs256Service.issue` provenance regression test, guards it with an ArchUnit sole-producer rule, and proves it end-to-end through the real filter chain in `CrossTenantPermissionIT` (now a documented merge-blocking CI gate). Fail-closed is genuinely achieved on every branch, verified against adversarial type-confusion / empty-vs-null / wrong-collection inputs. Auth, crypto, and PII concerns were each explicitly reviewed (section 0 attestation): the RS256 gate is intact, no new crypto is introduced, and every logged/returned field is a UUID, enum, or closed-vocabulary string - the org PII policy is satisfied.

The two Low findings are forward-looking hardening for the Epic-3 controller-annotation gate; recommend folding F-1 into the T-016 developer guide now (one sentence) and F-2 into the deferred Epic-3 ArchUnit rule.

---

### Cross-references
- Threat model (design phase): `docs/features/US-011/03b-threat-model.md`
- Design: `docs/features/US-011/03-design.md`
- Code review: `docs/features/US-011/06-code-review.md`
- Story: `docs/story/2-rbac/US-011.md`
- Key code: `common/security/*`, `config/MethodSecurityConfig.java`, `common/web/GlobalExceptionHandler.java`, `identity/infrastructure/web/JwtAuthenticationFilter.java`, `architecture/HexagonalArchitectureTest.java`, `rbac/security/CrossTenantPermissionIT.java`
