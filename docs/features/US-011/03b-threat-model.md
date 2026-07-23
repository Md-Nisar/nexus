# US-011 — STRIDE Threat Model: Enforce permission checks on API endpoints via Spring Security

_Output of Step 3b (`/security-review` in threat-model mode). Gate-2 deliverable. Adversarial STRIDE analysis of the `03-design.md` solution. Feeds the task breakdown (Step 4)._

**Scope of this analysis:** the design in `docs/features/US-011/03-design.md` — the `@RequiresPermission` meta-annotation, `TenantAwarePermissionEvaluator` (named-bean SpEL), `AuthenticatedRequestDetails` fail-closed reader, `InsufficientPermissionException`, `MethodSecurityConfig`, and the new `GlobalExceptionHandler` branch. The upstream token-mint/verify path (US-010, EPIC-001) is in scope only as a **trust dependency** of the central B5 claim.

**Verification basis (code re-read this session, not trusted from the design doc):**
- `JwtAuthenticationFilter.java` — builds `UsernamePasswordAuthenticationToken(sub, null, ROLE_* authorities)`, `setDetails(Map.of("tenantId", "emailVerified", "tokenVersion", "permissions"))` (L79–83); on invalid token clears context + entry point 401 (L87–92); MDC `userId`/`tenantId` set L85–86, cleared in `finally` L96–97 **around `chain.doFilter`** (L94).
- `JwtRs256Service.java` — `issue()` resolves `permissions[]` via `roleResolutionService.resolve(user.getId(), user.getTenantId())` (L72–73) and writes `tenant_id = user.getTenantId().toString()` (L81) — **same tenant value for both**. `verify()` pins RS256 (L115–118), guards `alg=none`/HS256-confusion, but does **not** null-check `tenant_id` (L141).
- `RoleResolutionService.java` — `resolve()` `requireNonNull`s both ids (fail-closed, L54–55); cache keyed `(tenantId, userId)`.
- `JpaUserRoleRepository.findActivePermissionNames` — **double tenant predicate** `ur.tenantId = :tenantId AND r.tenantId = :tenantId` (L49–50), explicitly documented as defense-in-depth against a future assignment-time cross-tenant leak.
- `SecurityConfig.java` — `@EnableWebSecurity` only; `.anyRequest().authenticated()` (L85); filter-chain `AccessDeniedHandler` → `ACCESS_DENIED` (L115–125); `AuthenticationEntryPoint` → `AUTH_003` 401 (L98–108).
- `GlobalExceptionHandler.java` — generic `@ExceptionHandler(AccessDeniedException.class)` → `ACCESS_DENIED`, WARN (L134–139); `logHandledException` emits `correlationId` but **not** `userId`/`tenantId` as structured fields today (L161–183); `problem()` builds RFC-7807 with `code` + `traceId` (L185–190).
- `JwtClaims.java` — `tenantId` is `String` (L17); `permissions` `List<String>`, defensively copied (L21, L34); doc asserts "Contains no PII — `sub` is a UUID, `email` intentionally absent."

**Explicit review attestation (per policy — auth/crypto/PII code is never approved silently):**
- **Authentication:** RS256 signature verification, algorithm pinning, and alg-confusion guards reviewed in `JwtRs256Service.verify` — sound and load-bearing for this whole model.
- **Cryptography:** no new crypto introduced by this story; token integrity rests on the existing RS256 signature (reviewed).
- **PII:** the denial log fields (`userId`, `tenantId`) and the 403 response body were reviewed against the org PII rule — both are UUIDs, no name/email/PII; `JwtClaims` is PII-free by contract. No PII exposure identified in this design.

---

## 1. Trust boundaries and data flow

```
[ Internet / hostile client ]
        |  Authorization: Bearer <JWT>
        v
  === TB1: network -> app ===
  CorrelationIdFilter -> LoginRateLimitFilter -> JwtAuthenticationFilter
        |  (RS256 verify; on fail -> 401 AUTH_003, chain short-circuits)
        |  on success: SecurityContext.authentication = UsernamePasswordAuthenticationToken
        |              .details = Map{tenantId, permissions, emailVerified, tokenVersion}
        v
  === TB2: filter chain -> dispatcher (authenticated) ===
  .anyRequest().authenticated()  (filter-chain authz: authN only, NOT permission)
        v
  === TB3: dispatcher -> method-security proxy (@EnableMethodSecurity) ===
  @PreAuthorize("@permissionEvaluator.hasPermission(authentication, '<perm>')")
        |
        v  TenantAwarePermissionEvaluator.hasPermission
           -> AuthenticatedRequestDetails.fromAuthentication(auth)  [fail-closed read]
           -> Set.contains(requiredPermission)
        | allow -> controller
        \ deny  -> throw InsufficientPermissionException (403 RBAC_001)
                  -> HandlerExceptionResolver -> GlobalExceptionHandler (WARN + counter)
```

Components analysed: **C1** `JwtAuthenticationFilter` (dependency, not modified); **C2** `AuthenticatedRequestDetails` reader; **C3** `TenantAwarePermissionEvaluator`; **C4** `@RequiresPermission` + `MethodSecurityConfig` (SpEL/AOP wiring); **C5** `GlobalExceptionHandler` denial branch; **C6** the upstream mint path `JwtRs256Service.issue` + `RoleResolutionService` (dependency of the B5 claim).

---

## 2. Component-by-component STRIDE table

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **C1** JwtAuthenticationFilter (dep.) | Forged/alg-confusion token → covered by RS256 verify (T-01) | Injected `permissions` claim → signature fails → 401 (T-01) | n/a | `tenant_id`-absent validly-signed token → `Map.of` NPE → 500 (T-13, low) | — | Anonymous/foreign `Authentication` reaching evaluator (T-04) |
| **C2** AuthenticatedRequestDetails reader | — | Stringly-typed key contract vs. filter (T-06) | — | Fail-closed avoids 500 leak (good, B4) | Malformed details → throw, no I/O (safe) | Untyped `Map` cast, first non-log consumer (T-06) |
| **C3** TenantAwarePermissionEvaluator | Trusts token provenance blindly (T-02) | — | Denial trace depends on C5 (T-07) | `requiredPermission` echoed to caller (T-09, low) | O(n) in-mem, no amplification (safe) | **Cross-tenant boundary — B5 (T-02, top finding)** |
| **C4** `@RequiresPermission` / SpEL / AOP | — | `{value}` is compile-time constant, no SpEL injection (T-11, safe) | — | — | SpEL compiled+cached, no per-req parse (safe) | Self-invocation bypass (T-05); unannotated endpoint (T-03); templating misconfig fail-mode (T-10) |
| **C5** GlobalExceptionHandler denial | — | — | No audit-stream event; WARN+counter only (T-07) | Generic message, no internals (good) | — | Fail-closed vs. routine denial indistinguishable in logs (T-08) |
| **C6** mint path (dep.) | — | Double tenant predicate in SQL (strong, verified) | — | — | — | **Linchpin of B5** — token tenant-scoping (T-02) |

---

## 3. Findings

Ordered with the cross-tenant boundary (B5) first, per the epic's own risk register (Critical impact).

---

### [High] T-02 — Cross-tenant boundary is enforced entirely upstream, with zero local backstop in this story's code (B5)

**Component:** C3 evaluator / C6 mint path. **STRIDE:** Elevation of Privilege. **OWASP:** A01 (Broken Access Control), A04 (Insecure Design).

**The design's claim (B5):** there is no tenant-to-tenant comparison in this story; the boundary holds "by construction" because US-010 resolves `permissions[]` scoped to the caller's own `tenant_id` at mint time, so a Tenant-A token can never carry a Tenant-B-only grant. The evaluator does a flat `Set.contains` plus a presence/non-blank guard on `tenant_id`.

**Adversarial verification — where the claim holds:**
- Confirmed in code that `JwtRs256Service.issue` uses `user.getTenantId()` for **both** the permission resolution (L72–73) and the `tenant_id` claim (L81) — they cannot diverge on this path.
- Confirmed `findActivePermissionNames` applies a **double** tenant predicate (`ur.tenantId = :tenantId AND r.tenantId = :tenantId`), itself already documented as defense-in-depth against an assignment-time cross-tenant leak. The upstream scoping is genuinely robust.
- `RoleResolutionService` fails closed (`requireNonNull`) rather than resolving against a default/unscoped tenant.

So for **the single mint path that exists today**, the functional guarantee is sound and the `CrossTenantPermissionIT` (which seeds a user with `tenant:write` only in Tenant B and asserts 403 on a Tenant-A token) genuinely proves it end-to-end.

**Where the claim is fragile — the residual risk:**
The evaluator performs **no** tenant reasoning of its own; it blindly trusts that whatever `permissions[]` sits on the `Authentication` is tenant-consistent with the `tenant_id` on the same `Authentication`. B4's fail-closed logic only rejects *malformed/absent* details — it does **not** and **cannot** detect a *well-formed but semantically cross-tenant* `Authentication`. The entire Critical-rated boundary therefore depends on a single invariant — _"the only producer of an authenticated `Authentication` with a `permissions` detail is a tenant-scoped mint path"_ — that is:
1. maintained in a **different component** (`JwtRs256Service.issue`), already shipped, that this story does not touch or test;
2. **not asserted anywhere** in this story's code (no comparison, no consistency check);
3. **not protected by any structural guard** against a future second producer.

Concrete future break scenarios (all plausible in Epic 3+):
- An **admin-impersonation / "act-as" / tenant-switch** feature that mints or mutates an `Authentication` where `tenant_id` and `permissions[]` are assembled from different tenant contexts.
- A **service-to-service / batch token** or internal `Authentication` built without going through `RoleResolutionService`.
- A **test utility** (`@WithMockUser`, a hand-rolled token) that leaks into a shared path or sets a precedent contributors copy.
- A refactor routing authentication through an `AuthenticationManager`/provider that reconstructs `details`.

In every case the evaluator silently returns `true` for a permission the caller only holds in another tenant → **cross-tenant privilege escalation**, the epic's single highest-consequence failure mode — and no test in this story would catch it, because they all exercise the current mint path.

**Risk:** A future Authentication-producing code path (not caught by this story's tests or any guard) grants a caller a permission scoped to a different tenant. Silent, no error, full cross-tenant escalation.

**Design's mitigation:** insufficient as *defense-in-depth* for a Critical-rated property, though sufficient for *current functional correctness*. Relying 100% on an upstream invariant with no local assertion, no binding test, and no guard against alternate producers is not safe engineering for the epic's named highest-consequence control.

**Required mitigations (task-breakdown items):**
1. **Bind the invariant with a named, tested contract.** Add a class-level Javadoc/ADR statement on `TenantAwarePermissionEvaluator`: _"This evaluator assumes `permissions[]` on the `Authentication` were resolved for the same tenant as the `tenant_id` detail. This invariant is guaranteed ONLY by `JwtRs256Service.issue` + `RoleResolutionService`. Any new code that constructs an authenticated `Authentication` with a `permissions` detail MUST reuse that tenant-scoped resolution."_ Reference it from ADR-0013.
2. **Add a provenance/contract regression test** asserting `JwtRs256Service.issue` sources both the `permissions` resolution and the `tenant_id` claim from the *same* `user.getTenantId()` (locks C6 so a future refactor that decouples them fails a test).
3. **Guard against a second producer.** Add a test/ArchUnit-style assertion that `JwtAuthenticationFilter` is the only production code that calls `setDetails(...)` with a `permissions` key (or, equivalently, the only builder of an authenticated token carrying that detail). If a second producer appears, this must fail and force an explicit review of the B5 invariant.
4. **Make `CrossTenantPermissionIT` a hard CI gate before Epic 3** (the design already designates it; formalise it as a merge gate), and ensure it seeds the multi-tenant-user case (grants in both A and B) — it is the only end-to-end proof of the Critical property.

This is a **Condition of approval**, not a Blocker: nothing is exploitable today (verified), but the architect must land items 1–4 during implementation so the Critical property is not left resting on an untested, unguarded upstream assumption.

---

### [Medium] T-03 — Forgotten `@RequiresPermission` leaves an endpoint open to any authenticated user (Edge 10 / R3 / Gap 3)

**Component:** C4. **STRIDE:** Elevation of Privilege. **OWASP:** A01, A04.

The filter-chain default is `.anyRequest().authenticated()` — authentication only, **not** permission. A controller method shipped without `@RequiresPermission` is reachable by *any* authenticated user of *any* tenant. The design (B8) **defers** the "controller-must-be-annotated-or-opted-out" ArchUnit rule to an Epic-3 entry criterion.

**Assessment:** deferral is *defensible for this story* — there are no protected production controllers yet (only the test fixture), and forcing an opt-out marker before any real endpoint exists is awkward. But the epic's stated goal is "zero unguarded endpoints from Epic 3 onward," and there is a real risk that Epic-3 stories start merging endpoints *before* the enforcement rule lands — a window with no backstop.

**Required mitigation (recommended, not blocking this story):** formalise the deferred rule as a **hard Epic-3 entry criterion tracked now** (a ticket, not just a design sentence): the first protected controller cannot merge until the ArchUnit "every `@RestController` method carries `@RequiresPermission` or an explicit `@PublicEndpoint`" rule + the opt-out convention exist. Flag this forward explicitly in the task breakdown so it is not lost.

---

### [Medium] T-05 — Spring AOP self-invocation bypasses enforcement (Edge 7 / R8 / §G)

**Component:** C4. **STRIDE:** Elevation of Privilege. **OWASP:** A01.

An annotated method called from *within the same bean* bypasses the proxy → no permission check runs, no error. A developer who believes an internal call is guarded ships an unauthorized-executable path. The design accepts this as a documented Step-9 limitation, not a code deliverable.

**Assessment:** this is a genuine, well-known Spring gotcha, but it does not materialise in this story (no real annotated production endpoints). Documenting is the industry-standard mitigation. For an EoP-class limitation on the epic's core control, docs alone are the floor, not the ceiling.

**Required mitigations:**
1. **Make the Step-9 developer-guide entry a hard deliverable** (not optional), with a prominent self-invocation warning and the correct pattern (annotate the entry point, not an internal helper; or split beans).
2. When the Epic-3 annotation-enforcement rule (T-03) is built, **include a lint/ArchUnit check that flags same-class direct calls to `@RequiresPermission` methods** (R8's own suggested mitigation). Recommended, not blocking.

---

### [Medium] T-06 — Stringly-typed `Authentication.getDetails()` contract has no compile-time binding between producer and consumer (R4)

**Component:** C2 / C1. **STRIDE:** Tampering (of contract integrity) / EoP. **OWASP:** A04.

The filter writes `Map.of("tenantId", …, "permissions", …)` with string-literal keys (L79–83); the new reader reads the same string literals. Nothing binds the two at compile time. A rename or key typo on either side silently breaks the reader → it fails closed → **every** protected endpoint returns 403 (a total availability break for guarded routes) with no compiler warning. The design (B2) keeps the untyped `Map` deliberately to avoid touching the frozen filter, centralising the cast in one tested reader.

**Assessment:** keeping the untyped `Map` is an **acceptable residual risk and does not need escalation to a typed principal** — provided the reader is exhaustively unit-tested (E.1 covers null/not-a-Map/absent-key/wrong-type). The failure mode is fail-closed (safe), not fail-open. The gap is *correctness/availability* fragility, not a security hole.

**Required mitigation (recommended):** introduce a small shared constants holder for the four detail keys, referenced by **both** the filter and the reader, so the key contract is single-sourced; and add a contract test asserting the reader successfully parses an `Authentication` produced by the real `JwtAuthenticationFilter` (not just hand-built maps), so a future filter-side key change breaks a test rather than production. Recommended, not blocking.

---

### [Medium] T-08 — Fail-closed/malformed-token denials are indistinguishable from routine "user lacks permission" denials in logs (A09)

**Component:** C5. **STRIDE:** Repudiation / detection gap. **OWASP:** A09 (Security Logging & Monitoring Failures).

B4 routes *all* deny conditions through the same `InsufficientPermissionException` → same `RBAC_001` WARN log → same counter. But two very different events collapse into one signal:
- **Routine:** an authenticated user calls an endpoint they legitimately can't use (benign, high-volume).
- **Security-interesting:** `getDetails()` is absent/not-a-Map, `tenant_id` blank, or a *foreign `Authentication`* reached the evaluator — i.e. exactly the malformed/alternate-producer conditions that would accompany a probing attack or the T-02 break.

An operator cannot separate "someone is hitting the evaluator with a malformed/foreign Authentication" from "user clicked a forbidden button." The most detection-worthy event is buried in benign noise.

**Required mitigation:** add a distinguishing field to the denial log (e.g. `reason=permission_absent` vs. `reason=malformed_authentication` / `missing_tenant`), and consider a separate low-cardinality counter tag for the fail-closed branch so a spike in *malformed* denials is independently alertable. Recommended, strengthens A09; not blocking.

---

### [Low] T-07 — No audit-stream event for permission denials (B7)

**Component:** C5. **STRIDE:** Repudiation. **OWASP:** A09.

The design emits a structured WARN log (`userId`, `tenantId`, `requiredPermission`, `correlationId`, `traceId`) + a Micrometer counter `nexus.rbac.permission_denied{permission}`, but **no** audit-stream event.

**Assessment — defensible, NOT a Blocker.** A denial is a *rejected* action, not a state change; the epic explicitly scopes auditing to role assignment/revocation and is silent on check denials. The WARN log carries full forensic context (actor, tenant, permission, trace), and the counter enables spike alerting for attack detection. Coupling this hot, read-only path to `SecureEventService` (a `REQUIRES_NEW` write) for every 403 would add cost and a failure mode the source material doesn't ask for.

**Two caveats to confirm in implementation:**
1. **Verify the MDC claim.** B7 asserts `userId`/`tenantId` are still in MDC at handler time because the denial is thrown inside `JwtAuthenticationFilter`'s try/`finally` (around `chain.doFilter`, L94–97) and the `HandlerExceptionResolver` runs *inside* that call. This is **correct** as verified — but note the existing `logHandledException` does **not** currently emit `userId`/`tenantId` as structured fields (only `correlationId`). The new handler must explicitly add them (and the log pattern must include them) or the forensic value is lost.
2. If Security later wants **attributable, immutable** denial records (WARN logs are neither tamper-evident nor necessarily retained like audit), that is a separate additive story — flag forward. Recommended, not blocking.

---

### [Low] T-09 — 403 response echoes `requiredPermission` to the unauthorized caller

**Component:** C3/C5. **STRIDE:** Information Disclosure. **OWASP:** A01.

The `RBAC_001` body includes `requiredPermission: "tenant:write"`, telling a denied caller exactly which permission gates the endpoint, aiding an attacker mapping the permission model.

**Assessment — acceptable.** Permission names are a closed, non-secret, code-defined vocabulary (7 names); the caller is already authenticated; and the field has real value for the frontend guard (US-013) and developer debugging. Disclosure risk is marginal. No change required; noted for completeness.

---

### [Low] T-10 — Meta-annotation templating misconfiguration (A05)

**Component:** C4. **STRIDE:** EoP (fail-open) vs. availability (fail-closed). **OWASP:** A05 (Security Misconfiguration).

`{value}` substitution requires the `AnnotationTemplateExpressionDefaults` bean; the design correctly flags confirming the exact class name against the pinned Spring Security 6.4 / Boot 4.1.

**Assessment:** the realistic misconfigurations are **fail-closed** — if the defaults bean is missing, `{value}` is treated literally, the evaluator receives `"{value}"`, never matches, and returns 403. The dangerous mode would be the composed `@PreAuthorize` not being detected *at all* (→ unguarded, fail-open), which is not the behaviour on this Spring version (composed-annotation `@PreAuthorize` is supported independently of templating defaults).

**Required mitigation:** the slice test (E.2) must include **both** a positive control (caller *with* `tenant:write` → 200) **and** the negative (without → 403). The pair is the only thing that proves the annotation is genuinely processed — neither silently fail-open nor always-fail-closed. This is already in the test plan; make it a **non-negotiable assertion pair**, and confirm the templating class name at implementation (a bad guess degrades to fail-closed, which the positive control catches). Verification requirement, not a design change.

---

### [Low] T-13 — Validly-signed token missing `tenant_id` → 500, not fail-closed 403

**Component:** C1 (pre-existing, dependency). **STRIDE:** DoS / Information Disclosure (minor). **OWASP:** A05.

`JwtRs256Service.verify` does not null-check `tenant_id` (L141), so a validly-signed token without that claim yields `JwtClaims.tenantId() == null`; the filter's `Map.of("tenantId", null, …)` (L79) then throws `NullPointerException` (`Map.of` rejects null values) *outside* the `AuthenticationException` catch → propagates as a 500.

**Assessment — low, not this story's code, and not attacker-reachable:** only the server can mint a validly-signed token, and `issue()` always sets `tenant_id`. An attacker cannot craft such a token (signature). The evaluator is never reached (500 happens in the filter). It is a latent robustness gap in the frozen filter, not a US-011 exposure.

**Required mitigation (optional, forward):** note for a future US-010/EPIC-001 hardening ticket that `verify` should reject a missing `tenant_id` claim with `AUTH_003` (401) rather than letting the filter NPE into a 500. Out of scope for US-011; flag only.

---

## 4. Threats considered and found adequately mitigated (no action)

| Threat | STRIDE | Why adequate |
|---|---|---|
| **T-01** Forged/tampered/injected-`permissions` JWT | S/T | RS256 signature verify + explicit alg pinning (`JwtRs256Service.verify` L115–118) reject `alg=none`/HS256-confusion and any tamper → 401 `AUTH_003` before the evaluator. Verified in code. (FR5, Test Scenario 5.) |
| **T-04** Anonymous/foreign `Authentication` at an annotated endpoint | E | B4 fail-closed: non-`Map` details / not-authenticated → throw → 403. Anonymous token's `WebAuthenticationDetails` is not the expected `Map` → denied. (Note: this is *also* the T-02 backstop for the *malformed* case — but not the *well-formed-cross-tenant* case.) |
| **T-11** SpEL injection via `@RequiresPermission` value | T/E | `{value}` is a compile-time annotation constant, never request-derived; Spring compiles+caches the expression per method. No user input enters the SpEL. No injection, no per-request parse-DoS. |
| **T-12** DoS / cost amplification on the enforcement path | D | Evaluator is in-memory `Set.contains` on a ≤7-element list, no DB/Redis/network. Unauthenticated callers hit 401 at the filter and never reach it — no unauthenticated amplification. |
| **permitAll interaction with global `@EnableMethodSecurity`** | E | `permitAll` endpoints carry no `@RequiresPermission`, so the proxy does not intercept them; they remain reachable. Method security cannot re-open or lock these. (E.2 asserts this.) |
| **A03 Injection (SQL/JPQL)** | T | This story issues no queries (reads JWT claims only). The upstream `findActivePermissionNames` uses parameterised JPQL (verified) — no injection. |
| **A02 Cryptographic failures** | — | No new crypto; token integrity rests on the reviewed RS256 path. |
| **PII in logs/response (org policy)** | I | Denial log + 403 body carry only UUIDs (`userId`/`tenantId`) and a static English sentence; `JwtClaims` is PII-free by contract. No PII. |

**A06 (Vulnerable Components):** the design introduces **no new dependency** (`spring-boot-starter-security` already present; `@EnableMethodSecurity`/`@PreAuthorize`/`AnnotationTemplateExpressionDefaults` all ship with it — impact §8, verified). A full `./mvnw dependency:tree` + CVE scan belongs to the Phase-7 **code audit** of the implementation, not this design-phase threat model, and is noted here as a Phase-7 requirement rather than run against not-yet-written code.

---

## 5. Residual risk summary

| ID | Severity | Threat | Status after recommended mitigations |
|---|---|---|---|
| T-02 | High | Cross-tenant boundary rests entirely on an untested/unguarded upstream invariant | Reduced to Low once the invariant is documented, contract-tested, and guarded against a second `Authentication` producer (items 1–4). Cannot be driven to zero without a second data source the design rightly avoids — residual accepted, but must be *visible and guarded*, not silent. |
| T-03 | Medium | Forgotten annotation → open endpoint | Deferred to a **tracked** Epic-3 entry gate; no live exposure in this story. |
| T-05 | Medium | Self-invocation bypass | Mitigated by mandatory docs now + lint at Epic 3. |
| T-06 | Medium | Stringly-typed details contract | Fail-closed (safe) today; residual accepted with shared key constants + producer-side contract test. |
| T-08 | Medium | Malformed vs. routine denial indistinguishable | Closed by a `reason` discriminator field/tag. |
| T-07 | Low | No audit event for denials | Accepted for scope; WARN+counter sufficient; forward-flag for Security. |
| T-09 | Low | `requiredPermission` disclosure | Accepted (non-secret vocabulary). |
| T-10 | Low | Templating misconfig | Fail-closed; caught by the positive/negative test pair. |
| T-13 | Low | Missing-`tenant_id` token → 500 | Not attacker-reachable; forward-flag for EPIC-001 hardening. |

---

## 6. Verdict

### APPROVE WITH CONDITIONS

The design is fundamentally sound. Fail-closed is genuinely achieved in every branch identifiable (malformed/absent details, non-`Map`, blank tenant, foreign/anonymous `Authentication`, templating misconfig, and the empty-permissions case all deny — none fail open). The RS256 verify path that gates the whole model is solid. The B5 cross-tenant claim is **functionally correct for the only mint path that exists today** — verified down to the double tenant predicate in `findActivePermissionNames` — and the `CrossTenantPermissionIT` genuinely proves it end-to-end. **No Blocker-severity issues: nothing here is exploitable today.**

However, the epic's single Critical-rated property is left resting on an upstream invariant that this story neither asserts, tests, nor guards. That is acceptable *only if* the invariant is made explicit and defended. The architect must address the following before/during implementation:

1. **(from T-02 — the priority condition)** Document the tenant-provenance invariant on `TenantAwarePermissionEvaluator` (and in ADR-0013); add a contract test locking `JwtRs256Service.issue` to resolve `permissions[]` and `tenant_id` from the *same* tenant value; and add a guard (test/ArchUnit) that `JwtAuthenticationFilter` is the *only* production producer of an authenticated `Authentication` carrying a `permissions` detail. Any future second producer must fail this guard and trigger an explicit B5 re-review.
2. **(from T-02)** Formalise `CrossTenantPermissionIT` — seeding a user with grants in *both* tenants — as a **hard CI merge gate** that must be green before any Epic-3 endpoint work begins.
3. **(from T-03)** Track the deferred "every controller method annotated or explicitly opted out" ArchUnit rule as a **named Epic-3 entry criterion now** (a ticket), so the first protected controller cannot merge without it.
4. **(from T-05)** Make the Step-9 self-invocation developer-guide warning a **hard deliverable** of this story, and fold a same-class-call lint check into the Epic-3 rule of condition 3.
5. **(from T-08)** Add a `reason` discriminator (e.g. `permission_absent` vs. `malformed_authentication`) to the denial WARN log so the security-interesting fail-closed branch is separable from routine denials; confirm the new handler actually emits `userId`/`tenantId` as structured fields (they are in MDC but the current log helper does not emit them).
6. **(from T-06, T-10 — recommended)** Single-source the four `Authentication` detail keys as shared constants used by both filter and reader, add a producer-side contract test for the reader, and keep the positive+negative MockMvc control pair as a non-negotiable proof that the annotation is genuinely processed.

Conditions 1–5 are required; condition 6 is strongly recommended. None block Gate-2 sign-off of the design itself — they are implementation-and-task-breakdown obligations that convert an otherwise-silent Critical-property dependency into a documented, tested, and guarded one.

---

### Cross-references
- Design: `docs/features/US-011/03-design.md`
- Impact: `docs/features/US-011/02-impact.md`
- Requirements: `docs/features/US-011/01-requirements.md`
- Story: `docs/story/2-rbac/US-011.md`
- ADR-0013 D3: `docs/adr/0013-rbac-data-model-and-enforcement-contract.md`
- Verified code: `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`, `...identity/infrastructure/security/JwtRs256Service.java`, `...identity/domain/JwtClaims.java`, `...config/SecurityConfig.java`, `...common/web/GlobalExceptionHandler.java`, `...rbac/application/RoleResolutionService.java`, `...rbac/infrastructure/persistence/JpaUserRoleRepository.java`
