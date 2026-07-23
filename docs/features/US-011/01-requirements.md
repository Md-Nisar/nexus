# US-011 — Requirement Analysis Document

**Feature:** Enforce permission checks on API endpoints via Spring Security
**Epic:** EPIC-002 (RBAC Foundation)
**Status:** Draft — pending Gate 1 sign-off
**Analyst:** Business Analyst (requirements-only; no design/code in this document)

---

## 1. Context

EPIC-001 established *who* a caller is (JWT authentication). EPIC-002 establishes *what they may do*. US-009 built the roles/permissions schema, and US-010 (immediately prior, already merged) populated the JWT's `roles[]`/`permissions[]` claims at login/refresh. US-011 is the piece that actually *uses* those claims: a reusable `@RequiresPermission` annotation, backed by Spring Security method security and a tenant-aware `PermissionEvaluator`, that lets any controller method declare the single permission it requires and get a 403 automatically if the caller's JWT doesn't carry it — including when the caller holds that permission only in a *different* tenant. The story's own background note calls the cross-tenant check "the highest-consequence correctness requirement in EPIC-002." This story introduces the first custom annotation and the first AOP/method-security mechanism anywhere in the codebase; every other cross-cutting concern today is filter-based. Nothing in the `rbac` bounded context has an `interfaces`/controller package yet, so this story is pure enforcement plumbing with no endpoint of its own to protect — its proof point is that a *future* endpoint can adopt it with zero bespoke logic.

---

## 2. Functional Requirements

Numbered from the story's 6 ACs and Technical Notes, made atomic/testable. Each cites its source.

- **FR1** — A method annotated `@RequiresPermission("<permission>")` returns the endpoint's normal (2xx) response when the caller's JWT `permissions[]` claim contains `<permission>`. *(AC1)*
- **FR2** — The same method returns `403` when the caller's JWT `permissions[]` claim does not contain `<permission>`. *(AC1)*
- **FR3** — A caller who holds `<permission>` only under a tenant other than the one the called endpoint is scoped to receives `403`, even though the permission name string matches exactly. *(AC2 — "highest-consequence test" per the story)*
- **FR4** — Every permission-check failure (FR2 and FR3 alike) returns exactly: HTTP `403`, `code = RBAC_001`, body containing `required_permission: "<name>"` and `message: "You do not have permission to perform this action"` — no per-endpoint variation in shape. *(AC3)*
- **FR5** — A request with no JWT, or an invalid/tampered JWT (including one with a manually injected `permissions` claim but invalid signature), is rejected with `401`, and the permission-check logic is never reached for it. *(AC4, Test Scenario 5)*
- **FR6** — `@RequiresPermission`, once this story ships, can be applied to a method in any controller — present or future, in any bounded context — and enforces correctly with no additional per-controller wiring beyond the annotation itself. *(AC5, AC7)*
- **FR7** — Permission evaluation reads exclusively from the already-populated JWT `permissions[]` claim carried on the request's `Authentication` (via US-010) — it must not invoke `RoleResolutionService` or perform any per-request database query. *(Epic background: "Reads permissions from the JWT (no DB call per request)"; already-confirmed fact #6)*
- **FR8 (P1)** — The permission-check evaluation itself adds less than 5ms to p95 endpoint latency. *(AC6 — see Open Question 5 on what "cache hit path" means here, since FR7 implies no cache is consulted at all)*
- **FR9** — A permission-check denial thrown by the evaluator is distinguishable, via a dedicated exception type, from the pre-existing generic filter-chain `AccessDeniedException` handling in `GlobalExceptionHandler`, so that RBAC denials get the FR4 contract while non-RBAC 403s (already handled today) are unaffected. *(ADR-0013 D3 — resolved decision, restated here as a functional requirement this story must implement, not re-litigate)*
- **FR10** — `@EnableMethodSecurity` is active platform-wide once this story ships (a global configuration change, not per-controller). *(Technical Notes)*

**Explicitly not covered by any stated FR** (see Gaps §8): what happens when more than one permission is required by a single endpoint; whether any observability/audit event is emitted on a 403.

---

## 3. Non-Functional Requirements

**Performance**
- Permission-check overhead: < 5ms added to p95 (AC6, P1). As currently worded this NFR is not cleanly testable in isolation from Test Scenario 6's "200 RPS, p95 < 300ms" endpoint-level target — the story conflates a component-level budget (5ms) with a system-level one (300ms) in a single scenario. [INFERENCE] the 5ms figure is meant to be measured by comparing an annotated vs. unannotated endpoint's latency delta, but the story does not say so explicitly.
- No numeric target is given for cold-path cost (e.g., first invocation, method-security proxy construction) — only steady-state.

**Scalability**
- No RPS ceiling beyond the one performance test scenario (200 RPS) is stated; nothing addresses whether the evaluator's cost scales with the *size* of the `permissions[]` array (number of roles/permissions a user holds) — plausible for a tenant with many granular roles.

**Availability / SLO**
- Per FR7, this story adds no new external dependency (no DB, no Redis) to the per-request hot path — so it should not, by construction, introduce a new availability risk to already-authenticated requests. No SLO number is stated anywhere in the story for this specifically; the epic's only related SLO is the 5ms/300ms performance figures above, not an uptime/error-rate target.

**Security**
- This is explicitly flagged (both in the story and EPIC-002's technical risk register) as the single highest-consequence correctness requirement in the epic: a cross-tenant boundary defect here is a privilege-escalation vulnerability, not a data bug.
- Fail-closed behavior is implied but never stated as an explicit requirement: what should the evaluator do if the `Authentication` details it expects (e.g., a `permissions` entry) are absent or malformed, rather than simply empty? See Open Question 8.
- Zero high/critical SAST findings on the evaluator is stated as an epic-level (not story-specific) quality gate in EPIC-002's QA section — should be treated as binding here too, per its own severity language.

**Observability**
- **Not addressed anywhere in the source material.** No requirement states whether a 403 permission denial is logged, metriced, correlated to `traceId`, or emitted to the audit stream — this is a gap, not an inferred requirement (see Gaps §8, Open Question 7). Contrast with the epic's explicit compliance requirement that *role assignment/revocation* events be audited — permission *check failures* are never mentioned.

**i18n**
- The 403 `message` string is a fixed, hardcoded English sentence in AC3 (`"You do not have permission to perform this action"`). No localization requirement is stated one way or the other.

**Accessibility**
- Not applicable — this is a backend-only story (Technical Notes: "Angular: no changes in this story").

---

## 4. Edge Cases

| # | Case | Expected per source material | Status |
|---|---|---|---|
| 1 | Caller's JWT `permissions[]` is an empty array | 403 (FR2) | Verified — implied by FR2's set-membership logic |
| 2 | Caller's JWT is missing/invalid entirely | 401, permission check never reached | Verified (FR5, Test Scenario 5) |
| 3 | Caller has the exact permission string, but scoped to a different tenant | 403, cross-tenant boundary holds | Verified (FR3, AC2) |
| 4 | Endpoint requires more than one permission | Not addressed anywhere | **Open — Question 9** |
| 5 | `Authentication` object reaching the evaluator was not built by `JwtAuthenticationFilter` (e.g. a future internal/test path) and lacks the expected `permissions`/`tenantId` entries | Not addressed | **Open — Question 8. Fail-closed (deny) vs. fail-open (error/allow) is unstated.** |
| 6 | Permission name passed to `@RequiresPermission` is a typo / not one of the seven code-seeded permissions | Not addressed | **Open — Question 9 (fail-fast at startup vs. silent always-deny at runtime unstated)** |
| 7 | Same-class/self-invocation call to an annotated method (bypasses Spring AOP proxy interception entirely, a well-known Spring Security limitation) | Not addressed anywhere in the source material | **Gap — see §8** |
| 8 | Concurrent requests from the same user during a token refresh window, where the *new* token would carry different permissions than the one presented on an in-flight request | Each request is presumably evaluated independently against whichever token it presented (no session state) | [INFERENCE] — not stated explicitly, but consistent with the stateless design |
| 9 | Actuator/Swagger/`.well-known` endpoints, already `permitAll()`'d at the filter-chain level | Presumably unaffected once `@EnableMethodSecurity` is enabled globally, since they carry no `@RequiresPermission` | Not explicitly stated — **Gap** |
| 10 | No `@RequiresPermission` present on a new controller method at all | Endpoint remains reachable by any *authenticated* user (current filter-chain default-deny only requires authentication, not permission) | Not addressed as an edge case anywhere, despite the epic's stated goal of "zero unguarded endpoints from Epic 3 onward" | **Gap/Risk — see §6, §8** |
| 11 | Tenant-ID comparison: `JwtClaims.tenantId()` is a plain `String`, not a `UUID` type, in the frozen contract | Whether comparison is raw string equality or requires canonicalization is unstated | **Open — Question 11** |

---

## 5. Assumptions

All flagged `[CONFIRM]` for Gate 1 stakeholder sign-off. None are treated as settled defaults — ambiguity is surfaced, not resolved by inference.

- `[CONFIRM]` The `PermissionEvaluator` will read the caller's tenant/permission data by casting the existing untyped `Map<String,Object>` in `Authentication.getDetails()` (as `JwtAuthenticationFilter` currently populates it), rather than this story introducing a typed principal/details value object as part of its own scope.
- `[CONFIRM]` The evaluator's tenant-boundary check compares the JWT's own `tenant_id` claim against *something* the annotated method exposes — but the story's `@PreAuthorize("...#tenantId...")` sample implies a method parameter that the epic's own first real consumer endpoint (US-012, `POST /api/v1/users/{userId}/roles`) doesn't obviously have. `[INFERENCE]` It is plausible the check could instead compare two callers' own JWT `tenant_id` claims against each other (satisfying AC2's literal test wording) with no resource-tenant parameter required at all — but this is not stated or confirmed anywhere in the source material and materially changes the annotation's shape (see Open Question 4).
- `[CONFIRM]` Package placement for `@RequiresPermission`, `TenantAwarePermissionEvaluator`, and `InsufficientPermissionException` is undecided in the story/ADR — assumed to be resolved at Gate 2, not implied by any existing convention.
- `[CONFIRM]` What concretely satisfies AC5/AC7 ("usable on any controller method... without additional configuration") — a real, low-risk existing endpoint annotated for real, versus a dedicated test-fixture controller purpose-built to prove the annotation compiles/enforces.
- `[CONFIRM]` `@RequiresPermission` takes exactly one permission string per annotated method; multi-permission (AND/OR) composition is out of scope unless a stakeholder confirms a near-term consuming story needs it.
- `[CONFIRM]` A permission-check failure produces no audit/security event in this story — assumed silent (only the HTTP 403 response), pending confirmation this is acceptable given Security & Compliance's stated interest in the epic overall.
- `[CONFIRM]` The evaluator fails closed (denies, 403) on any unexpected condition (missing claim data, evaluator exception) rather than failing open — not stated as an explicit requirement anywhere in the story.

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | Cross-tenant boundary bug in `TenantAwarePermissionEvaluator` — a permission check that incorrectly passes across tenants | **Critical** | Already named in the story's own risk register: dedicated security test suite + mandatory code-review gate. Should be a hard CI gate before Epic 3 starts, per the epic's synthesis note. |
| R2 | The annotation/evaluator's SpEL shape is designed around a `tenantId` method parameter that the epic's own first consuming endpoint (US-012) doesn't have — a Gate 2 design built on the story's literal Technical Note could produce a contract none of the real consumers can actually use, forcing rework mid-epic | **High** | Resolve Open Question 4 explicitly at Gate 2, validated against US-012's real method signature before finalizing the annotation shape. |
| R3 | Nothing enforces that a new controller method actually carries `@RequiresPermission` — the epic's stated business goal ("zero unguarded endpoints from Epic 3 onward") has no named enforcement mechanism in any source document; a forgotten annotation silently leaves an endpoint open to any authenticated user | **High** | Needs an explicit owner decision (Open Question 6) — e.g. a lint/ArchUnit rule requiring every REST controller method to carry either `@RequiresPermission` or an explicit "intentionally unguarded" marker. Not decided anywhere today. |
| R4 | Reading `Authentication.getDetails()` as an untyped `Map` inside a brand-new `PermissionEvaluator` is the first non-logging consumer of that map — a missing/mistyped key produces a silent `ClassCastException`/`NullPointerException` with no compiler enforcement | **Medium** | Decide typed-vs-untyped explicitly at Gate 2 (Open Question 1); if untyped is kept, define the fail-closed contract for malformed/missing entries (Open Question 8). |
| R5 | `InsufficientPermissionException` cannot extend `common.domain.DomainException` (the convention every other cross-context exception in this codebase follows) because ADR-0013 D3 requires it to extend Spring's `AccessDeniedException` instead — this is a genuinely new exception-placement pattern with no established package-location precedent | **Medium** | Resolve package home explicitly at Gate 2 (Open Question 2); document the divergence from the `DomainException` convention so future contributors don't assume all cross-context exceptions share one base. |
| R6 | AC6's "cache hit path" / "< 5ms" phrasing appears to be inherited language from the epic's Redis permission cache (used by US-010 at login/refresh only) but this story's own confirmed design (FR7) reads only JWT claims with no cache involved at all — if read literally, this NFR could describe a mechanism this story must *not* build | **Medium** | Clarify with QA/Architect (Open Question 5) before treating the 5ms figure as a testable target tied to a "cache." |
| R7 | This is the first custom annotation/AOP mechanism and first `PermissionEvaluator` in the codebase — no existing test pattern for unit-testing `@PreAuthorize` SpEL expressions or mocking a `PermissionEvaluator`; effort/time to build reliable tests may be underestimated relative to the story's 5-point size | **Low** | Allocate spike/exploration time; reuse the existing `SecurityConfigTest` `@SpringBootTest(MOCK)` + `MockMvc` + `springSecurity()` pattern as a base. |
| R8 | Spring AOP proxy-based method security does not intercept same-class self-invocation calls — a developer calling an annotated method from within the same bean bypasses the check entirely with no runtime error, and nothing in the source material flags this as a known limitation to educate developers on | **Low** | Document explicitly in developer guidance once the annotation ships; consider whether an ArchUnit rule can at least flag same-package direct calls to annotated methods. |

---

## 7. Open Questions

1. **Architect** — Should the `PermissionEvaluator` continue reading `Authentication.getDetails()` as an untyped `Map` (as `JwtAuthenticationFilter` populates it today), or does this story introduce a typed principal/details value object for type safety? This is the first non-logging consumer of that map.
2. **Architect** — What package should `@RequiresPermission`, its supporting evaluator, and the method-security configuration live in — a cross-context `common` location (since every future bounded context will consume it), or somewhere under `rbac` (`rbac.interfaces` / `rbac.infrastructure.security`)? Relatedly, where should `InsufficientPermissionException` live, given it cannot extend `common.domain.DomainException` like every other cross-context exception in this codebase (per ADR-0013 D3, it must extend Spring's `AccessDeniedException` instead) — is a new package/convention needed for this class of exception?
3. **Architect / QA** — What concretely satisfies AC5/AC7's "usable on any controller method... compiles and enforces without additional configuration"? A real, low-risk existing endpoint annotated for real as proof, or a purpose-built test-fixture controller?
4. **Architect / PM (highest priority — determines the annotation's shape)** — The story's Technical Note shows `@PreAuthorize("@permissionEvaluator.hasPermission(authentication, #tenantId, '{permission}')")`, implying the annotated method takes a `tenantId` parameter. But the epic's first real consumer, US-012 (`POST /api/v1/users/{userId}/roles`), has no obvious `tenantId` argument — it derives tenant from the caller's own JWT. Should the evaluator instead validate purely against the caller's own JWT `tenant_id` claim, with resource-vs-caller tenant mismatches (e.g., "is this specific user actually in my tenant") deferred to each consuming story's own service-layer logic? This must be settled before Gate 2 design, not discovered mid-implementation.
5. **QA / Architect** — Does AC6/Test Scenario 6's "< 5ms" figure and "cache hit path" wording describe the JWT-claims-only read this story is scoped to build (per the epic's own statement that per-request enforcement makes no DB call), or is it stale language carried over from the epic's separate Redis permission cache (which US-010 uses only at login/refresh)? If the latter, does this story need any cache concept at all, or is the NFR simply "read `Authentication` details + `Set.contains`"?
6. **PM / Security** — Does the epic's stated business goal ("zero unguarded endpoints from Epic 3 onward") require an automated enforcement mechanism in this story (e.g., a lint/ArchUnit rule requiring every REST controller method to carry `@RequiresPermission` or an explicit opt-out), or is it accepted as a code-review-only discipline?
7. **Security** — Should a permission-check failure (403/`RBAC_001`) be written to any audit/security event stream? The epic names Security & Compliance as a stakeholder needing "role assignment events" audited, but says nothing about auditing permission-check *denials* — is this an intentional scope boundary or an unaddressed gap?
8. **Architect** — What is the fail-closed contract when `Authentication.getDetails()` doesn't contain the expected `permissions`/`tenantId` data at all (e.g., an `Authentication` built by some future code path other than `JwtAuthenticationFilter`)? Should the evaluator throw `InsufficientPermissionException` (403, safe default) or is a distinct error (e.g., 500) acceptable/expected?
9. **Architect** — Does any endpoint in the epic's own API table (US-012, US-015) require more than one permission on a single method, or is `@RequiresPermission` scoped to exactly one permission string per method for the foreseeable future? Relatedly, what happens if the permission string passed to the annotation doesn't match one of the seven code-seeded permission names — is this caught at startup (fail-fast) or only manifests as a silent always-403 at runtime?
10. **QA** — Test Scenario 3 requires "user with `tenant:write` in Tenant A receives 403 calling an endpoint scoped to Tenant B" — since the `rbac` bounded context has no controllers of its own yet, which concrete endpoint or test fixture will this story's own integration/security test actually call?
11. **Architect** — Is the tenant-boundary comparison a raw string equality check between two `JwtClaims.tenantId()` `String` values, or does it need canonicalization (case-folding, UUID re-parsing), given `tenantId` is typed as a plain `String` (not `UUID`) in the frozen JWT contract?

---

## 8. Gaps

Missing from the source material entirely — not inferable, not addressed by any AC, Technical Note, or ADR:

1. No observability or audit requirement for permission-check *denials* — contrast with the epic's explicit audit requirement for role assignment/revocation events, which has no counterpart for 403s.
2. No reconciliation anywhere between the Technical Note's `#tenantId`-parameterized SpEL sample and the epic's own first consumer endpoint (US-012), which has no such parameter — this is a real, unresolved contradiction between two source documents, not a matter of interpretation (see Open Question 4).
3. No named mechanism (lint rule, ArchUnit check, or otherwise) to prevent a future controller method from shipping with no `@RequiresPermission` at all, despite "zero unguarded endpoints" being a stated epic business goal.
4. No i18n requirement — or explicit statement that i18n is out of scope — for the hardcoded English 403 message string.
5. No mention anywhere of multi-permission composition (a single endpoint requiring more than one permission).
6. No mention of Spring AOP's same-class self-invocation limitation for method security, which is a real, well-known gap for any first-time adopter of `@PreAuthorize`.
7. No explicit statement of what should happen to the pre-existing `permitAll()` endpoints (actuator, Swagger, `.well-known`) once `@EnableMethodSecurity` is turned on globally — presumably unaffected, but never stated.
8. No fail-closed/fail-open contract for malformed or missing `Authentication` details reaching the evaluator.
9. No numeric availability/SLO figure specific to this story (only the shared 5ms/300ms performance figures).
10. No package/module home named for the annotation, evaluator, or `InsufficientPermissionException` in either the story or ADR-0013 (D3 resolves only the *exception-handling pattern*, not where the classes live).

---

## 9. Stakeholder Map

| Stakeholder | Interest |
|---|---|
| Development Teams (all future feature authors) | Direct consumer — need a stable, documented `@RequiresPermission` contract usable with zero bespoke auth logic per the epic's stated business goal #4 |
| Security & Compliance | Highest stake — the cross-tenant boundary check is named the epic's single highest-consequence correctness requirement; also has an unaddressed interest in whether permission denials are audited (Open Question 7) |
| Architect | Owns nearly every open question here — annotation/evaluator/exception package placement, typed-vs-untyped `Authentication` details, the SpEL/`tenantId` parameter shape (Open Question 4, highest priority), fail-closed contract |
| QA | Owns the concrete test-fixture/endpoint question (Open Question 3, 10) and the un-numbered multi-permission/self-invocation gaps |
| PM | Owns the "zero unguarded endpoints" enforcement-mechanism decision (Open Question 6) and any prioritization tradeoff if Gate 2 design work uncovers rework from Open Question 4 |
| US-012 / US-015 / Epic 3 authors | Direct downstream consumers who inherit whatever annotation shape this story settles on — US-012 especially, since its first real endpoint has no obvious `tenantId` argument (Open Question 4) |
| Business Users (indirect) | Experience a generic 403 message on denial; no technical detail exposed to them per the epic's UX section — not a direct stakeholder in this backend-only story but the response contract (AC3) is what they ultimately see surfaced by the frontend (US-013) |

---

## 10. Success Metrics

No story-specific metrics are stated in US-011 itself (a pure backend enforcement-contract story, no user-facing feature of its own). Inherited from EPIC-002's stated success criteria, to the extent they apply to this story:

- Zero privilege-escalation findings involving the permission evaluator in the pre-GA penetration test.
- The cross-tenant boundary security test suite is green and gates CI before Epic 3 development starts (per the epic synthesis note calling this "the highest-consequence failure mode on a multi-tenant platform").
- Permission-check overhead measurably adds < 5ms to p95 endpoint latency, once Open Question 5 resolves what that figure is actually meant to measure.
- At least one real endpoint (the first Epic 3 endpoint, or a designated existing low-risk endpoint) is protected using `@RequiresPermission` with zero changes required to the annotation/evaluator contract afterward — the epic's own stated release-readiness bar for this capability.

No metric in any source document addresses adoption completeness (e.g., "% of endpoints annotated") — consistent with Gap 3 above (no enforcement mechanism named).

---

### Cross-references
- `docs/story/2-rbac/US-011.md` — source story
- `docs/story/2-rbac/EPIC-002.md` — parent epic (PM/BA/ARC/QA sections, API table, permission naming convention)
- `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` — D3 (resolved: exception type/handler precedence)
- `docs/adr/0007-jwt-library-jjwt-not-resource-server.md` — confirms hand-rolled JJWT filter, no `JwtDecoder`/`JwtAuthenticationToken`
- `docs/features/US-010/06-code-review.md` — confirms current `rbac` context shape and a pre-existing MEDIUM cross-context coupling finding (not this story's job to fix)
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java` — verified: `@EnableWebSecurity` only, no method security yet, filter-chain-level `AccessDeniedHandler`/`AuthenticationEntryPoint`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java` — verified: untyped `Map` in `Authentication.getDetails()`, `ROLE_<name>` authorities only
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java` — verified: `tenantId` is `String`, not `UUID`
- `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java` — verified: existing generic `@ExceptionHandler(AccessDeniedException.class)` at line 134
