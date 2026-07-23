# US-011 — Impact Analysis

**Feature:** Enforce permission checks on API endpoints via Spring Security
**Epic:** EPIC-002 (RBAC Foundation)
**Step:** 2 — Impact Analysis (read-only). This document maps what US-011 *touches*; it does **not** design the solution (Step 3 / Gate 2).
**Input basis:** `docs/features/US-011/01-requirements.md` (approved Gate 1), `docs/story/2-rbac/US-011.md`, ADR-0013 D3, ADR-0007. Codebase facts below were re-verified by reading the named files this session.

**Gate 1 resolution carried in (do not re-open):** Open Question 4 is settled — `@RequiresPermission("resource:action")` takes **only** the permission string; the tenant-boundary check validates against the caller's own JWT `tenant_id` claim, with **no** `tenantId` method parameter. Resource-vs-caller tenant matching stays the consuming story's service-layer job (US-012+). This simplified shape is assumed throughout.

---

## 1. Backend layers touched

This story is pure enforcement plumbing. It is the **first** AOP / method-security mechanism in the codebase — every prior cross-cutting concern is `Filter`-based (verified: grep for `EnableMethodSecurity|PreAuthorize|PermissionEvaluator|@RequiresPermission` across `src/` returns nothing).

**New artifacts** (final package homes are a Gate 2 decision — see §10):

| Artifact | Nature | Layer/role | Notes |
|---|---|---|---|
| `@RequiresPermission` annotation | New | interfaces-facing developer contract | Meta-annotation carrying Spring's `@PreAuthorize`; applied on controller methods across all contexts. Takes one permission string (Gate 1 shape). |
| `TenantAwarePermissionEvaluator` | New | infrastructure (security adapter) | Reads `permissions[]` + `tenant_id` from `Authentication`; performs flat `Set.contains` membership + tenant-claim consistency. Named in ADR-0013 D3. Must **not** land in domain/application (see §5). |
| `InsufficientPermissionException extends AccessDeniedException` | New | cross-cutting exception | Carries `requiredPermission`. Cannot extend `common.domain.DomainException` (ADR-0013 D3) — new placement pattern (see §5, §10). |
| Method-security enablement (`@EnableMethodSecurity` + any `MethodSecurityExpressionHandler`/bean wiring) | New config | config | Global switch; platform-wide once merged (FR10). |

**Modified files** (verified line anchors):

- `config/SecurityConfig.java` — add `@EnableMethodSecurity` (currently `@EnableWebSecurity` only, line 41). No change needed to the filter chain, `permitAll` list (lines 76–85), or the filter-chain-level `AccessDeniedHandler` (lines 115–125) / `AuthenticationEntryPoint` (lines 98–108). Whether the annotation goes on `SecurityConfig` or a new dedicated `MethodSecurityConfig` is a Gate 2 call.
- `common/web/GlobalExceptionHandler.java` — add a new `@ExceptionHandler(InsufficientPermissionException.class)` returning `403 + RBAC_001 + { required_permission, message }` (FR4). The existing generic `@ExceptionHandler(AccessDeniedException.class)` at lines 134–139 (`code=ACCESS_DENIED`) stays untouched as the fallback; Spring's most-specific-type dispatch selects the new handler for the subtype (ADR-0013 D3). This file already imports `org.springframework.security.access.AccessDeniedException` (line 22), so importing its subtype is consistent.

**Reading path for the evaluator (confirmed):** `JwtAuthenticationFilter` (lines 76–83) builds a `UsernamePasswordAuthenticationToken` with principal = `claims.sub()` (String), authorities = `ROLE_<name>` only, and stashes `tenantId` (String), `emailVerified`, `tokenVersion`, `permissions` (`List<String>`) into `auth.setDetails(Map.of(...))` — an **untyped `Map<String,Object>`**. The evaluator will be the **first non-logging consumer** of that map. No typed principal/details class exists (Gate 2 decision — see §10 and R4).

---

## 2. Data impact

**None.** This story adds no tables, columns, indexes, or constraints. The RBAC schema (`V5__rbac_schema.sql`: `permissions`, `roles`, `role_permissions`, `user_roles`) already exists from US-009. Per FR7, enforcement reads only the JWT `permissions[]`/`tenant_id` claims already on the request `Authentication` — no per-request DB query, no Flyway migration, no `ddl-auto=validate` implication. `RoleResolutionService` (mint-time only) is **not** invoked per request.

---

## 3. API impact

- **No new REST endpoint of its own.** The `rbac` context still has no `interfaces`/controller package (verified: `rbac/` contains only `domain/`, `application/`, `infrastructure/{persistence,cache,health}`). US-011 ships no path, method, or DTO.
- **New response contract on failure:** existing endpoints (once annotated) can now return `403 + RBAC_001 + { required_permission, message }`. This is additive and only reached via `@RequiresPermission`; no existing endpoint changes behaviour until annotated. Not a breaking change; no versioning needed.
- **Proof/canary mechanism needed (AC5/AC7) — flag only, do not design:** AC5/AC7 require demonstrating the annotation "compiles and enforces without additional configuration," and Test Scenario 3 requires a concrete cross-tenant call — but there is **no controller anywhere in `rbac`** to annotate. Gate 2 must decide between (a) annotating a real, low-risk existing endpoint (e.g. in `identity.interfaces.rest`) versus (b) a purpose-built test-fixture controller. This is Open Question 3/10 from requirements — a **decision needed at Gate 2**, not resolved here.

---

## 4. Cross-context effects & blast radius

- **This is a platform-wide mechanism consumed by every future controller in every bounded context.** The `@RequiresPermission` contract, once shipped, is a compile-time dependency for US-012, US-013 (frontend guard consumes the 403 contract), US-015, and **all of Epic 3+**. Any change to the annotation's shape after this story ripples across every consumer — so the Gate 1 shape resolution (permission-string-only) must hold firm through Gate 2. This is the epic's highest-leverage contract.
- **`@EnableMethodSecurity` is a global toggle (FR10):** it activates method-security proxying platform-wide, not per-controller. Edge Cases 7 (`permitAll` actuator/Swagger/`.well-known`) — these carry no `@RequiresPermission`, so they remain unaffected; worth an explicit confirming assertion in test rather than an assumption (requirements Gap 7).
- **Pre-existing MEDIUM finding — context only, NOT this story's job:** `docs/features/US-010/06-code-review.md` records that `identity.infrastructure.security.JwtRs256Service` directly imports `rbac.application.RoleResolutionService` (the only cross-context import in the codebase, "Not addressed / tracked as follow-up"). US-011 does not touch `JwtRs256Service` and must not be scoped to fix this. It is relevant only as evidence that (a) cross-context coupling already exists and is tolerated as tracked debt, and (b) `HexagonalArchitectureTest` does **not** catch cross-*context* coupling (see §5), which informs where US-011's new types may safely live.

---

## 5. ArchUnit / hexagonal architecture impact

Verified rules in `architecture/HexagonalArchitectureTest.java`:

- `domain` must not depend on `application`/`infrastructure`/`interfaces` (lines 24–29).
- `application` must not depend on `infrastructure`/`interfaces` (lines 31–37).
- `domain` must not use `org.springframework.web..` / `jakarta.servlet..` (lines 39–45).
- `domain` + `application` must not depend on Redis client packages (lines 51–57).
- General rules: no field injection, no standard streams, no JUL.

**Key findings:**

1. **`TenantAwarePermissionEvaluator` implements `org.springframework.security.access.PermissionEvaluator` — a Spring Security type.** There is **no** ArchUnit rule today that forbids `org.springframework.security..` imports in `domain`/`application` (the web/servlet/redis bans are enumerated and do not include Spring Security). So an accidental placement in `domain`/`application` would **not** be automatically caught — but it would still violate hexagonal intent. The evaluator is an inbound security adapter and belongs in an **infrastructure** (or a config/security) layer, never domain/application. Safe homes that pass all current rules: `rbac.infrastructure.security`, or a cross-cutting `common`/`config` security location. Gate 2 must choose (§10).

2. **`@RequiresPermission` carries `@PreAuthorize` (`org.springframework.security.access.prepost`) and is applied on `interfaces` (controllers).** No current rule blocks interfaces from importing Spring Security or another context's types. If the annotation lives under `rbac`, every other context's controllers (`identity.interfaces`, future `rbac.interfaces`, Epic 3 contexts) will import a `rbac`-owned type — cross-context, but not a cross-*layer* violation under the existing per-package-pattern rules. A `common`-level home avoids making it context-owned and better fits a truly shared contract.

3. **`InsufficientPermissionException extends AccessDeniedException`** cannot live in `common.domain` alongside `DomainException` and the other cross-context exceptions (verified: `common/domain/` holds `DomainException`, `AccountLockedException`, etc.; none extend a Spring Security type) — it extends a Spring Security class, so it introduces a genuinely new exception-placement pattern (requirements R5). `GlobalExceptionHandler` lives in `common.web` and already imports `AccessDeniedException`, so `common.web` (or a `common.security`) can host the exception without `common` gaining a dependency on the `rbac` context. If it were placed under `rbac`, `common.web` would then depend on `rbac` — an undesirable inversion. Gate 2 decision (§10).

4. **Optional new guardrail to consider at Gate 2 (flag, not a mandate):** since no rule currently prevents Spring Security types leaking into `domain`/`application`, Step 3 may want to propose adding such an ArchUnit rule (mirroring the Redis ban at lines 51–57) so this first-of-its-kind mechanism can't erode layering later. Also relevant to R3/Gap 3 (nothing enforces that new controllers actually carry `@RequiresPermission`) — whether an ArchUnit "every controller method is annotated or explicitly opted out" rule belongs to this story is Open Question 6, a **PM/Security decision**, not settled here.

---

## 6. Testing impact

Three test tiers are implied; the first two rely on existing patterns, the third needs a concrete fixture decision.

| Tier | Purpose | Existing pattern to reuse | Gap |
|---|---|---|---|
| **Unit** | Evaluator logic in isolation: permission present/absent (FR1/FR2), tenant-claim match/mismatch (FR3), empty `permissions[]` (Edge 1), missing/malformed `Authentication.getDetails()` fail-closed behaviour (Edge 5, Open Q8). | No existing precedent for unit-testing a `PermissionEvaluator` or `@PreAuthorize` SpEL — **first in codebase** (R7). Straightforward for the evaluator's plain Java logic; SpEL wiring needs the slice tier. |
| **Slice / MockMvc** | Method-security *wiring*: annotation actually intercepts, denial maps to `403 + RBAC_001` via the new handler, 401-vs-403 precedence (FR5 — no JWT reaches the check), tampered-JWT rejected by the filter before the evaluator (Test Scenario 5). | `config/SecurityConfigTest` — `@SpringBootTest(webEnvironment=MOCK)` + H2 + `MockMvc` + `springSecurity()` (no Docker). Directly applicable. | Needs a controller to target — ties to the AC5/AC7 fixture-vs-real-endpoint decision (§3, Open Q3/10). |
| **Integration / security suite (`*IT`)** | The **cross-tenant scenario** (FR3, AC2 — "highest-consequence test", R1 Critical): a caller holding `tenant:write` in Tenant A denied against a Tenant-B-scoped call, with real seeded RBAC data. | `TestcontainersConfiguration` (shared `@TestConfiguration`, real MySQL 8.4, `nexus_app` grants callback) backing `*IT`; `rbac/application/RoleResolutionServiceIT` is the reference. | Requires a concrete endpoint/fixture to call (Open Q10) and a second-tenant seed (US-010's review added exactly this kind of second-tenant seeding in `RoleResolutionServiceIT` — reusable approach). |

**Infrastructure that is missing today:** none new — both the no-Docker MockMvc harness and the Testcontainers MySQL harness already exist. The only genuine unknown is the **test fixture controller** the security/integration tests will target, which is the same open item as §3 (Gate 2). Note the cross-tenant test's severity: R1 is the story's own named Critical risk, and the epic gates CI on this suite being green before Epic 3 starts — treat it as a hard gate, not a nice-to-have.

---

## 7. Non-functional impact

- **Latency:** near-zero added cost by construction. Per FR7 the evaluator does a flat `Set.contains` membership check plus a string comparison of two JWT-claim values already in memory on the request `Authentication` — no DB, no Redis, no network. ADR-0013 D1 deliberately forbids wildcard/hierarchy so evaluation stays O(1)/O(n) over a small in-memory list. The AC6 "< 5ms p95" budget is trivially met; the only measurable cold cost is one-time method-security proxy construction, not steady-state.
- **AC6 "cache hit path" wording — treat as JWT-claim-read-only (do NOT build a cache):** requirements R6 / Open Question 5 flag that "cache hit path" is stale language inherited from the epic's Redis permission cache (used by US-010 only at login/refresh). This per-request enforcement path consults **no cache**. Step 3 should design this as "read `Authentication` details + `Set.contains`" and **must not** introduce any Redis/cache concept (Nexus's Redis is confined to rate-limiting + mint-time permission cache; adding request-path caching would need an explicit ADR — none is warranted here).
- **Scalability:** cost scales only with the size of a user's `permissions[]` array; for the seeded 7-permission model this is negligible. No RPS concern beyond Test Scenario 6's 200 RPS / p95 < 300ms endpoint-level target (which is a system-level figure, not this component's budget).
- **Availability:** adds no new dependency to the already-authenticated hot path, so introduces no new availability risk by construction.
- **Observability — currently a gap, needs a Gate 2 decision (not a build mandate):** the source material specifies **no** logging/metric/audit for a 403 denial (requirements §3 Observability, Gap 1, Open Q7). The existing `GlobalExceptionHandler` already logs handled exceptions at WARN with `event=api_request` structured fields, so an `InsufficientPermissionException` handler would inherit at least a WARN log line for free — but whether a denial emits a dedicated security/audit event (contrast: role assignment events *are* audited per the epic) is an unresolved Security decision for Gate 2. A design without a stated observability plan is incomplete, so Step 3 must at minimum state the log fields/metric for a denial even if it decides against a full audit event.

---

## 8. Dependency & sequencing impact

- **Blocked by:** US-010 (JWT carries `permissions[]`) — **done/merged** (commit `aa028b9`). No blocker remains.
- **Blocks:** US-012, US-013, and every endpoint-protecting story in Epic 3+. This is on the critical path for the whole epic's enforcement story.
- **New library dependencies:** **none.** `spring-boot-starter-security` is already present; `@EnableMethodSecurity`, `@PreAuthorize`, and `PermissionEvaluator` all ship in that starter. No `oauth2-resource-server` (ADR-0007 — hand-rolled JJWT filter stands; the evaluator reads the filter-produced `Authentication`, not a Spring `JwtAuthenticationToken`). No version bumps, no license review needed.
- **In-flight conflict check:** current branch is `feature/US-011`; the only in-flight file is the story doc. The one adjacent concern is the tracked MEDIUM `JwtRs256Service → rbac` coupling (§4) — if a *separate* follow-up were to refactor that into a port concurrently, it touches `identity.infrastructure` and `rbac.application`, not US-011's new files, so no direct edit collision is expected. No other conflicting work identified.

---

## 9. Documentation impact

US-011 creates a **new developer-facing contract** — the first custom security annotation in the platform. This warrants a developer-guide entry showing `@RequiresPermission("resource:action")` usage, the permission-string-only shape (Gate 1 resolution), the 401-vs-403 boundary, the `RBAC_001` response shape, and the **Spring AOP self-invocation caveat** (Edge Case 7 / R8 / Gap 6 — annotated methods called from within the same bean bypass the proxy and are not enforced). This is a **Step 9 (`/docs`) concern** — flag only; do not write it now. ADR-0013 already covers the exception-handling decision (D3), so no new ADR is strictly required unless Gate 2 chooses to add the layering/annotation-enforcement ArchUnit rule (§5.4) or a typed-principal value object (§10), either of which would merit a short ADR note.

---

## What Step 3 (Design / Gate 2) must resolve

Design decisions deliberately **not** made in this impact pass:

1. **Package homes** for `@RequiresPermission`, `TenantAwarePermissionEvaluator`, `InsufficientPermissionException`, and the method-security config — `common`-level (shared, since every context consumes it) vs. `rbac.infrastructure.security` / `rbac.interfaces`. Must keep `common` free of any `rbac` dependency and keep the evaluator out of domain/application (Open Q2, R5).
2. **Typed vs. untyped `Authentication` details** — keep casting the existing untyped `Map<String,Object>`, or introduce a typed principal/details value object (this being the first non-logging consumer of that map; Open Q1, R4).
3. **The evaluator's concrete SpEL/interface shape** under the Gate 1 permission-string-only resolution — whether it genuinely implements Spring's `PermissionEvaluator` interface signatures or is a named SpEL-referenced bean method, given no `tenantId` parameter is passed.
4. **Fail-closed contract** for missing/malformed `Authentication` details (throw `InsufficientPermissionException` → 403 vs. surface a 500) (Open Q8, Edge 5).
5. **Tenant comparison semantics** — raw `String` equality of `JwtClaims.tenantId()` (it is a `String`, not `UUID`) vs. canonicalization (Open Q11, Edge 11).
6. **AC5/AC7 proof mechanism** — real annotated endpoint vs. dedicated test-fixture controller, and the concrete endpoint the cross-tenant `*IT` will call (Open Q3/Q10).
7. **Denial observability** — log fields and whether a security/audit event is emitted on 403 (Open Q7, Gap 1); the design must state this explicitly.
8. **Optional guardrails** — whether to add an ArchUnit rule banning Spring Security types from domain/application, and/or a rule requiring controller methods to be annotated (Open Q6, R3, §5.4).
9. **Single-permission scope confirmation** — `@RequiresPermission` takes exactly one permission string; multi-permission AND/OR composition stays out of scope (Open Q9).

**Explicitly out of scope for this story (unchanged):** field/row-level filtering, ABAC, any request-path caching, and fixing the pre-existing `JwtRs256Service → rbac` coupling.

---

### Cross-references
- Story: `docs/story/2-rbac/US-011.md`
- Requirements: `docs/features/US-011/01-requirements.md`
- ADR-0013: `docs/adr/0013-rbac-data-model-and-enforcement-contract.md`
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java`
- `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- Prior-finding context: `docs/features/US-010/06-code-review.md`
