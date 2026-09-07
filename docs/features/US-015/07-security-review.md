# US-015 — Phase 7 Security Code Audit (Mode B)

_Output of `/security-review` in code-audit mode. **Gate 5 deliverable.** Adversarial review of the shipped implementation of US-015 ("Enable role and role-permission management API") against `03b-threat-model.md`, OWASP Top 10 (2021), and `SECURITY.md`._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-015 · **Branch:** `feature/US-015` · **Reviewer:** Application Security Engineer · **Date:** 2026-09-07
**Verdict:** **PASS — no Blocker.** 0 Blocker · 0 High · 3 Medium · 13 Low.

---

## 0. Scope, method, and attestations

### 0.1 Diff scope

`git diff origin/main...HEAD` is **empty** — the branch tip equals `origin/main` (`cd08f8c`) and the entire story is **staged but uncommitted**. This audit was therefore performed against `git diff HEAD`: **86 files, +10 148 / −183**. Every changed backend main-source file was read in full; test sources were read selectively, by name inventory plus targeted reads of the security-critical cases.

Backend main sources reviewed in full:

| Area | Files |
|---|---|
| Interfaces | `RoleController`, `PermissionController`, `RbacControllerSupport`, `UserRoleController` (migration), 6 DTOs |
| Application | `RoleManagementService`, `RoleAssignmentService` (diff), `RoleManagementPort`, `UserRoleAssignmentPort`, `RbacAuditPort`, `RoleAuditEvent` |
| Domain | `RbacRoleNames`, `RbacDangerousPermissions`, `RoleView`, `PermissionView`, `Role` (diff), 5 new exceptions |
| Infrastructure | `JpaRoleManagementAdapter`, `JpaRoleRepository`, `JpaRolePermissionRepository`, `JpaUserRoleAssignmentAdapter`, `JpaUserRoleRepository`, `RbacDbPrivilegeHealthIndicator`, `RbacAuthEventAdapter` |
| Cross-cutting (unchanged, re-read as trust dependencies) | `GlobalExceptionHandler`, `AuthEventRetryBuffer`, `AuthEventType` |
| Config / policy | `application.yml`, `application-dev.yml`, `application-test.yml`, `pom.xml`, `spotbugs-exclude.xml`, `SECURITY.md`, `monitoring.md`, `runbook.md` |

**Excluded from findings, per the task brief:** the `JpaRoleManagementAdapter#findRole` projection fix (Phase 6, already applied and verified — confirmed present at `JpaRoleManagementAdapter.java:75-77` delegating to the real JPQL projection `findRoleViewById`, not `findById`).

### 0.2 Explicit review attestation (standing policy — auth, crypto, and PII are never approved silently)

- **Authentication — reviewed. No findings.** US-015 adds no authentication code. The new authentication-adjacent surface is `RbacControllerSupport.resolveActor` (`RbacControllerSupport.java:53-77`), which I read line by line. All three fail-closed branches are present and all three **throw**: non-`String` principal → `MALFORMED_AUTHENTICATION` (57-60); non-UUID principal string → `MALFORMED_AUTHENTICATION` (61-67); unparseable tenant → `MISSING_TENANT` (68-75). The class is `final` with a private constructor and only `static` methods (32, 38) — T-S6's two required additions are both shipped. `RbacControllerSupportTest` asserts each branch *throws* rather than returning a falsy value (test names `should_throwMalformedAuthentication_*`, `should_throwMissingTenant_*`), plus `should_bePackagePrivateFinalUtilityClass_when_inspectedViaReflection`. Token validation, expiry, refresh and replay handling are unchanged from US-011 and out of this diff.
- **Authorization — reviewed in depth; this is the story's substance.** See §2. Every one of the six new endpoints carries an explicit `@RequiresPermission`; object-level (IDOR) checks are performed against a **fresh DB read**, never against request input; tenant isolation holds on every new query path. No authorization bypass found.
- **Cryptography — reviewed. No findings.** US-015 introduces no cryptographic code, no key material, and no new randomness source. Ids come from the existing `IdGenerator` / `UuidV7IdGenerator` (`UuidCreator.getTimeOrderedEpoch()`, `SecureRandom`-backed, ADR-0005). Zero `Math.random` in the backend. `roles.id` is exposed in `RoleResponse` but is tenant-scoped and already fully enumerable to any `role:read` holder via `GET /roles`, so UUIDv7's time-ordering adds no enumeration surface.
- **PII — reviewed against the organisation's no-PII rule. No exposure introduced.** `RoleResponse{id,name,description,isSystemRole,createdAt}` and `PermissionResponse{id,name,description}` carry **no user identifier of any kind**. `RoleAuditEvent` (`RoleAuditEvent.java:24-31`) carries UUIDs, a role name, a permission name and a `RequestContext` — and **structurally has no `description` field**, which is the strongest part of the T-T9 position. Every new log key-value is a UUID, a role name, a permission name, or a boolean. `description` — the only tenant-controlled free-text field — is **never logged and never audited** in the shipped code; I verified this by reading every `log.at*` call site in `RoleManagementService` and every branch of `RbacAuthEventAdapter#buildMetadataJson`. See L-01 and L-02 for the two weaknesses in how that invariant is *documented and tested* (the invariant itself holds).

### 0.3 Severity scale

**Blocker** (exploitable now, ship-stopping) · **High** (exploitable with effort or insider access) · **Medium** (defense-in-depth gap) · **Low** (code hygiene with security flavour). Consistent with `03b-threat-model.md` §0.3.

---

## 1. Threat-model cross-reference — every "mitigated" claim, checked against shipped code

This is the primary purpose of a Phase 7 audit on a story that shipped a Gate 2 threat model. Each row states the code location that discharges the claim, or flags it.

| Threat / required change | Claimed status | Verified in code | Result |
|---|---|---|---|
| **T-S5** — tenant/system-role forgery via request body | ✅ closed by omission | `CreateRoleRequest.java:24-33` models exactly `{name, description}`. `is_system_role` hard-coded `false` at `JpaRoleManagementAdapter.java:67`. `tenantId` sourced only from `actor.tenantId()` (`RoleManagementService.java:108`) | **Confirmed** |
| **T-S6** — D4 helper blast radius | ⚠️ partially closed; 2 additions required | `RbacControllerSupport` is `final`, private ctor, all-`static` (32, 38); test asserts each branch throws | **Both additions shipped** |
| **T-T8** — JSON injection into `auth_events.metadata` via `roleName` | ✅ two layers | Layer 1: `RbacAuthEventAdapter.java:18` imports `tools.jackson.databind.ObjectMapper` (Jackson 3, injected); serialisation is `objectMapper.writeValueAsString(metadata)` over a `LinkedHashMap`, never concatenation. Layer 2: `CreateRoleRequest` `@Pattern("^[A-Za-z0-9][A-Za-z0-9 ._-]*$")` excludes `"`, `\`, `<`, `>`, `{`, `}`, all control chars, all non-ASCII | **Confirmed** (see L-11 on the dual-Jackson classpath) |
| **T-T9 / RC-3** — `description` allow-list + never-logged invariant | ❌ change required | Pattern tightened to `^[^\p{Cntrl}  ]*$` (`CreateRoleRequest.java:29-31`) ✅. Invariant stated in `CreateRoleRequest`'s Javadoc ✅. **Not** stated in `RoleView`'s Javadoc ❌ (RC-3 required both) | **Partially discharged — L-01** |
| **T-T10 / D1** — `Role` dirty-flush | ✅ closed by construction | `findRoleViewById` JPQL projection (`JpaRoleRepository.java`, Q2); every `RoleManagementPort` method returns a `RoleView`/`PermissionView`/id/count. `RolePermissionsPrivilegeIT` asserts `UPDATE roles` denied as `nexus_app` | **Confirmed** |
| **T-T11 / D9** — grant drift on `roles`/`role_permissions` | ✅ addressed | `RbacDbPrivilegeHealthIndicator` extended with 8 new legs incl. the `COLUMN_PRIVILEGES` check; `role_permissions` correctly **never** checked for `DELETE` (the permanently-DOWN trap is avoided) | **Confirmed** |
| **T-R5** — committed change, lost audit row | ⚠️ compensated | `RbacAuthEventAdapter` catch-all → `RBAC_AUDIT_WRITE_LOST` ERROR + `nexus.rbac.audit_write_failed{operation}` with the three new tags | **Confirmed** |
| **T-R6 / RC-6** — actor-indexed query blind spot | ⚠️ under-rated; runbook fix | `runbook.md:101` carries the `JSON_UNQUOTE(JSON_EXTRACT(metadata,'$.createdBy'))` query | **Confirmed** (see L-09 on the redundant port method) |
| **T-I6 / RES-4** — 403-vs-404 existence oracle | ✅ accepted as-is | `RoleManagementService.java:255-264`: 404 `ROLE_NOT_FOUND` first, then 403 `CROSS_TENANT_TARGET`. 404 → `handleNotFound`, DEBUG only (`GlobalExceptionHandler.java:66-69`). 403 → `handleInsufficientPermission`, WARN + `nexus.rbac.permission_denied{permission,reason}` (159-176). Both bodies are fixed static literals; neither echoes the id, the tenant, or the role name | **Confirmed implemented exactly as documented — no additional leak** (see §3) |
| **T-I8 / RC-2** — ~30-minute staleness window | ❌ change required | `runbook.md:31` carries the corrected composite wording verbatim | **Confirmed** |
| **T-I9** — log injection via `roleName` | ✅ closed | Every `roleName` emission is `addKeyValue(LOG_KEY_ROLE_NAME, …)` — structured, never concatenated (`RoleManagementService.java:122, 185, 240, 273, 304`). The one parameterised message in the diff (`RbacAuthEventAdapter`, `RBAC_AUDIT_WRITE_LOST`) interpolates only UUIDs and a static `operation` literal | **Confirmed** |
| **T-D6 / RC-4** — unthrottled create / unbounded list | ❌ change required | Per-tenant cap enforced at `RoleManagementService.java:104-106` via `countRolesInTenant` (Q12), default 500, → `RoleLimitExceededException` / RBAC_008. `RoleManagementIT` covers the cap+1 case. Check-then-insert race honestly documented at 94-97 | **Confirmed** (see L-08 on config declaration) |
| **T-D7 / RC-1** — reserved-name squat DoS | ❌ change required | `RbacRoleNames.RESERVED = {TENANT_ADMIN, MEMBER}` + case-insensitive `isReserved` (`RbacRoleNames.java`); enforced **first** in `createRole` (`RoleManagementService.java:101-103`) → `ReservedRoleNameException` / RBAC_007. Two ITs incl. the no-seeded-roles tenant | **Confirmed** |
| **T-D8 / D7** — priority-lane pressure | ✅ ratified | `ROLE_PERMISSION_GRANTED`/`_REVOKED` admitted to `PRIORITY`; `ROLE_CREATED` correctly excluded (`AuthEventType.java:88-95`) | **Confirmed — but the admission rationale has a gap: M-03** |
| **T-E14 / RC-5a** — AC11 must be Q3→Q11 with a locking read | ⚠️ one guard short | `verifyCallerIsActiveTenantAdmin` (`RoleManagementService.java:290-311`) calls `findRoleIdByName` then `hasActiveAdminAssignment`. The adapter delegates to `lockActiveAdminAssignment`, annotated `@Lock(LockModeType.PESSIMISTIC_READ)` (`JpaUserRoleRepository.java:152`) and tenant-scoped. **The ArchUnit ban is shipped** (`HexagonalArchitectureTest.java`, `role_management_service_must_not_call_the_non_locking_admin_read`). `RoleManagementAdminGateIT:158` carries the concurrent-admin-revocation case | **Confirmed — the whole chain, including RC-5a** (see L-07 on the rule's reach) |
| **T-E15 / RC-5b** — AC7 app-layer-only, MEMBER amplification | ❌ change required | `requireMutableRole` is a **single shared guard** called by both write paths before anything else mutable (`RoleManagementService.java:152, 210`). `RolePermissionSecurityIT` carries the two named MEMBER cases (`should_return409WithRbac003_when_attachingRoleWriteToSeededMember`, `…_when_detachingUserReadFromSeededMember`) plus both TENANT_ADMIN cases. `monitoring.md:49` sets the `RBAC_003` alert to `> 0` | **Confirmed** |
| **T-E16 / RC-7** — exploitation-side detection for the D15 residual | ⚠️ acceptance conditional on RC-7 | `nexus.rbac.self_role_assignment` counter + `RBAC_SELF_ROLE_ASSIGNMENT` WARN, **unconditional**, in `RoleAssignmentService.assign()`'s existing post-commit block. `RoleAssignmentEscalationIT` covers both the bare self-assignment and the full two-counter chain | **Counter confirmed shipped and unconditional — but the *composed* alert is not implementable as documented: M-01** |
| **T-E17** — revoke-side admin stripping | ⚠️ folded into RES-1 | `revoke()`'s Javadoc amended to cross-reference `assign()`'s M-3 note and name the successor story | **Confirmed** |
| **T-E18** — cross-tenant + AC11 fail-closed on empty Q3 | ✅ closed | Fail-closed at `RoleManagementService.java:295-299`: `adminRoleId.isPresent() && …` short-circuits to the 403 branch. `RolePermissionSecurityIT:286` is the dedicated IT | **Confirmed** |
| **T-E19 / RC-5c** — silently unenforced `@RequiresPermission` | ⚠️ escape hatch | Both D8 ArchUnit rules shipped with the preferred formulations (`notHaveModifier(FINAL)`, `containAnyMethodsThat(annotatedWith(...))`) — **not** dropped or weakened. Reflection tests additionally assert the exact permission *string* per handler (`assertRequiresPermission("createRole", ROLE_WRITE())`), closing the mis-typed-string vector ArchUnit cannot reach | **Confirmed** (see L-05 for the residual runtime gap) |
| **T-E20 / RC-6 / RES-9** — flag-off is not a privilege rollback | ❌ change required | `runbook.md:81` carries the `BIN_TO_UUID(user_id) … WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL` reverse lookup, with an empirical verification note at 119-122 | **Confirmed** |
| **C2 / §4.5** — named accountable owner | resolved at Gate 2 | Named individual present in `03b-threat-model.md` §4.5, with review date 2026-11-27 and an Epic-3-kickoff hard expiry | **Confirmed** |
| **C3** — successor story exists with an id before merge | required | `docs/story/2-rbac/US-016.md` exists in the diff | **Confirmed** |

**Result: every threat marked mitigated has visible mitigation in the shipped code**, with one partial (RC-3's second Javadoc site, L-01) and one whose *documented composition* exceeds what the shipped metrics can express (M-01).

---

## 2. Component-by-component authorization walk-through

### 2.1 The `attachPermission` guard chain — the story's security-critical path

Verified order in `RoleManagementService.attachPermission` (`:148-200`), against the §8.6-pinned order:

| # | Guard | Line | Failure | Correct? |
|---|---|---|---|---|
| 1 | Tenant resolution — `resolveRoleInTenant` | 151 | 404 `ROLE_NOT_FOUND` → 403 `CROSS_TENANT_TARGET` | ✅ |
| 2 | AC7 system-role immutability — `requireMutableRole` | 152 | 409 `RBAC_003` + WARN | ✅ **before** AC11, as pinned — this is MEMBER's sole gate |
| 3 | Permission existence — `findPermission` | 154-158 | 404 `PERMISSION_NOT_FOUND` | ✅ |
| 4 | AC11 dangerous-permission admin gate | 160-163 | 403 `NOT_TENANT_ADMIN` + WARN, fail-closed on empty Q3 | ✅ |
| 5 | Duplicate pre-check — `hasPermission` | 165-167 | 409 `RBAC_005` | ✅ |
| 6 | Insert (+ `pk_role_permissions` translation backstop) | 168 | 409 `RBAC_005` | ✅ |

No ordering bug. **No path to a `role_permissions` write bypasses guards 1 and 2** — both write methods call both, and the port exposes no other mutator.

### 2.2 IDOR / object-level authorization

Every role-scoped operation resolves the target from the database and compares `view.tenantId()` against `actor.tenantId()` (`:260-262`). Critically, the **post-resolution writes use `role.id()` from the DB projection, not the client's `parsedRoleId`** (`:168, 212`) — so even a hypothetical resolution bug could not be exploited by substituting the id at the write. `permissionId` is deliberately not tenant-scoped, which is correct: `permissions` is a global, migration-seeded, 7-row catalogue with no `tenant_id` column.

### 2.3 Trust of client-supplied identifiers

`tenantId` is **never** accepted from a request body, path, header, or query parameter anywhere in this story — the only source is `AuthenticatedRequestDetails.fromAuthentication` via `resolveActor`. `actorUserId` is always `authentication.getPrincipal()`. Path and body UUIDs are validated against a canonical-UUID regex *before* parsing (`RbacControllerSupport.parsePathUuid`, `AttachPermissionRequest`'s `@Pattern`), so a malformed value yields a 400 with a static message rather than an unhandled `MethodArgumentTypeMismatchException`/`HttpMessageNotReadableException` → 500. `GlobalExceptionHandler` is a plain `@RestControllerAdvice` with no handler for either, so this precaution is load-bearing and correctly implemented.

### 2.4 Feature flag — does it remove attack surface?

`@ConditionalOnProperty(name = "feature.nexus-us015-rbac-role-management.enabled", havingValue = "true")` on **both** controllers; default `false` in `application.yml`. Flag off ⇒ **the beans do not exist** ⇒ no route registered ⇒ 404 at the dispatcher, not a 403 from a live handler. Proven three ways: `RbacRoleManagementFeatureFlagTest` (defaulted / explicit-false / explicit-true, via `ApplicationContextRunner`) and `NexusSmokeTest.should_notRegisterRbacRoleManagementControllers_when_smokeProfileActive` against the **real** smoke-profile context. `RoleManagementService` remains a registered bean when the flag is off, but it has no other caller in the codebase (verified by grep), so no residual reachable surface.

---

## 3. The 403-vs-404 existence oracle (RES-4) — implemented as documented?

The task asked specifically whether this accepted trade leaks more than documented. It does not:

- **Status codes:** exactly as specified — 404 for "no such role anywhere", 403 for "exists in another tenant".
- **Bodies:** both are fixed static literals. 404 → `"No such role"`; 403 → `"You do not have permission to perform this action"` plus a `requiredPermission` property whose value is the compile-time constant `role:read`/`role:write`. Neither body carries the role id, the role name, the owning tenant, or any DB text. Verified at `GlobalExceptionHandler.java:66-69, 172-175`.
- **Telemetry asymmetry** is as designed: the 404 branch is DEBUG-only (invisible in production), the 403 branch is WARN + a counter + a ticket alert. Probe *misses* are not telemetry; probe *hits* are.
- **Timing:** both branches execute the same single `findRoleViewById` PK read and then diverge on an in-memory `UUID.equals`. There is no additional query, lock, or network call on either branch, so no meaningful timing differential is introduced.

**No additional leakage. RES-4 stands as accepted.**

---

## 4. Findings

### Medium

```
[Medium] RC-7's composed escalation alert cannot be evaluated from the shipped metrics — neither counter carries a tenant dimension
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java (self_role_assignment counter, post-commit block of assign())
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:192-196
File: docs/features/US-015/monitoring.md:48, 69
Issue: RES-1 is a **High** residual risk whose acceptance rests entirely on the claim that the
  D15/R-3 chain is *detected*, by composing the mint-side counter with the exploitation-side one.
  monitoring.md:48 specifies "page if nexus_rbac_dangerous_permission_granted_total > 0 **for the
  same tenant**", and the dashboard row at :69 specifies the overlay "per tenant". But
  `nexus.rbac.self_role_assignment` is registered with **no tags at all**, and
  `nexus.rbac.dangerous_permission_granted` carries only `permission`. Neither has a tenant
  dimension, so the per-tenant correlation the acceptance depends on is not expressible in
  PromQL against what ships.
Risk: In a multi-tenant deployment, an operator implementing monitoring.md as written cannot build
  the composed rule. The realistic outcome is that the escalation clause is silently dropped and
  self-assignment stays a low-priority ticket, which is exactly the "unbounded window between
  exploited and noticed" that RC-7 was created to close — the threat model's own stated condition
  for not rejecting the D15 acceptance. OWASP A09 (Security Logging & Monitoring Failures).
Fix: Do NOT add a tenant tag to the counters — tenant id is unbounded-cardinality and would be a
  worse defect. Instead correct monitoring.md to describe the composition that the shipped
  signals actually support: alert globally on `increase(nexus_rbac_self_role_assignment_total[5m])
  > 0` (ticket) and on `increase(nexus_rbac_dangerous_permission_granted_total[15m]) > 0`
  (ticket), and perform the **per-tenant correlation in the log pipeline**, where both
  `RBAC_SELF_ROLE_ASSIGNMENT` and the `ROLE_PERMISSION_GRANTED` INFO line already carry
  `tenantId` as a structured key. State the log query explicitly, the way runbook.md already does
  for the RC-6 and T-R6 queries.

RESOLUTION (2026-09-08): user made an informed decision against this report's recommendation —
  tagged both counters with `tenantId` instead of correlating in the log pipeline, accepting the
  cardinality tradeoff (bounded by tenant count, not unbounded; the two counters are the only
  tenant-tagged RBAC metrics in this story). `monitoring.md` and `03-design.md` §9.2/§9.3/§9.6
  updated with the real composed PromQL expression (`... and on (tenantId) ...`).
  `RoleAssignmentEscalationIT`'s two counter-read helpers updated to scope by `tenantId` — required
  because the shared *IT MeterRegistry now holds one Counter instance per tenant ever seen in the
  run, so an untagged `find()` would match an arbitrary one. Full verify: 960 unit + 284 IT green.
```

```
[Medium] The alerting that RES-1's risk acceptance depends on exists only as markdown; nothing in the repository deploys or tests it
File: docs/features/US-015/monitoring.md:44-53 (8 alert rules, Prometheus expressions)
Issue: There is no alerting-as-code anywhere in the repository — no Prometheus rule file, no
  Alertmanager config, no test asserting an expression parses or that a metric with the referenced
  name is actually emitted under the referenced tag values. The counters and the WARN/ERROR logs
  are genuinely wired and unit/integration-tested (RoleAssignmentEscalationIT,
  RoleManagementAuditIT), so the *signal* ships; the *detection* does not.
Risk: Every compensating control for RES-1 (High), RES-5 (Medium) and RES-9 (Medium) is a
  documented alert expression. If none is deployed, three accepted residual risks are running with
  their compensating controls absent, and nothing in CI or at deploy time notices. OWASP A09.
  This is a pre-existing, platform-wide convention rather than a US-015 regression — no prior story
  ships alert rules either — but US-015 is the first story to make a **High** residual acceptance
  contingent on one, which changes its weight.
Fix: Either (a) commit the eight rules as a Prometheus rule file under version control and add a
  CI step that lints it (`promtool check rules`), or (b) if alerting genuinely lives in an
  out-of-band ops repository, add a pre-merge checklist item to 04-tasks.md requiring written
  confirmation that the two RES-1 rules are deployed before the flag is enabled in production —
  and record in §4.5 of the threat model that the acceptance is void until they are.
```

```
[Medium] An attach/detach cycle can flood the capacity-200 drop-newest PRIORITY audit lane; D7's admission rationale conflates row distinctness with row volume
File: nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java:75-95
Issue: ROLE_PERMISSION_GRANTED and ROLE_PERMISSION_REVOKED were admitted to the PRIORITY lane on
  the stated grounds that "uniqueness is bounded by |permissions| = 7 per role, so a probing loop
  cannot mint unbounded distinct rows". The PRIORITY lane is a fixed-capacity (200) ArrayBlockingQueue
  with drop-newest overflow — it is bounded by row **volume**, not row **distinctness**. A
  `role:write` holder can loop attach → detach → attach on a single custom role indefinitely,
  emitting two PRIORITY-lane events per iteration. RC-4's per-tenant role cap bounds role
  *creation*; nothing bounds attach/detach cycling. ROLE_CREATED was correctly excluded for
  precisely this hazard profile, but the exclusion reasoning stops at distinctness too.
Risk: During an audit-pipeline outage — the only condition under which the retry buffer fills — a
  `role:write` holder can drive the PRIORITY lane to its 200-row cap and cause drop-newest eviction
  of genuinely critical events queued behind it: LOCKOUT, TOKEN_REFRESH_REUSE, PASSWORD_CHANGED,
  ROLE_ASSIGNED. Preconditions are real but narrow (concurrent audit outage + an authenticated
  `role:write` holder, which today means TENANT_ADMIN), so this is insider/defense-in-depth, not
  an unauthenticated path. OWASP A04 (Insecure Design) / A09.
Fix: No code change required for this release. Record it as a residual with a monitored trigger:
  the per-event-type lane-depth panel (monitoring.md) already exists — add a rule alerting when
  ROLE_PERMISSION_GRANTED + ROLE_PERMISSION_REVOKED together exceed a fixed share of PRIORITY-lane
  depth. If a cheap control is wanted, the natural one is a per-role attach/detach churn counter
  (`nexus.rbac.role_permission_churn`) at the same post-commit site, alerting at a low threshold.
  Correct the AuthEventType comment so a future reader is not told that a 7-permission bound makes
  the lane safe.
```

### Low

```
[Low] RC-3's never-log/never-audit invariant is documented on only one of the two required sites
File: nexus-backend/src/main/java/com/example/nexus/rbac/domain/RoleView.java (class Javadoc)
Issue: RC-3 part 2 required the constraint to be stated "in CreateRoleRequest's **and RoleView's**
  Javadoc, next to the field". CreateRoleRequest carries it and forward-references RoleView
  ("RoleView#description() carries the same constraint"), but RoleView's own Javadoc discusses only
  the projection-vs-entity rationale and says nothing about `description`.
Risk: RoleView is the type a future developer holds when writing a log line or an audit payload —
  it is the more likely point of accidental violation, and it is the one without the warning.
Fix: Add the sentence from CreateRoleRequest's Javadoc to RoleView's, next to the `description`
  component.
```

```
[Low] The "description is never logged" test cannot observe the layer where the risk actually lives
File: nexus-backend/src/test/java/com/example/nexus/rbac/interfaces/rest/RoleControllerTest.java:146-175
Issue: should_neverLogDescription_when_creatingRoleWithMarkerDescription attaches a root ListAppender
  and asserts the marker never appears — but it runs in a WebMvc slice with RoleManagementService
  **mocked**, so the service's own post-commit INFO block (the only place that logs role fields at
  all) never executes. The test proves the controller, filter chain and exception handler are clean;
  it cannot fail if someone adds `.addKeyValue("description", ...)` to the service.
Risk: The invariant is asserted where it was never at risk and unasserted where it is. The shipped
  code IS clean — I verified every log site in RoleManagementService by reading — but the guard
  against regression is illusory.
Fix: Add the equivalent ListAppender assertion to RoleManagementServiceTest around a real
  createRole/attachPermission/detachPermission call, where the post-commit block runs inline via
  the no-active-transaction fallback.
```

```
[Low] No end-to-end negative-control proving a token lacking role:read / role:write is rejected on the six new endpoints
File: nexus-backend/src/test/java/com/example/nexus/rbac/security/RolePermissionSecurityIT.java
Issue: Every test in the end-to-end security IT mints a JWT that HAS the required permission and
  then exercises a service-layer denial (409/403 from AC7/AC8/AC11). Enforcement of
  @RequiresPermission itself is covered indirectly — annotation presence + exact permission string
  by reflection (RoleControllerTest/PermissionControllerTest), proxyability by the two D8 ArchUnit
  rules, and the mechanism generically by the pre-existing RequiresPermissionMockMvcTest — but
  there is no single test that drives a real HTTP request with a real under-privileged JWT at any
  of the six new URIs and asserts 403 RBAC_001.
Risk: The composite coverage is genuinely good and I found no defect, but the threat model listed
  "per-endpoint negative-control 403 tests" among the four things that must not be quietly
  descoped, and this is the one that partially was. A future change to SecurityConfig's matcher
  ordering would not be caught by any of the three indirect controls. OWASP A01.
Fix: Add one parameterised test to RolePermissionSecurityIT that mints a JWT with `user:read` only
  and asserts 403 with code RBAC_001 against each of the six URI/method pairs.
```

```
[Low] No negative control that GET /roles filters other tenants' roles out of the result
File: nexus-backend/src/test/java/com/example/nexus/rbac/security/RolePermissionSecurityIT.java
Issue: AC8 is enforced three ways: 404-then-403 on {roleId} (three cross-tenant tests present ✅),
  and result-filtering on the list endpoint (`findRoleViewsByTenantId`). The list path has no
  cross-tenant test — RoleManagementServiceTest's listRoles cases use a mocked port, and there is
  no IT that seeds roles in two tenants and asserts GET /roles returns only one tenant's.
Risk: Low — the JPQL predicate is `WHERE r.tenantId = :tenantId` with no join, so the failure mode
  is remote. But it is the one AC8 path with no negative control, and a future addition of an
  optional filter parameter is exactly how such a query loses its tenant predicate. OWASP A01.
Fix: One IT: seed a role in each of two tenants, assert GET /roles as tenant A returns only A's.
```

```
[Low] createRole translates every DataIntegrityViolationException into "duplicate role name"
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleManagementAdapter.java:65-72
Issue: The catch is on the base DataIntegrityViolationException, not on a uniqueness-constraint
  discriminator. Any integrity failure on the roles INSERT — an FK violation on tenant_id, a
  not-null violation, a future CHECK constraint — is reported to the client as 409 RBAC_006
  "A role with this name already exists in this tenant".
Risk: Not a disclosure issue (the message is a fixed literal and correctly never echoes the caught
  exception, per SECURITY.md's rule and DuplicateRoleNameException's own Javadoc). It is a
  detection issue: a genuine integrity fault is misreported as a benign, expected user error and
  is invisible in the RBAC_006 conflict counter, which is otherwise a clean signal. attachPermission
  (:118-125) has the same shape but a much smaller surface (a 2-column PK join row).
Fix: Optional. If tightened, discriminate on the constraint name before translating and rethrow
  otherwise, so the generic handler produces a 500 + ERROR log for a real integrity fault.
```

```
[Low] createRole's post-insert re-read uses orElseThrow() with no supplier, yielding an untyped 500
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:111
Issue: `roleManagementPort.findRole(newRoleId).orElseThrow()` raises a bare NoSuchElementException,
  which falls through to handleUnexpected → 500 INTERNAL_ERROR.
Risk: Effectively unreachable (same transaction, immediately after a flushed INSERT). The response
  leaks nothing — handleUnexpected returns a fixed literal and logs only the exception class name.
  Flagged purely as hygiene on a security-critical service: every other failure mode on this path
  is a typed domain exception with an error code.
Fix: `.orElseThrow(() -> new IllegalStateException("Role vanished after insert"))` or an explicit
  typed exception, so the ERROR log names the actual invariant that broke.
```

```
[Low] The RC-5a ArchUnit ban is keyed to one class name and one method signature
File: nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java
      (role_management_service_must_not_call_the_non_locking_admin_read)
Issue: The rule is `noClasses().that().haveSimpleName("RoleManagementService").should().callMethod(
  UserRoleAssignmentPort.class, "findActiveAssignmentViews", UUID.class, UUID.class)`. It does not
  cover (a) a future second application service in rbac.application that reaches for the same
  method, (b) a rename of RoleManagementService, or (c) any other non-locking read added to the
  port later.
Risk: The rule closes today's exact hazard, which is the realistic one and is the right call. But
  the invariant it encodes — "authorization decisions use the locking read" — is broader than the
  rule, so the rule will quietly stop covering the invariant as the context grows.
Fix: Widen the `that()` clause to `resideInAPackage("..rbac.application..")` and exclude
  RoleAssignmentService by name, which inverts the maintenance burden onto the one legitimate
  caller instead of onto every future one.
```

```
[Low] nexus.rbac.max-roles-per-tenant is declared only as an inline @Value default
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:79
File: nexus-backend/src/main/resources/application.yml (absent)
Issue: RC-4's cap is `@Value("${nexus.rbac.max-roles-per-tenant:500}")` with no corresponding entry
  in application.yml. Every comparable tunable in this codebase is declared there with an
  environment-variable indirection (e.g. `${NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS:900}`).
Risk: A security control (a DoS ceiling on an unthrottled write endpoint) is invisible to anyone
  reading the configuration, and the house pattern for overriding it per environment is absent —
  so an operator responding to an incident has no documented lever. OWASP A05 (Security
  Misconfiguration).
Fix: Add `nexus.rbac.max-roles-per-tenant: ${NEXUS_RBAC_MAX_ROLES_PER_TENANT:500}` to
  application.yml with a comment pointing at RC-4/T-D6, matching the surrounding style.
```

```
[Low] findActiveUserIdsForRole ships with no production caller and is deliberately not tenant-scoped
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java:92
File: .../infrastructure/persistence/JpaUserRoleAssignmentAdapter.java:102-105
File: .../infrastructure/persistence/JpaUserRoleRepository.java:183-189
Issue: RC-6 asked for a **runbook DBA query**, and runbook.md:81 duly carries it. The port method
  is an additional implementation of the same lookup with no caller anywhere in main sources
  (verified by grep — only its own adapter unit test references it). Its Javadoc explicitly states
  it is "deliberately NOT tenant-scoped" and that "this story's own runtime flows never call it".
Risk: A tenant-unscoped, user-id-returning reverse lookup sitting on a live port is a ready-made
  IDOR primitive for whoever wires it up next. The Javadoc rationale ("the role id already pins the
  tenant") is correct today but is exactly the kind of implicit invariant that a future endpoint
  author will not re-derive. OWASP A01 / A04.
Fix: Either delete it (the runbook query already discharges RC-6 and is the documented mechanism),
  or add the tenantId parameter and use it, so the method is safe to call from anywhere. If it is
  kept as-is, add an explicit "not for use on any request-scoped path" line to its Javadoc.
```

```
[Low] Dual Jackson 2 / Jackson 3 classpath, with the correct choice enforced only by Javadoc and review
File: nexus-backend/pom.xml (transitively) — tools.jackson.core:jackson-databind:3.1.4 via flyway-core,
      com.fasterxml.jackson.core:jackson-databind:2.21.4 via jjwt-jackson
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java:18
Issue: Both ObjectMapper types are on the compile classpath. The adapter correctly imports
  tools.jackson.databind.ObjectMapper (Jackson 3, the Spring Boot 4.1 auto-configured bean) and
  its Javadoc forbids the Jackson-2 type by name — this is T-E13 carried forward correctly, and the
  shipped code is right. But nothing mechanical prevents an IDE auto-import from selecting
  com.fasterxml.jackson.databind.ObjectMapper in a future edit, and both types compile identically
  at the call site (`writeValueAsString(Map)`).
Risk: Low in practice — Jackson 2 also escapes JSON correctly, so a wrong import degrades
  consistency and the injected-bean contract, not the T-T8 escaping guarantee itself. Recorded
  because T-T8's primary layer rests on this single import line. OWASP A06 / A08.
Fix: One ArchUnit rule: no class in ..identity.infrastructure.audit.. may depend on
  com.fasterxml.jackson.databind.ObjectMapper. Converts a Javadoc prohibition into a build failure,
  matching D8's stated philosophy.
```

```
[Low] Health-indicator GRANTEE pattern interpolates the DB username into a LIKE expression
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java
      (grantee(String userName) → "'" + userName + "'@%", bound as the LIKE parameter)
Issue: The value is bound as a PreparedStatement parameter (no SQL injection — the refactor to
  countMatches() with call-site literal SQL is correct and improves on the prior shape). But the
  bound value is a LIKE **pattern**: `%` or `_` inside the DB username would act as wildcards.
Risk: Effectively nil — userName comes from SELECT CURRENT_USER() via DbUserUtil, never from a
  request. The theoretical impact is a widened GRANTEE match producing a false-positive DOWN, not
  a bypass. Recorded for completeness because this is a security-control component.
Fix: None required. If desired, escape `%` and `_` in grantee(), or match on GRANTEE equality
  against both `'user'@'%'` and `'user'@'localhost'`.
```

```
[Low] Test-scope commons-compress 1.24.0 predates the 1.26.0 DoS fixes
File: nexus-backend/pom.xml (transitive: org.testcontainers:testcontainers:1.21.3 → commons-compress:1.24.0, test scope)
Issue: commons-compress < 1.26.0 is affected by CVE-2024-25710 (infinite loop / DoS on a crafted
  DUMP archive) and CVE-2024-26308 (allocation-of-resources DoS on a crafted pack200 archive).
Risk: Not shipped — test scope only, reached solely by Testcontainers parsing Docker images the
  build itself supplies. No untrusted archive crosses it. OWASP A06, informational.
Fix: Optional. Pin commons-compress to ≥1.26.2 in dependencyManagement if the OSS-scan gate
  flags it, or suppress with this justification.
```

```
[Low] Frontend devDependency vulnerabilities: 15 total (1 critical, 7 high, 4 moderate) — zero in production dependencies
File: nexus-frontend/package-lock.json
Issue: `npm audit --audit-level=moderate` reports 15 advisories across the build toolchain —
  node-tar (critical + high, PAX type confusion / decompression DoS / infinite loop / uncontrolled
  recursion), brace-expansion (high, exponential-time DoS), undici (moderate, response
  desynchronisation / CRLF injection / cookie attribute injection), @babel/core, @hono/node-server
  (moderate, path traversal via encoded backslash on Windows). `npm audit --omit=dev` reports
  **found 0 vulnerabilities** — none of these reach the shipped browser bundle.
Risk: Build-pipeline supply-chain exposure (OWASP A06 / A08), not runtime exposure to end users.
  Reported explicitly rather than skipped, per audit policy.
Scope note: **US-015 changes zero frontend files** (confirmed: no nexus-frontend path appears in
  `git diff HEAD --stat`, and pom.xml's only change is the removal of a JaCoCo exclusion — zero
  new backend dependencies). These findings are pre-existing repository state and are not
  attributable to this story; they are recorded here because the audit ran the scan.
Fix: Out of scope for US-015. Raise as a separate maintenance item; most are resolved by
  `npm audit fix` (all report fixAvailable: true). Verify the @emnapi lockfile-prune trap noted in
  project memory before committing any lockfile change on Windows.
```

---

## 5. OWASP Top 10 (2021) summary

| ID | Category | Result |
|---|---|---|
| **A01** | Broken Access Control | **Clean on the shipped paths.** Six endpoints, six explicit `@RequiresPermission`. Tenant isolation verified on every new query. IDOR closed by resolving from a fresh DB read and writing with the DB-sourced id. Two test-coverage gaps: L-03, L-04. Latent primitive: L-09 |
| **A02** | Cryptographic Failures | **Clean.** No new crypto, no new key material, no new randomness source. `SecureRandom`-backed UUIDv7 ids only. No secret, token, or credential appears in any new DTO, log, URL, or metric tag |
| **A03** | Injection | **Clean.** Every new query is a parameterised Spring Data derived method or `@Query` — Q1, Q2, Q3, Q7, Q9, Q12 all reviewed, zero string concatenation. The health indicator's JDBC SQL is call-site-literal with a bound parameter (L-10 is a LIKE-pattern nit, not injection). JSON injection into `auth_events.metadata` closed by Jackson-3 map serialisation + an ASCII allow-list (T-T8). Log injection closed by structured `addKeyValue` + the same allow-list (T-I9) |
| **A04** | Insecure Design | **One finding: M-03** (PRIORITY-lane volume vs. distinctness). The design work is otherwise unusually strong — single shared guards, fail-closed defaults, enforcement-by-omission on the create DTO, a per-tenant cap on the one growth this API cannot reverse |
| **A05** | Security Misconfiguration | **One finding: L-08** (undeclared cap property). Flag defaults to off in `application.yml`; enabled only in dev and test profiles; smoke profile verified off against the real context |
| **A06** | Vulnerable & Outdated Components | **Zero new dependencies** (confirmed against the full `dependency:tree`). Backend stack is current: Spring Boot 4.1.0, Spring Framework 7.0.8, Spring Security 7.1.0, Hibernate 7.4.1, mysql-connector-j 9.7.0, BouncyCastle 1.84, jjwt 0.12.6, logback 1.5.34. Findings L-11, L-12, L-13 |
| **A07** | Identification & Authentication Failures | **Clean.** No authentication code added. `resolveActor`'s three fail-closed branches reviewed and tested. No session, no credential, no MFA surface touched |
| **A08** | Software & Data Integrity Failures | **Clean on the story's own surface.** `auth_events` remains append-only at the privilege level; `roles` has no `UPDATE`/`DELETE` grant; the health indicator now detects drift on both new tables including the column-scoped leg. Supply chain: L-13 (frontend dev toolchain) |
| **A09** | Security Logging & Monitoring Failures | **Two findings: M-01, M-02.** The *emission* side is strong — three INFO success logs, two WARN denial logs, one ERROR audit-loss log, five counters, three new append-only audit types, all structured and all covered by ITs. The *detection* side is where the gaps are |
| **A10** | SSRF | **Not applicable.** No outbound HTTP, no URL parsing, no user-supplied endpoint anywhere in the diff |

---

## 6. Dependency scans (run, not skipped)

**`cd nexus-backend && ./mvnw dependency:tree`** — completed successfully; full tree captured and reviewed. **Zero dependency changes in this story**: the only `pom.xml` edit is the removal of a now-obsolete JaCoCo coverage exclusion for `*.rbac.infrastructure.persistence` (that package gained a concrete adapter class in this story, so the empty-package workaround is no longer needed). No new `<dependency>` element, no version change. CVE review of the resulting tree found no known-affected **compile/runtime** artefact; the two notes are L-12 (test-scope commons-compress) and L-11 (dual-Jackson classpath, a hygiene rather than a CVE concern).

**`cd nexus-frontend && npm audit --audit-level=moderate`** — a `nexus-frontend` directory **does exist**, so the scan was run rather than skipped on the grounds of scope. Result: 15 advisories (1 critical, 7 high, 4 moderate, 3 low), **all in devDependencies**; `npm audit --omit=dev` reports `found 0 vulnerabilities`. **US-015 changes zero frontend files**, so these are pre-existing repository state, recorded as L-13 and explicitly not attributed to this story.

_Caveat recorded honestly: this CVE assessment is based on advisory knowledge as of the reviewer's training cutoff plus the live `npm audit` database. It is not a substitute for the repository's OSS-scanning CI gate, which should be treated as authoritative for the backend tree._

---

## 7. Verdict

**PASS. No Blocker finding. No High finding.**

Nothing here stops the release. All three Medium findings are **detection and documentation** gaps rather than exploitable defects — the enforcement code is correct, the signals are emitted, and the tests that matter most (the concurrent admin-revocation case, the `nexus_app` privilege ITs, the MEMBER negative controls, the adversarial JSON corpus) are all present and were not descoped.

Every one of the seven required changes from the Gate 2 threat model (RC-1 … RC-7) is visible in the shipped code or the shipped runbook, and every threat marked "mitigated" has a code location behind it. The single load-bearing control — AC11's `Q3 → Q11` chain with a `PESSIMISTIC_READ` locking read, plus the RC-5a ArchUnit ban on the non-locking shortcut — is implemented exactly as mandated, including the ArchUnit rule that turns the F1 trap into a build failure.

**Recommended before enabling the flag in production:**
1. Resolve **M-02** — either commit the alert rules or record explicitly that the RES-1 acceptance is void until they are deployed out of band.
2. Correct **M-01**'s monitoring.md wording to the composition the shipped metrics actually support.

Neither is a merge blocker. Both are prerequisites for the *risk acceptance* in RES-1 to hold as written.

---

### Cross-references

- `docs/features/US-015/03b-threat-model.md` — the Gate 2 threat model this audit verifies, threat by threat (§1)
- `docs/features/US-015/03-design.md` — D1, D4, D5, D6, D7, D8, D9, D11, D15, D16 and §8.6's pinned check ordering
- `docs/features/US-015/monitoring.md` · `runbook.md` — the operational artifacts assessed in M-01, M-02 and §1
- `docs/story/2-rbac/US-016.md` — the successor story required by condition C3; present
- `SECURITY.md` §3.1 and the new RBAC error-code register (RBAC_001 … RBAC_008) — house rules applied throughout
