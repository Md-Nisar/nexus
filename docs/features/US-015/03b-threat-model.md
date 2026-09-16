# US-015 — STRIDE Threat Model: Enable role and role-permission management API

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md`. Feeds `/breakdown` (Phase 4) and discharges the design's D15 condition **C2**._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-015 · **Reviewer:** Application Security Engineer · **Status:** Gate 2 review — **conditional pass, 6 design changes required**

---

## 0. Scope, verification basis, and headline result

**Scope.** The design in `docs/features/US-015/03-design.md`: `RoleController` / `PermissionController` / `RbacControllerSupport` (6 endpoints), `RoleManagementService` and its AC7/AC8/AC11 guard chain, the new `RoleManagementPort` / `JpaRoleManagementAdapter`, the Q1–Q11 query set, the `RoleAuditEvent` / `RbacAuditPort` / `RbacAuthEventAdapter` audit path, the `nexus_app` privilege boundary on `roles` / `role_permissions`, the D8 ArchUnit rules, the D9 health-indicator extension, and the D11 feature flag. US-009's schema, US-011's enforcement, US-012's `RoleAssignmentService`, and US-014's audit pipeline are in scope **as trust dependencies** — and, in the case of US-012's `assign()` / `revoke()`, as the other half of a live escalation chain this story makes reachable.

**The load-bearing fact for this whole document.** `TenantAwarePermissionEvaluator.hasPermission` (`common/security/TenantAwarePermissionEvaluator.java:44-51`) performs a flat `details.hasPermission(permission)` membership test on the JWT `permissions[]` claim and **nothing else** — no tenant comparison, no resource comparison, no admin-status check. Its own Javadoc (lines 15-29) says so. **AC7, AC8, AC9 and AC11 are therefore entirely service-layer logic in `RoleManagementService`, with no backstop from the enforcement annotation and — for `role_permissions` — no backstop from the database either.** Every Elevation finding below descends from this.

### 0.1 Verification basis — code and configuration re-read this session, not trusted from the design doc

| Claim under test | Verified how | Result |
|---|---|---|
| Evaluator does no tenant/resource comparison | `common/security/TenantAwarePermissionEvaluator.java:44-51` | **Confirmed** — single `details.hasPermission()` call; Javadoc 15-29 states the invariant explicitly |
| **F1: `hasActiveAdminAssignment` is a locking read; `callerHoldsActiveTenantAdmin` is not** | `rbac/application/port/out/UserRoleAssignmentPort.java:35-42` and `rbac/application/RoleAssignmentService.java:287-303` | **Confirmed, and the distinction is real.** Port Javadoc 35-41 mandates `PESSIMISTIC_READ`, forbids a JWT claim, and forbids "a plain non-locking read, because a non-locking read is a REPEATABLE-READ snapshot that can miss a concurrent revocation". `callerHoldsActiveTenantAdmin` 287-303 self-documents as "a plain (non-locking) read… only decides whether to redact one response field, not whether to authorize a mutation" |
| **R-3 mint side: AC8 matches role *name*, not privilege** | `RoleAssignmentService.java:107` | **Confirmed** — `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())` |
| **R-3 propagate side: `revoke()`'s T-E9 hole is symmetric** | `RoleAssignmentService.java:180-188` (Javadoc) and `191-260` (body) | **Confirmed, and the design under-states its consequence.** `revoke()` has **no** admin gate at all. Its only guard (208-225) is the actor-agnostic last-admin count check `lockedActiveAdminIds.size() <= 1 && contains(ref.id())` — which blocks removal of the **final** admin assignment only. A non-admin holding `user:write` can therefore strip a tenant from N admins down to **1**. See T-E17 |
| M-3 forward-tracking Javadoc exists as quoted | `RoleAssignmentService.java:79-91` | **Confirmed** — including the closing sentence D13 replaces verbatim |
| **AC7 has no DB backstop on `role_permissions`** | `nexus-database/mysql/init/02-grants-post-schema.sql:31-35` and `db/migration/V5__rbac_schema.sql:45-53, 96` | **Confirmed.** `GRANT SELECT, INSERT, DELETE ON nexus.role_permissions` (line 33). `role_permissions` has no soft-delete column and **no trigger** — the only trigger in V5 is `trg_user_roles_no_delete` on `user_roles` (V5:96) |
| **No `UPDATE` grant on `roles`** | `02-grants-post-schema.sql:32` | **Confirmed** — `GRANT SELECT, INSERT ON nexus.roles`. No `UPDATE`, no `DELETE`. AC7's *rename/flip* backstop is real; its *role_permissions* backstop does not exist |
| **MEMBER amplification: the seeded MEMBER role is held by every self-registered user** | `V5__rbac_schema.sql:119-135` and `RoleAssignmentService.java:268` | **Confirmed** — MEMBER is seeded with `user:read` only; `RoleAssignmentService`'s own Javadoc line 268 states "every self-registered `MEMBER`". Attaching a dangerous permission to MEMBER is a **tenant-wide** escalation. See T-E15 |
| **AC10 staleness: role-set fingerprint does not detect permission edits** | `rbac/application/RoleResolutionService.java:22-29, 53-68` and `port/out/PermissionCachePort.java:10-21` | **Confirmed in code, in the source's own words.** `RoleResolutionService` Javadoc 27-29: *"A role's own permission set changing without any role (re-)assignment (a future US-015 concern) is **not covered by this fingerprint**"*. `resolve()` 60-62 returns the cached payload whenever `sameRoles(...)` matches |
| **AC10 window is ~30 min, not the 15 the design states** | `application.yml:143` (`permission-cache-ttl-seconds: 900`), `application.yml:185` (`access-token-ttl-seconds: 900`), `RoleResolutionService.java:17-18` ("consulted at JWT-mint time… never per protected-API-request") | **Confirmed — the design's own correction is still short by a factor of 2.** See T-I8 |
| Jackson-3 injected mapper is the escaping mechanism | `identity/infrastructure/audit/RbacAuthEventAdapter.java:17, 54, 152` | **Confirmed** — `import tools.jackson.databind.ObjectMapper`, injected, `objectMapper.writeValueAsString(metadata)` at 152. Javadoc 28-34 forbids the Jackson-2 type and hand-instantiation |
| `buildMetadataJson` omits null keys; `withUserId` is hard-wired to `targetUserId` | `RbacAuthEventAdapter.java:105, 134-153` | **Confirmed** — F2 is real; `RbacAuditEvent` has nowhere to carry `permissionId`/`permissionName` |
| `AuthEventType` priority lane is 6; the 3 new constants are absent | `identity/domain/AuthEventType.java:44-49, 67-74` | **Confirmed** — `PRIORITY` holds 6 including `ROLE_ASSIGNED`/`ROLE_REVOKED`; `ROLE_ASSIGNMENT_DENIED` deliberately excluded (48-49, 56-59) |
| `handleConflict`/`handleNotFound` are DEBUG; `handleInsufficientPermission` is WARN + counter | `common/web/GlobalExceptionHandler.java:65-76, 159-176` | **Confirmed** — AC7 blocks are invisible at production log levels without D12's service-level WARN. `nexus.rbac.permission_denied{permission, reason}` is emitted at 167-171 |
| `RBAC_003`/`RBAC_005`/`RBAC_006` dispatch by base type, zero new handler code | `GlobalExceptionHandler.java:71-76` | **Confirmed** — `@ExceptionHandler(ConflictException.class)` → 409 using `e.code()` |
| §6.5 squat: a `TENANT_ADMIN`-named non-system role fails closed for escalation | Traced `RoleManagementPort#findRoleIdByName` (design §4.3) → `UserRoleAssignmentPort#hasActiveAdminAssignment`, and `RoleAssignmentService.java:107-123` | **Confirmed fail-closed for escalation — and refuted as "harmless".** See T-D7 |
| D6's `name` pattern permits `TENANT_ADMIN` | Design §8.1 `^[A-Za-z0-9][A-Za-z0-9 ._-]*$` — underscore is in the class | **Confirmed** — the squat passes validation |
| D16 is **not** in the residual-risk table | Design §12.3 (prose) vs §12.5 (RES-1…RES-8) | **Confirmed absent.** See T-E20 / required change RC-6 |
| Zero new dependencies proposed | Design §0, §10 of `02-impact.md` | **Confirmed by document review.** No `pom.xml` dependency change, no `package.json` change, no frontend file. `./mvnw dependency:tree` / `npm audit` are **deferred to the Phase 7 code audit** — this is a design-phase review with no code to scan. Recorded rather than silently skipped |

### 0.2 Headline result

**The design is unusually strong.** It correctly identifies and pins the story's two most dangerous traps (F1's non-locking read, F2's carrier mismatch), it refuses to record the M-3 gap as discharged, it converts a Javadoc convention into an ArchUnit build failure (D8), it closes the entity-dirty-flush footgun by construction (D1 projections), and D16 catches an inherited rollback falsehood that would otherwise have shipped in a runbook. §6.5's fail-closed tracing of the reserved-name case is correct as far as it goes.

**Six things still need to change before Gate 2 closes.** In order of severity:

1. **The D15 compensating control detects the wrong event** (T-E16). `nexus.rbac.dangerous_permission_granted` fires on the *legitimate admin action that creates the precondition*, and is silent on the *actual exploitation*. The design's claim that "the window between reachable and noticed is minutes" is true and irrelevant — the window between **exploited** and **noticed** is unbounded.
2. **AC10's corrected window is still wrong** (T-I8). ~30 minutes, not 15, and the wrong figure is about to be written into a runbook, Test Scenario 8, and Epic 3 UI copy.
3. **The reserved-name squat is a permanent, app-unremediable tenant DoS** (T-D7), not the harmless curiosity §6.5 records.
4. **`GET /roles` / `POST /roles` is a stored response-amplification DoS** with no ceiling (T-D6).
5. **AC7's negative-control tests name only `TENANT_ADMIN`**, never `MEMBER` — the higher-impact target (T-E15).
6. **D16 has no severity rating and its remediation path has no reverse lookup** (T-E20).

None is a Blocker. All six are cheap. **Verdict: conditional pass** — Gate 2 may close once RC-1…RC-6 (§7) are folded into `03-design.md`.

### 0.3 Explicit review attestation (standing policy — auth, crypto, and PII are never approved silently)

- **Authentication — reviewed.** US-015 adds no authentication code. It consumes the `Authentication` produced by `JwtAuthenticationFilter` and validated by `JwtRs256Service` (RS256 pinned; reviewed under US-011 T-01/T-02, unchanged). The new authentication-adjacent surface is `RbacControllerSupport.resolveActor` — three fail-closed branches (`MALFORMED_AUTHENTICATION` ×2, `MISSING_TENANT`), reviewed under **T-S5** and **T-S6**. The inherited trust dependency on US-011 T-02 (tenant-provenance invariant, `TenantAwarePermissionEvaluator.java:15-29`) is unchanged and still load-bearing: if any future code assembles `tenantId` and `permissions` from different tenant contexts, nothing in US-015 detects it.
- **Authorization — reviewed in depth; this is the story's entire substance.** AC8 tenant isolation (T-E18), AC7 system-role immutability (T-E15), AC11 dangerous-permission gating (T-E14), the R-3 propagate-side residual (T-E16, T-E17), `@RequiresPermission` enforcement integrity (T-E19), and the D16 privilege-persistence-after-rollback finding (T-E20).
- **Cryptography — reviewed. No findings.** US-015 introduces no cryptographic code, no new key material, no new randomness source. Ids come from the existing `rbac.domain.IdGenerator` / `UuidV7IdGenerator` (`UuidCreator.getTimeOrderedEpoch()`, ADR-0005, `SecureRandom`-backed), verified clean under US-012 §0.3 and unchanged. Zero `Math.random` in the backend. `roles.id` and `role_permissions` ids are UUIDv7; `roles.id` **is** exposed in `RoleResponse`, but the values are tenant-scoped and already fully enumerable to any `role:read` holder via `GET /roles`, so the time-ordering property creates no new enumeration surface. **No cryptographic findings.**
- **PII — reviewed against the organisation's no-PII rule. No exposure introduced, and this story's posture is stricter than US-012's.** `RoleResponse{id, name, description, isSystemRole, createdAt}` and `PermissionResponse{id, name, description}` carry **no user identifier of any kind** — no actor, no creator, no email, no display name (contrast `RoleAssignmentResponse`, which carries `assignedBy` and needed the T-I5 redaction logic). `RoleAuditEvent` carries `tenantId`, `roleId`, `roleName`, `permissionId`, `permissionName`, `actorUserId`, `RequestContext` — UUIDs, labels, and the pre-existing `ip`/`userAgent`/`traceId` triple already governed by `RequestContext.of`. Every new log field in D12 is a UUID, a role name, a permission name, or a boolean. **One caveat, recorded as T-T9:** `roles.description` is tenant-controlled free text under a permissive allow-list. Nothing stops a tenant administrator from *typing* PII into it, and it is returned to every `role:read` holder in the tenant. That is a data-governance note for Epic 3, not a US-015 defect — but the field must never be added to a log or an audit payload, and that invariant is currently undocumented.

**Severity scale** (consistent with `docs/features/US-012/03b-threat-model.md` §0.3): **Blocker** / **Critical** / **High** / **Medium** / **Low**.

**Threat ID numbering** continues the epic's STRIDE-lettered sequence. US-009 allocated T-S1–S2, T-T1–T4, T-R1–R2, T-I1–I3, T-D1–D2, T-E1–E6; US-012 extended to T-S4, T-T7, T-R4, T-I5, T-D5, T-E13. **US-015 therefore begins at T-S5, T-T8, T-R5, T-I6, T-D6, T-E14.** US-011's parallel `T-01…T-13` sequence is disjoint and not extended.

---

## 1. Trust boundaries and data flow

```
[ Internet / hostile client — may hold a VALID token for a low-privilege tenant member,
  or a valid token whose privileges were revoked up to ~30 minutes ago (T-I8) ]
        |  POST/GET/DELETE /api/v1/roles[/{roleId}/permissions[/{permissionId}]]
        |  GET /api/v1/permissions                                    + Bearer JWT
        v
=== TB1: network -> app ==================================================
  CorrelationIdFilter (traceId; client-influenceable -> flows into audit metadata)
  -> LoginRateLimitFilter  ** login/refresh ONLY — NOT these paths (T-D6) **
  -> JwtAuthenticationFilter: RS256 verify; principal(sub) + details{tenantId,
     permissions, ...}; MDC userId/tenantId
        |  invalid/absent -> 401, chain short-circuits
        v
=== TB2: filter chain -> dispatcher ======================================
  SecurityConfig .anyRequest().authenticated()   <-- authN only, NOT permission
  @ConditionalOnProperty feature flag            <-- bean absent => 404 (fail-closed)
        |  ** flag-off removes the API but NOT the privileges already granted (T-E20) **
        v
=== TB3: dispatcher -> method-security proxy =============================
  @RequiresPermission("role:write" | "role:read")
     -> TenantAwarePermissionEvaluator.hasPermission
        == FLAT Set.contains on the JWT permissions[] claim. ZERO tenant comparison. ==
        == Cannot express AC7, AC8, AC9 or AC11. All four are service-layer logic. ==
        == Silently unenforced on a non-public/final handler (T-E19; D8 closes)      ==
        v
=== TB4: interfaces -> application (the Spring-Security-free boundary) ===
  RoleController / PermissionController
     -> RbacControllerSupport.parsePathUuid / resolveActor / requestContext
        ** shared fail-closed helper, now on 8 endpoints incl. US-012's (T-S6) **
     actor = RoleChangeActor(principal, details.tenantId)   <-- JWT-only provenance
     body  = CreateRoleRequest{name, description}           <-- NO tenantId, NO isSystemRole
        |  ArchUnit: no org.springframework.security type may cross into ..application..
        v
  RoleManagementService @Transactional
     -> [1] resolveRoleInTenant(roleId)      Q2  404 then 403   [AC8]
     -> [2] requireMutableRole(view)             409 RBAC_003   [AC7]  <== app-layer ONLY
     -> [3] findPermission(permissionId)     Q4  404            [OQ5a]
     -> [4] if dangerous:                                       [AC11]
              findRoleIdByName(tenant, TENANT_ADMIN)   Q3  empty -> 403 FAIL CLOSED
              hasActiveAdminAssignment(...)            Q11 ** FOR SHARE, locking (T-E14) **
     -> [5] hasPermission / attach / detach   Q8/Q10/Q9
        v
=== TB5: app -> MySQL as `nexus_app` (least-privilege) ===================
  permissions       SELECT
  roles             SELECT, INSERT              <-- no UPDATE/DELETE: AC7 rename backstop
  role_permissions  SELECT, INSERT, DELETE      <-- ** NO backstop for AC7 (T-E15) **
                                                    no soft-delete column, no trigger
  user_roles        SELECT, INSERT, UPDATE(revoked_at)   <-- Q11's FOR SHARE
  auth_events       INSERT, SELECT              <-- append-only
        v
=== TB6: post-commit, best-effort side effects (afterCommit) =============
  RbacAuditPort.recordRole* -> RbacAuthEventAdapter -> SecureEventService(REQUIRES_NEW)
                            -> AuthEventPort -> JpaAuthEventAdapter -> auth_events.metadata (JSON)
     ** tenant-controlled roleName crosses into a native JSON column here (T-T8) **
  INFO structured logs  ** tenant-controlled roleName crosses into logs here (T-I9) **
  nexus.rbac.dangerous_permission_granted counter   ** D15's compensating control (T-E16) **
  ^^ none may throw or block; a failure leaves a COMMITTED privilege change
     with no audit trail (T-R5)
        v
=== TB7: OUT-OF-BAND — the boundary this story does not own ==============
  US-012 POST/DELETE /api/v1/users/{userId}/roles   (live, flag-enabled, unmodified)
     assign(): AC8 gate matches role NAME only          -> T-E16 propagate side
     revoke(): NO admin gate at all, only last-admin    -> T-E17 admin stripping
  ** US-015 supplies the input that makes both reachable: a custom role carrying
     user:write / role:write / tenant:write. **
        v
=== TB8: token mint (login/refresh) — the staleness boundary =============
  RoleResolutionService.resolve() -> role-set fingerprint MISSES permission edits
  -> stale permission set baked into a NEW 900s JWT  => ~30 min effective window (T-I8)
```

**Components under analysis.**
**C1** `RoleController` / `PermissionController` + 6 DTOs ·
**C2** `RbacControllerSupport` (D4, shared with US-012) ·
**C3** `RoleManagementService` — the AC7/AC8/AC11 guard chain and the `attachPermission` critical path ·
**C4** `RoleManagementPort` / `JpaRoleManagementAdapter` + Q1–Q10 ·
**C5** `UserRoleAssignmentPort#hasActiveAdminAssignment` (Q11, reused verbatim) ·
**C6** `RoleAuditEvent` / `RbacAuditPort` / `RbacAuthEventAdapter` → `SecureEventService` → `auth_events` ·
**C7** the `nexus_app` DB privilege boundary on `roles` / `role_permissions` ·
**C8** architectural + operational controls (D8 ArchUnit, D9 health indicator, D11 flag, D12 observability) ·
**C9** `TenantAwarePermissionEvaluator` (trust dependency, unmodified) ·
**C10** `RoleAssignmentService.assign()` / `revoke()` (trust dependency, **Javadoc-only change**, and the other half of the R-3 chain) ·
**C11** `RoleResolutionService` / `PermissionCachePort` (trust dependency, unmodified — the AC10 staleness boundary).

---

## 2. Component-by-component STRIDE table

Legend: **✅** addressed by the design as written · **⚠️** partially addressed, gap identified · **❌** not addressed, change required · **n/a** not applicable.

### C1 — `RoleController` / `PermissionController` + DTOs

| | Threat | Verdict |
|---|---|---|
| **S** | Caller forges tenant or actor via request body | ✅ `CreateRoleRequest` models only `{name, description}`; `tenantId` and `isSystemRole` are **enforced by omission** (§8.1), which is stronger than validating them away. Actor is always `authentication.getPrincipal()`. **T-S5, Low** |
| **T** | Client-supplied `{roleId}` / `{permissionId}` / body `permissionId` used to target another tenant's resource | ✅ Tenant equality re-checked against a **fresh DB read** of `RoleView.tenantId`, never against request input (§8.6 ordering rule 1). **T-E18** |
| **R** | Handler acts without attributable identity | ✅ Actor is unwrapped in the controller and carried as `RoleChangeActor` into every audit payload |
| **I** | Over-disclosure in response DTOs | ✅ No PII on any path (§0.3). `isSystemRole` exposure assessed and accepted — **T-I7, Low** |
| **D** | Unthrottled writes / unbounded list responses | ❌ **T-D6, Medium.** No rate limiting, no per-tenant role cap, no pagination. `GET /roles` grows without bound from a single actor's writes |
| **E** | `@RequiresPermission` silently unenforced on a non-public / `final` handler or class | ⚠️ **T-E19, Medium→Low.** D8's two ArchUnit rules close the visibility half; self-invocation and mis-typed permission strings remain, covered only by per-endpoint negative-control tests. One implementation-time escape hatch needs closing (§7 RC-5) |

### C2 — `RbacControllerSupport` (D4)

| | Threat | Verdict |
|---|---|---|
| **S** | `resolveActor` fails **open** on a malformed principal or unparseable tenant | ✅ Three explicit fail-closed branches specified (§4.1, §8.5 rows 3–4): non-`String` principal, non-UUID principal, unparseable tenant → 403, never a 500 |
| **S** | **Blast-radius widening:** the D4 extraction puts one fail-closed helper behind 8 endpoints including US-012's shipped 3 | ⚠️ **T-S6, Medium.** The design frames the extraction purely as a benefit. It is also a single point of failure whose regression now fails open on twice the surface. Partially mitigated by the explicit abort condition (§4.1) and ➕`RbacControllerSupportTest` |
| **T** | `UUID`-typed `@PathVariable` → `MethodArgumentTypeMismatchException` → unhandled 500 | ✅ Design mandates `String` + `CANONICAL_UUID` pattern + parse (§4.1). Correct — `GlobalExceptionHandler` is a plain `@RestControllerAdvice` and has no handler for that exception |
| **R** / **I** / **D** | — | n/a |
| **E** | Divergent copies of a security helper, one of which fails open | ✅ This is precisely what D4 prevents; the abort condition prevents a *behaviour-changing* migration |

### C3 — `RoleManagementService` (the guard chain and `attachPermission`)

| | Threat | Verdict |
|---|---|---|
| **S** | Service trusts caller-asserted identity | ✅ Design invariant: only `RoleChangeActor`, `UUID`, `String`, `RequestContext` cross the boundary; ArchUnit `domain_and_application_must_not_depend_on_spring_security` + `rbac_application_methods_must_not_accept_principal_or_map` |
| **T** | A write path reaches `role_permissions` without passing AC7/AC8 | ⚠️ **T-E15.** Single shared `resolveRoleInTenant` + `requireMutableRole` guards (§4.2) — correct design, **but the only enforcement is code review + tests.** No DB backstop, no ArchUnit rule can express "every write calls both" |
| **T** | Accidental `Role` entity dirty-flush → production-only `UPDATE` rejection | ✅ **T-T10, Low.** Closed by construction — D1 returns `RoleView` projections, never a managed entity (§4.3) |
| **R** | Denied AC11 attempts leave no durable record | ⚠️ **T-R7, Medium.** WARN + counter only. Asymmetric with US-014 AC4, which made role-assignment denials a first-class durable audit row |
| **I** | 403-vs-404 existence oracle on `{roleId}` | ✅ **T-I6, Low.** Deliberate Gate 1 OQ4 trade; UUIDv7 ids, authenticated population, 403 branch is loud |
| **D** | AC11's `FOR SHARE` lock held while awaiting a second pooled connection | ✅ **T-D9, Low.** Closed by construction — audit is `REQUIRES_NEW` **after commit** (§2, §6.6). Lock scope is one user's rows (Q11 drives off `user_roles.user_id`) |
| **E** | **AC11 implemented as a non-locking read → TOCTOU** | ⚠️ **T-E14, High (as a design-intent-vs-implementation gap).** Design pins `Q3 → Q11` and forbids the shortcut in three places. Needs one more mechanical guard (§7 RC-4) |
| **E** | AC11 fails **open** in a tenant with no seeded `TENANT_ADMIN` role | ✅ **T-E18, Low.** Explicit fail-closed 403 branch (§8.5 row 7) + dedicated IT. Correct posture |
| **E** | Attaching a dangerous permission to the seeded **MEMBER** role escalates every user in the tenant | ❌ **T-E15, High threat / Medium residual.** AC7 blocks it and AC7 is app-layer-only. **MEMBER is named nowhere in any test scenario** |
| **E** | A minted dangerous role is then propagated via US-012 | ⚠️ **T-E16 / T-E17, High.** Out of this story's fix scope by decision D15; the compensating control needs strengthening |

### C4 — `RoleManagementPort` / `JpaRoleManagementAdapter`

| | Threat | Verdict |
|---|---|---|
| **S** / **R** | — | n/a |
| **T** | Constraint-violation mistranslation → 500 leaking MySQL text | ✅ Both translations specified (§4.5); all three exceptions carry **fixed static literals**, never `DataIntegrityViolationException.getMessage()` — correct, because `handleConflict` echoes `getMessage()` verbatim into the RFC 7807 body (`GlobalExceptionHandler.java:75`) |
| **T** | Injection via JPQL | ✅ All queries are parameterised Spring Data derived/`@Query` methods; no string concatenation anywhere in the Q1–Q10 shapes. **OWASP A03 — clean** |
| **I** | Constraint names / hex UUIDs leaked in a 409 body | ✅ Explicitly forbidden (§4.4), copying `DuplicateRoleAssignmentException`'s documented discipline |
| **D** | N+1 on `GET /roles/{id}/permissions` | ✅ Q7 pinned as a single projection join, bounded at 7 rows |
| **D** | Q3 de-sargonised by an `UPPER()` wrapper on AC11's write hot path | ✅ Explicitly forbidden (§5.2), with an optional `EXPLAIN`-asserting IT |
| **E** | Port returns a mutable `Role` a caller can load-mutate-save | ✅ Closed by construction (D1) |

### C5 — `UserRoleAssignmentPort#hasActiveAdminAssignment` (Q11)

| | Threat | Verdict |
|---|---|---|
| **S** | Admin status derived from a stale JWT claim | ✅ Port Javadoc forbids it (`UserRoleAssignmentPort.java:35-41`); design forbids it (§5.2); the ~30-min staleness window (T-I8) is exactly why |
| **T** | Concurrent revocation of the caller's admin assignment missed by a snapshot read | ⚠️ **T-E14.** `PESSIMISTIC_READ` / `FOR SHARE` is the mandated mechanism; the risk is entirely at implementation time |
| **D** | Lock escalation / table-wide lock | ✅ Drives off `user_roles.user_id` (implicit FK index) — one user's rows. Materially unlike US-012's F3 `tenant_id`-driven hazard |
| **E** | Privilege insufficient for `FOR SHARE` under the column-scoped grant | ✅ Empirically settled by `UserRolesPrivilegeIT` (executes `FOR UPDATE` as `nexus_app`); `FOR SHARE` is no stricter. US-012's R-4 is closed, not inherited |

### C6 — `RoleAuditEvent` / `RbacAuditPort` / `RbacAuthEventAdapter` → `auth_events`

| | Threat | Verdict |
|---|---|---|
| **S** | Forged actor in an audit row | ✅ `actorUserId` is always `actor.userId()` from the principal — never path-, body-, or target-derived (T-S3 discipline, inherited) |
| **T** | **JSON injection into the native `metadata` column via tenant-controlled `roleName`** | ⚠️ **T-T8, Medium→Low.** Two independent layers: Jackson-3 injected mapper (primary, sufficient alone) + D6's ASCII allow-list (defence in depth). Verified mechanism at `RbacAuthEventAdapter.java:152` |
| **T** | Audit-row mutation / deletion after the fact | ✅ `auth_events` is append-only at the privilege level (`GRANT INSERT, SELECT`, grants line 23). The 3 new types inherit this with no new mechanism |
| **R** | **Best-effort write loses the audit row for a committed privilege change** | ⚠️ **T-R5, Medium.** Inherited from US-012 T-R3. Mitigated by ERROR + `RBAC_AUDIT_WRITE_LOST` + `nexus.rbac.audit_write_failed{operation}` (verified `RbacAuthEventAdapter.java:112-127`) **plus** D12's three INFO success logs, which are the only trace surviving an audit-pipeline outage |
| **R** | **`auth_events.user_id` is NULL for all 3 new types → invisible to actor-indexed forensic queries** | ⚠️ **T-R6, Medium.** The design's RES-7 rates this as an unbuilt-tooling inconvenience. It is more than that: an operator running the *existing* per-user audit query gets a silent **false negative** |
| **R** | AC11 denials are not durably audited | ⚠️ **T-R7, Medium.** §6.5's reasoning is sound but inconsistent with US-014 AC4 |
| **I** | PII in metadata | ✅ None — UUIDs, `roleName`, `permissionName`, `traceId`, plus the pre-existing `ip`/`userAgent` (§0.3) |
| **D** | Priority-lane flooding (6 → 8 admitted types, capacity-200 drop-newest, ≥180 pager) | ✅ **T-D8, Low.** D7's exclusion of `ROLE_CREATED` — the only caller-uncapped, cheap type — is what makes "no threshold change" defensible rather than hopeful. Reasoning verified against the enum's own criterion (`AuthEventType.java:51-59`) |

### C7 — the `nexus_app` DB privilege boundary

| | Threat | Verdict |
|---|---|---|
| **T** | Role rename / `is_system_role` flip below the application layer | ✅ Structurally impossible — no `UPDATE` grant on `roles` (grants line 32). Genuine defence in depth |
| **T** | **`role_permissions` mutation below the application layer** | ❌ **T-E15.** `INSERT` and `DELETE` are granted, with no soft-delete column and no trigger. **AC7 is a pure application-layer control on both write endpoints** |
| **T** | Silent grant drift re-permitting `UPDATE ON roles` | ✅ **T-T11, Low.** D9 extends `RbacDbPrivilegeHealthIndicator` to `roles` and `role_permissions`, including the `COLUMN_PRIVILEGES` leg — which is the right call, since a column-scoped `GRANT UPDATE (description)` produces no `TABLE_PRIVILEGES` row |
| **D** | Health indicator flags a permanently-DOWN state on the intended `role_permissions` `DELETE` | ✅ Explicitly called out as a copy-paste trap (§9.5) |

### C8 — architectural and operational controls

| | Threat | Verdict |
|---|---|---|
| **E** | Silently unguarded privileged endpoint | ⚠️ **T-E19.** D8 closes visibility; needs an anti-drop clause (RC-5) |
| **D**/**E** | Kill switch does not actually roll back privilege | ❌ **T-E20, High finding / Medium residual.** D16 identifies it correctly but is confined to §12.3 prose with no severity and an incomplete remediation path |
| **I** | Operator acts on a wrong staleness figure during an incident | ❌ **T-I8, Medium** |

### C9 / C10 / C11 — trust dependencies

| | Threat | Verdict |
|---|---|---|
| **E** (C9) | Evaluator cannot express tenant, resource, or admin status | ✅ Understood and compensated entirely in C3. Inherited US-011 T-02 invariant unchanged |
| **E** (C10) | `assign()` name-match → propagate-side escalation | ⚠️ **T-E16, High.** D15 accepts; C1 needs strengthening |
| **E** (C10) | `revoke()` has **no** admin gate → admin stripping N→1 | ⚠️ **T-E17, High.** Under-stated in §10.1 |
| **I**/**E** (C11) | Revoked permission remains effective for ~30 min | ❌ **T-I8, Medium** |

---

## 3. Identified threats

Each entry: what an attacker achieves · existing mitigation in the design · required mitigation · residual.

---

### T-S5 — Tenant or system-role forgery via the create-role request body · **Low** · ✅ closed

**Attack.** A `role:write` holder posts `{"name":"X","tenantId":"<other-tenant>","isSystemRole":true}`, hoping for lenient binding, to mint a role in another tenant or an AC7-immune role in their own.

**Existing mitigation.** `CreateRoleRequest` models exactly two fields (§8.1). Neither `tenantId` nor `isSystemRole` exists on the record, so Jackson discards them and no validation rule can be forgotten. `tenantId` comes exclusively from `actor.tenantId()`; `is_system_role` is hard-coded `FALSE` in `RoleManagementPort#createRole` (§4.3). **Enforcement by omission, which the design correctly calls stronger than validating them away.**

**Required.** None. One test asserting that an unknown body field does not alter behaviour is worth having, but this is closed structurally.

**Residual: none.**

---

### T-S6 — Blast-radius widening from the D4 shared fail-closed helper · **Medium** · ⚠️ partially closed

**Attack.** Not a direct attack — a regression vector. `RbacControllerSupport.resolveActor` encodes three fail-closed security branches. D4 migrates US-012's `UserRoleController` onto it in the same change, so from day one **one implementation backs 8 endpoints across two stories**, including US-012's shipped, flag-enabled, production authorization surface. A future edit that turns any branch fail-open — e.g. returning a default tenant instead of throwing `MISSING_TENANT` — silently degrades both stories at once.

**Assessment.** D4's reasoning for extracting is correct (three divergent copies of a fail-closed helper is the worse failure mode, and divergence is invisible until one copy is the one that fails open). But the design presents the extraction as pure upside. It is a *trade*: fewer copies, larger blast radius per defect.

**Existing mitigation.** The explicit abort condition (§4.1: if migrating `UserRoleController` requires editing **any** existing assertion in `UserRoleControllerTest` or `RoleAssignmentSecurityIT`, stop and duplicate) is a genuinely good control — it makes US-012's shipped tests the unmodified regression gate. Plus ➕`RbacControllerSupportTest` covering the three branches.

**Required.** Two cheap additions for `/breakdown`, not a design change:
1. `RbacControllerSupportTest` must assert each fail-closed branch **throws**, not merely that it returns something falsy — a test asserting `assertThat(result).isNull()` would pass against a fail-open rewrite.
2. The class must be `final` with a private constructor and only `static` methods, so no subclass can override a branch.

**Residual: Low.** Accepted with the abort condition in place.

---

### T-T8 — JSON injection into `auth_events.metadata` via tenant-controlled `roleName` · **Medium → Low** · ✅ adequately layered

**Attack.** `roleName` becomes genuinely tenant-controlled free text **for the first time in this story** — US-012 could only echo the two seeded names. It flows: `CreateRoleRequest.name` → `roles.name` → `RoleAuditEvent.roleName` → `buildMetadataJson` → `auth_events.metadata`, a **native MySQL `JSON` column**. A name such as `X","grantedBy":"<victim-uuid>","x":"` would, under naive string concatenation, forge a metadata field. US-012's T-T5 established empirically that MySQL *accepts* valid injected JSON silently and that `JSON_EXTRACT` returns the forged value, keeping the **last** duplicate key — so a successful injection is a durable audit forgery, not a parse error.

**Existing mitigation — two independent layers, verified in code:**

1. **Primary: Jackson 3, injected.** `RbacAuthEventAdapter.java:17` imports `tools.jackson.databind.ObjectMapper`; line 54 holds it as an injected field; line 152 is `objectMapper.writeValueAsString(metadata)` over a `LinkedHashMap` (134-151). The value is never concatenated. Jackson escapes `"`, `\`, and control characters correctly. **This layer alone is sufficient** for structural JSON injection. The adapter's Javadoc (28-34) forbids the Jackson-2 type and hand-instantiation, and §6.3 carries that forward to the new overload.
2. **Defence in depth: D6's allow-list.** `^[A-Za-z0-9][A-Za-z0-9 ._-]*$` on `name` excludes `"`, `\`, `<`, `>`, `{`, `}`, all control characters, and all non-ASCII — including U+2028/U+2029. So the payload class never reaches the serialiser. §8.1 is explicit that this is *behind* Jackson, never *instead of* it. Correct framing.

**Is this sufficient? Yes — for `roleName`.** Two layers, the primary of which is a maintained library operating on a `Map` rather than a string template, and the secondary of which is a strict ASCII allow-list. `permissionName` rides the same path and is migration-seeded today; even if a future migration introduces an exotic permission name, Jackson alone covers it. `traceId` is client-influenceable via `CorrelationIdFilter` but is likewise Jackson-escaped (inherited US-012 T-T5, unchanged).

**Required.** The design already mandates the adversarial `RbacAuthEventAdapterTest` (quotes, backslashes, control characters, U+2028) and the null-`permissionId` omit-the-key case. One addition for `/breakdown`: the **DTO-layer** test corpus must use the *same* adversarial strings against `CreateRoleRequest`'s `@Pattern`, asserting 400. Otherwise layer 2 is asserted only by inspection.

**Residual: Low.** Accepted.

---

### T-T9 — `description` has a broader allow-list and an undocumented, untested "never logged" invariant · **Medium** · ❌ change required

**This is the exposure the design under-covers.** §8.1 gives `description` only `@Pattern("^[^\\p{Cntrl}]*$")` and justifies the weaker rule with: *"`description` is deliberately **not** audited and **not** logged, so this is its only exposure."* That sentence is doing a lot of load-bearing work, and it is neither documented as an invariant in code nor covered by any test.

**Three distinct problems.**

1. **The pattern is weaker than the design implies.** Java's `\p{Cntrl}` is `[\x00-\x1F\x7F]`. It does **not** include U+2028 LINE SEPARATOR or U+2029 PARAGRAPH SEPARATOR, and it does not include `"`, `\`, `<`, `>`, `&`. So `description` accepts a full XSS payload, a JSON-metacharacter payload, and the two Unicode line terminators — the exact corpus the design mandates as the adversarial test for `roleName`. If `description` ever reaches JSON or a log, it is materially less protected than `name`.
2. **"Not logged / not audited" is an invariant with no enforcement.** `RoleAuditEvent` correctly carries no `description` field (§6.1) — that part *is* structural, and it is the strongest thing about the current position. But nothing prevents a future `log.atInfo().addKeyValue("description", view.description())` in the D12 success-log block, or a `description` field being added to `RoleAuditEvent` by a later story that reasonably assumes it is safe. There is no comment, no ArchUnit rule, and no test that would fail.
3. **`description` is a stored, cross-user, tenant-controlled string rendered by a future UI.** It is returned in `RoleResponse` to every `role:read` holder in the tenant (§8.2 — it appears in the `GET /roles` list body). Epic 3's Tenant Admin UI is its consumer. Angular's default interpolation escapes, so this is not an automatic XSS — but a role-description field is exactly where a developer reaches for `[innerHTML]` to render formatting, and `DomSanitizer.bypassSecurityTrustHtml` is one line away. The design's §8.8 forward notes to Epic 3 mention `isSystemRole` and the `{"data":…}` envelope but say **nothing** about `description` being untrusted.

**Existing mitigation.** `RoleAuditEvent` omits `description` structurally. Spring's response serialisation JSON-encodes it correctly on the way out. That is the whole of it.

**Required mitigation (RC-3).** Three cheap changes to `03-design.md`:
1. Tighten the pattern to `^[^\p{Cntrl}  ]*$` — a one-character-class change that removes the two Unicode line terminators, which have no legitimate use in a role description and are the primitive for both log-line splitting and JS-string-literal breaking.
2. State the invariant as a **security constraint in prose and in the code**: "`description` must never be written to a log, a metric tag, or an audit payload. It is the only tenant-controlled field in this story not covered by an allow-list strong enough for those sinks." Put it in `CreateRoleRequest`'s and `RoleView`'s Javadoc, next to the field.
3. Add one line to §8.8's Epic 3 forward notes: "`description` is untrusted tenant-controlled text. Render it as text content only — never via `innerHTML` / `[innerHTML]` / `bypassSecurityTrust*`."

**Residual after mitigation: Low.**

---

### T-T10 — Accidental `Role` dirty-flush → production-only failure · **Low** · ✅ closed by construction

**Attack.** Not adversarial; an integrity/availability self-inflicted wound. `Role` maps `tenantId`, `name`, `description`, `systemRole` as plain updatable columns (§5.4, verified). `nexus_app` has no `UPDATE` on `roles` (grants line 32). Every `*IT` connects as the Testcontainers `test` superuser, so an accidental `setDescription` on a managed entity passes CI and fails **only in production** with `command denied`.

**Existing mitigation.** D1 removes the footgun entirely: `RoleManagementPort` returns `RoleView` projections or ids, never a managed entity (§4.3). Plus `RolePermissionsPrivilegeIT` connecting as `nexus_app` and asserting `UPDATE roles` is denied — the only test that can catch it. Plus the §9.3 alert whose first runbook check is the MySQL error log for `command denied` on `roles`.

**Required.** None. `RolePermissionsPrivilegeIT` must be non-negotiable in `/breakdown`.

**Residual: Low.**

---

### T-T11 — Grant drift below the application layer · **Low** · ✅ addressed by D9

**Attack.** An operator or a drifted provisioning script issues `GRANT UPDATE ON nexus.roles TO 'nexus_app'@'%'`. Role renames and `is_system_role` flips become executable, bypassing AC7 entirely — and today no health check, metric, or test notices, because `RbacDbPrivilegeHealthIndicator` inspects only `user_roles`.

**Existing mitigation.** D9 generalises the indicator to a per-table expectation set covering `user_roles`, `roles`, `role_permissions`, with a `COLUMN_PRIVILEGES` leg so a column-scoped `GRANT UPDATE (description)` cannot hide behind an empty `TABLE_PRIVILEGES` result. The design correctly flags that `role_permissions` must **not** be checked for `DELETE` (intentionally granted) or the indicator is permanently DOWN.

**Assessment.** This is the right call and is well-specified. Note the inherited limitation from US-012 §0.1: the indicator detects **over**-grant, not **under**-grant — a tightened grant that silently breaks Q11's `FOR SHARE` would not be flagged here (it is caught by `UserRolesPrivilegeIT` instead).

**Residual: Low.**

---

### T-R5 — Committed privilege change with no audit trail · **Medium** · ⚠️ inherited, adequately compensated

**Attack.** An attacker (or an outage) causes the post-commit audit write to fail. The `role_permissions` row is committed; the `auth_events` row is not. The privilege change is unattributable. Because the audit write happens in a `REQUIRES_NEW` transaction *after* the outer commit, `AuthEvent`'s assigned `@Id` means the actual `INSERT` and any DB-level rejection occur at that inner commit — after `recordEvent` has returned — so `JpaAuthEventAdapter`'s retry-buffer catch never fires for this mode (`RbacAuthEventAdapter.java:36-45`).

**Existing mitigation.** Verified at `RbacAuthEventAdapter.java:112-127`: catch-all → ERROR with `event=RBAC_AUDIT_WRITE_LOST` → `nexus.rbac.audit_write_failed{operation}`, gaining tags `createRole` / `grantPermission` / `revokePermission`. Paged at §9.3. **Plus** D12's three INFO structured success logs, which the design correctly refuses to treat as optional — they are the only durable trace surviving an audit-pipeline outage.

**Required.** None. This is US-012 T-R3 inherited unchanged, with the compensating controls already extended to the three new operations.

**Residual: Medium, accepted** (as in US-012).

---

### T-R6 — The three new event types are invisible to actor-indexed audit queries · **Medium** · ⚠️ under-rated by the design

**Attack.** An investigator asks "what did user X do?" and runs the established query against the indexed `auth_events.user_id`. Because §6.3 leaves `user_id` **NULL** for `ROLE_CREATED` / `ROLE_PERMISSION_GRANTED` / `ROLE_PERMISSION_REVOKED`, the three most privilege-consequential actions in this story **do not appear** — and the query returns success, not an error. A silent false negative during an incident is worse than a missing feature.

**Assessment of the design's choice.** The reasoning in §6.3 is sound: `auth_events.user_id` means *the subject* across the whole taxonomy, these events have no subject user, and setting it to the actor would silently redefine the column for 3 of 26 types. I agree with the decision. **I disagree with RES-7's severity framing**, which treats this purely as an unbuilt-tooling cost ("audit queries are forensic and low-frequency"). The cost is not that a query is unavailable — it is that the *existing* query is now **wrong**, silently.

**Required mitigation (RC-6, folded into the D16/runbook change).** No design change to the carrier. Instead:
1. The runbook must carry the correct forensic query verbatim, e.g. `SELECT * FROM auth_events WHERE event_type IN ('ROLE_CREATED','ROLE_PERMISSION_GRANTED','ROLE_PERMISSION_REVOKED') AND JSON_UNQUOTE(JSON_EXTRACT(metadata,'$.createdBy')) = ?` (and `$.grantedBy` / `$.revokedBy`), stated as **required in addition to** the `user_id` query.
2. RES-7 should be reworded from "not queryable by the indexed column" to "**invisible to the standard actor query; a separate JSON-path query is mandatory**".

**Residual after mitigation: Low.**

---

### T-R7 — AC11 denials leave no durable audit record · **Medium** · ⚠️ defensible, but inconsistent with US-014

**Attack.** An insider probes the self-escalation path repeatedly. Each attempt yields a WARN log and a `nexus.rbac.permission_denied` counter increment. **No `auth_events` row is written.** Log retention is not audit retention; the epic's compliance requirement is framed around the immutable, append-only `auth_events` table. After log rotation, the attempt is unprovable.

**The design's reasoning (§6.5) and my assessment.** §6.5 reads AC12's "a denied attempt does not write a success event" literally, as a negative constraint, and declines to add `recordRolePermissionDenied` because it would (a) exceed the AC, (b) add a fourth cheap-to-generate type with an unresolved lane question, and (c) hand a `role:write` holder an audit-row-writing loop. **(a) and (c) are correct.** The AC genuinely does not require it, and the AC11 denial branch *is* cheaply loopable (same role, same dangerous permission, repeated).

**But the asymmetry with US-014 is hard to justify.** US-014 AC4 made `ROLE_ASSIGNMENT_DENIED` a first-class durable audit row for exactly the same hazard profile — a 403 on an RBAC write path, equally loopable — and solved the flooding concern by putting it in the **STANDARD** lane rather than PRIORITY (`AuthEventType.java:48-49, 56-59`). So the platform's own established answer to "cheaply-generated denial rows" is *admit it, keep it out of the priority lane*, not *don't record it*. Under the current design, a denied **role assignment** by a `user:write` holder is durably audited, while a denied **dangerous-permission attach** by a `role:write` holder — a strictly higher-signal self-escalation indicator, and the single event D15's whole risk acceptance leans on — is not.

**Required.** This is an **AC-level question for PM, not a Gate 2 blocker.** I am not asking the architect to invent an AC. Two acceptable outcomes:
- **(preferred)** Add `recordRolePermissionDenied` scoped narrowly to the AC11 `NOT_TENANT_ADMIN` branch only (never the 409s, never the 404s, never cross-tenant), on the **STANDARD** lane, mirroring `ROLE_ASSIGNMENT_DENIED`'s treatment exactly. This is ~15 lines and reuses the existing carrier and adapter overload.
- **(acceptable)** Keep §6.5's position, but record the asymmetry explicitly in RES-x and state the retention requirement it implies: **the WARN `RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED` log must be retained at least as long as `auth_events`**, since it is the sole record. Right now nothing states that, and a 30-day log retention against a multi-year audit retention would be a silent compliance gap.

**Residual: Medium if the second option is taken and the retention requirement is written down; Low if the first.**

---

### T-I6 — 403-vs-404 existence oracle on `{roleId}` · **Low** · ✅ accepted

**Attack.** A caller distinguishes "role exists in another tenant" (403 `CROSS_TENANT_TARGET`) from "no such role anywhere" (404), enumerating the existence of other tenants' role ids.

**Existing mitigation / assessment.** Deliberate Gate 1 OQ4 trade for consistency with US-012's `resolveRoleInTenant`. `roles.id` is a UUIDv7 with no useful guessability; the population is authenticated tenant administrators; the leaked bit is bare existence, not name or tenant. The 403 branch is **loud** (WARN + `nexus.rbac.permission_denied{reason="CROSS_TENANT_TARGET"}`, verified `GlobalExceptionHandler.java:159-176`) with a ticket-level alert at §9.3; the 404 branch is DEBUG-only (verified line 67), which the design correctly characterises as "probe *misses* are not telemetry, only hits are".

**Required.** None.

**Residual: Low, accepted** (design RES-4).

---

### T-I7 — `isSystemRole` exposed in `RoleResponse` · **Low** · ✅ accepted

`isSystemRole` is tenant-scoped, already revealed by AC7's 409, and needed by any Epic 3 UI to grey out protected roles rather than discovering immutability through an error. D5's reasoning is correct. **No residual.**

---

### T-I8 — The corrected AC10 staleness window is still wrong: ~30 minutes, not 15 · **Medium** · ❌ change required

**This is my own finding, beyond the design's own correction.**

**The design's position (§5.5 / RES-2).** It correctly overturns an assumption inherited from US-012 — that a token refresh shortens the lag — and mandates the wording: *"Up to the 15-minute cache TTL. A token refresh does not shorten this window."* It requires that wording in the runbook, in Test Scenario 8, and in Epic 3 UI copy (§8.8).

**The mechanism, verified.** `RoleResolutionService.resolve()` (`RoleResolutionService.java:53-68`) re-reads **role names** live (line 57) and treats a cache hit as fresh whenever `sameRoles(cached, live)` matches (60-62). A `role_permissions` edit changes no role name, so the fingerprint matches and the **stale permission set is returned**. The source's own Javadoc says so at lines 27-29: *"A role's own permission set changing without any role (re-)assignment (a future US-015 concern) is not covered by this fingerprint."* `PermissionCachePort.java:10-21` documents the same. So far the design is right.

**Where it is still wrong.** `RoleResolutionService` is consulted **only at JWT-mint time** — its own Javadoc line 17-18: *"the single source consulted at JWT-mint time (login/refresh) and never per protected-API-request… enforcement in US-011 reads the JWT's own `permissions[]` claim, not this service."* Therefore a stale resolution is not merely served once; it is **baked into a freshly-minted access token** and enforced for that token's full lifetime. Verified configuration:

- `application.yml:143` — `permission-cache-ttl-seconds: ${NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS:900}` (15 min)
- `application.yml:185` — `access-token-ttl-seconds: 900` (15 min)

Worst-case timeline for a **revoked** permission:

| t | Event |
|---|---|
| 0 s | Admin detaches `user:write` from `CustomRole`. No cache eviction (ADR-0013 D4). |
| 899 s | Holder refreshes. Live role names unchanged ⇒ fingerprint matches ⇒ **stale** permission set returned ⇒ new JWT minted carrying `user:write`, valid 900 s. |
| 1799 s | That JWT finally expires. |

**Effective window ≈ 1800 s (30 minutes), not 900 s** — and the design's own §8.8 UI copy ("Changes may take up to 15 minutes… signing out and in does not speed this up") would tell a user a number that is short by half. Worse, "signing out and in does not speed this up" is not merely unhelpful: a refresh *at the wrong moment* **extends** the window, by re-minting a stale set into a fresh token.

**Why this matters as a security finding, not a documentation nit.** This is the Tampering/Elevation face of a cache: a *revoked* permission stays effective just as long as a *granted* one takes to appear. An operator responding to "we granted someone too much access, take it back now" will detach the permission, be told 15 minutes, and be wrong by 100% — with no signal. The correct emergency procedure is not detach-and-wait; it is **revoke the role assignment** via US-012's endpoint, which *does* change the role-set fingerprint and therefore *does* take effect on the next mint (`RoleResolutionService.java:60-62`, US-010 AC6). Nothing in the current design says this.

**Required mitigation (RC-2).** Correct §5.5, RES-2, §8.8 UI copy, Test Scenario 8, and the runbook to:

> *"Up to the permission-cache TTL **plus** one access-token lifetime — currently **up to ~30 minutes** (900 s + 900 s). A token refresh does **not** shorten this window and, if it occurs while the cache entry is still stale, **extends** it by re-minting the stale permission set into a fresh token. **To revoke effective access immediately, revoke the user's role assignment** (`DELETE /api/v1/users/{userId}/roles/{roleId}`, US-012) rather than detaching the permission from the role — an assignment change alters the role-set fingerprint and takes effect on the very next token mint."*

Test Scenario 8 must assert the composite window, not the cache TTL alone.

**Residual after mitigation: Low** (documentation-accurate, ADR-0013 D4 unchanged and not reopened).

---

### T-I9 — Log injection via tenant-controlled `roleName` · **Low** · ✅ closed

**Attack.** CRLF or U+2028 in `roleName` splits a log line, forging a second log entry.

**Existing mitigation.** Two layers: D6's allow-list excludes all control characters and all non-ASCII (so CR, LF, U+2028, U+2029 are unreachable), and §9.2's log-injection discipline mandates `roleName` be emitted **only** via SLF4J structured `addKeyValue("roleName", …)`, never string-concatenated into a message. The existing `LoggingStandardsTest` ArchUnit class enforces the structured-logging convention.

**Required.** None. Note the residual dependency: if D6's pattern is ever relaxed (a plausible Epic 3 request for non-ASCII role names), this control degrades to the structured-logging discipline alone. Worth one sentence in §8.1 so a future relaxation is recognised as a security change.

**Residual: Low.**

---

### T-D6 — Unthrottled role creation and unbounded list amplification · **Medium** · ❌ change required

**Attack.** A `role:write` holder loops `POST /api/v1/roles` with distinct names. There is no rate limit on this path (`LoginRateLimitFilter` covers login/refresh only — verified in `SecurityConfig`'s scope and stated in `02-impact.md` §6), no per-tenant role cap, and — per requirements R4 — **this story is precisely the mechanism that removes the previous ≤2-roles-per-tenant bound.** Each iteration is one cheap `INSERT`.

**Two amplifications the design treats separately but which compound.**

1. **Stored response amplification.** `GET /api/v1/roles` is unpaginated (D11) and returns every role in the tenant. So a *write-once* attack amplifies *every subsequent read by every user in the tenant*. At `name VARCHAR(64)` + `description VARCHAR(255)` + a UUID + a timestamp, ~350 bytes/role: 100 000 roles ≈ **35 MB per `GET /roles`**, served to any `role:read` holder, which includes every self-registered MEMBER-equivalent once Epic 3 ships role-management UI. That is a tenant-scoped DoS achievable by a single low-tier actor, and it persists — roles cannot be deleted (out of scope) and `nexus_app` holds **no `DELETE` on `roles`** (grants line 32), so **the application cannot clean it up**. Only a DBA can.
2. **Audit-lane pressure.** The design already identifies `ROLE_CREATED` as caller-uncapped and cheap, and correctly keeps it out of the PRIORITY lane (D7). That decision is right and I ratify it — but it mitigates lane flooding, not the two problems above.

**The design's position (D11 / RES-3).** *"The realistic ceiling is a tenant's hand-curated administrative role list — single to low-double digits."* That is an assumption about **benign** use. A threat model must assume hostile use. The design's own revisit trigger ("if any tenant exceeds ~200 roles") is a *detection* control with a weekly ad-hoc SQL panel behind it (§9.6) — days of latency against a loop that runs in seconds.

**Existing mitigation.** `ORDER BY name` determinism; the `{"data":…}` envelope keeping pagination additive; `ROLE_CREATED` excluded from PRIORITY; a weekly roles-per-tenant growth panel; the recorded revisit trigger.

**Required mitigation (RC-4).** A **per-tenant role cap** enforced in `RoleManagementService.createRole`, e.g. `nexus.rbac.max-roles-per-tenant: 500` (configurable, default well above D11's stated realistic ceiling of low-double-digits), returning `409` on breach. This is:
- **one `COUNT(*)` on an already-indexed predicate** (`uq_roles_tenant_name`'s `tenant_id` leftmost prefix — the same index Q1 uses), on the story's cheapest endpoint;
- the **only** control that bounds a growth this API cannot itself reverse (no `DELETE` grant on `roles`);
- simultaneously a ceiling on the `ROLE_CREATED` audit-row generator the design already worries about, and the thing that makes D11's "don't paginate" decision genuinely safe rather than conditionally safe.

I am **not** asking for pagination or rate limiting — I agree with D11 and with the epic's no-rate-limiting posture. A cap is the smaller, more targeted control.

**Residual after mitigation: Low.**

---

### T-D7 — Reserved-name squatting permanently disables AC11 and blocks tenant seeding · **Medium** · ❌ change required

**The design's §6.5 observation, and where I confirm and where I refute it.**

**Confirmed: fail-closed for escalation.** I traced both gates against the actual code. In a tenant with no seeded system roles — *the normal state for every Epic-3-created tenant today* (requirements Gap 9, ADR-0014 D5) — a `role:write` holder creates a **non-system** role literally named `TENANT_ADMIN` (D6's pattern permits underscores, so this passes validation). Then:

- **AC11 path:** `findRoleIdByName(tenantId, "TENANT_ADMIN")` (Q3) resolves the squatted role's id. `hasActiveAdminAssignment(actor.userId(), squattedRoleId, tenantId)` returns **false** — the creator holds no assignment of it. Dangerous-permission attachment is **blocked**. ✅
- **US-012 self-assignment path:** to grant themselves the squatted role they must call `assign()`. At `RoleAssignmentService.java:107`, `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())` is **true** (the squat is literally named `TENANT_ADMIN`), so lines 115-123 require `hasActiveAdminAssignment(actor.userId(), role.getId(), ...)` — false → **403 `NOT_TENANT_ADMIN`**. ✅

**So the design's escalation tracing is correct, and I confirm it. No privilege escalation exists.** Note the pleasing property that the squat is self-defeating: naming the role `TENANT_ADMIN` is exactly what brings US-012's AC8 name-match down on it.

**Refuted: "harmless".** §6.5 records this as fail-closed and therefore requiring no action. Fail-closed for *escalation*, yes. Harmless, no — it is a **permanent, application-unremediable denial of service on the tenant's entire administrative bootstrap**, executable with one unprivileged-ish `POST`:

1. **AC11 is permanently unsatisfiable in that tenant.** Q3 resolves the squatted, zero-permission role forever. `hasActiveAdminAssignment` against it can never be true for anyone, because nobody can ever be assigned it (blocked by AC8's name match, above). **No one in that tenant can ever attach `role:write` / `user:write` / `tenant:write` to any role, ever.** The tenant is permanently locked out of the story's entire dangerous-permission capability.
2. **Epic 3's per-tenant seeding is blocked.** When the seeding story tries to `INSERT` the genuine system `TENANT_ADMIN` role for that tenant, `uq_roles_tenant_name (tenant_id, name)` rejects it — the name is taken. Depending on how seeding handles that, it either fails the whole tenant provisioning or silently skips, leaving a tenant with a fake admin role.
3. **Nothing in the platform can undo it.** Role deletion is out of scope. `nexus_app` holds `SELECT, INSERT` on `roles` and **no `UPDATE` and no `DELETE`** (grants line 32) — so the role can be neither renamed nor removed by the application, now or by any future story, without a grant change. **Only a DBA with out-of-band credentials can fix it.**
4. **The same applies to `MEMBER`,** with the same reasoning.

The design's own reason for declining is: *"Reserving them in US-015 would be inventing an AC at Gate 2; this design does not do that."* I disagree with the characterisation. Rejecting a reserved value on a name field whose value is **already security-load-bearing in Q3** is not a new acceptance criterion — it is input validation on an existing AC1 field, exactly the same class of decision D6 already makes unilaterally when it picks an ASCII allow-list, a 64-char limit, and a no-trimming rule. Gate 1 did not specify those either.

**Required mitigation (RC-1).** In `RoleManagementService.createRole`, reject a `name` that case-insensitively equals any member of `RbacRoleNames` → `409` (reuse `DuplicateRoleNameException` / `RBAC_006`, whose message *"A role with this name already exists in this tenant"* is already accurate enough not to over-promise, or add a dedicated message). Concretely:

- Promote `RbacRoleNames` from a single `TENANT_ADMIN` constant to a `RESERVED` set `{TENANT_ADMIN, MEMBER}` with a `boolean isReserved(String)` helper, case-insensitive — mirroring `RbacDangerousPermissions`' shape and rationale exactly, and testable under the 0.90 `*.domain.*` gate.
- Two unit tests (`TENANT_ADMIN`, `tenant_admin`) and one IT in a tenant with no seeded roles.
- Cost: ~10 lines. Benefit: closes a permanent, DBA-only-remediable tenant DoS **and** de-risks Epic 3's seeding story before it is written.

Keep §6.5's existing recommendation that Epic 3's seeding story also reserve the names at tenant-creation time — but that story does not exist yet, and this one ships the endpoint that creates the hazard.

**Residual after mitigation: Low.** (A squat on some *other* name Epic 3 later wants to reserve remains possible; that is Epic 3's problem and is not security-relevant.)

---

### T-D8 — Priority-lane pressure (6 → 8 admitted types) · **Low** · ✅ accepted

D7's admission of `ROLE_PERMISSION_GRANTED` / `_REVOKED` and exclusion of `ROLE_CREATED` is reasoned against the enum's own stated criterion (verified `AuthEventType.java:51-59`), not by analogy. The exclusion of the one caller-uncapped, cheap type is what makes §9.4's "no threshold change" a safe answer rather than a hopeful one, and the added per-`event_type` lane-depth panel plus the 5%-of-weekly-volume review trigger convert the remaining assumption into a monitored one. **I ratify D7 and §9.4 as written.** RC-4's role cap further bounds the one residual concern.

**Residual: Low.**

---

### T-D9 — Lock held across a second pooled connection · **Low** · ✅ closed by construction

Q11's `FOR SHARE` is taken inside the write transaction; the audit write is `REQUIRES_NEW` on a second connection and fires **after commit** via `registerPostCommitSideEffects` (verified pattern at `RoleAssignmentService.java:393-405`). So no row lock is ever held while awaiting a second connection (§2). Lock scope is one user's rows. **No residual.**

---

### T-E14 — AC11 implemented as a non-locking read (the F1 trap) · **High** · ⚠️ well-pinned, one guard short

**The trap, verified as real.** Two mechanisms exist that look interchangeable and are not:

- **Mandated:** `UserRoleAssignmentPort#hasActiveAdminAssignment` — `UserRoleAssignmentPort.java:35-42` requires *"a fresh, locking (`PESSIMISTIC_READ`) DB read… never derived from a JWT claim… and **never a plain non-locking read, because a non-locking read is a REPEATABLE-READ snapshot that can miss a concurrent revocation**."*
- **Forbidden:** `RoleAssignmentService.callerHoldsActiveTenantAdmin` — `RoleAssignmentService.java:287-303`, whose own Javadoc says it reuses the M4 projection because the port *"exposes no 'find role by (tenant, name)' lookup"*, and that *"this is a plain (non-locking) read, which is appropriate here: unlike AC8's live-admin check, this only decides whether to redact one response field, not whether to authorize a mutation."*

**The distinction is real, it is documented in both places, and the design cites it accurately.**

**What an attacker achieves if `/breakdown` gets it wrong.** Under `REPEATABLE READ`, a plain read inside the write transaction sees the snapshot taken at transaction start. A caller whose `TENANT_ADMIN` assignment is revoked in a concurrent transaction that commits after that snapshot **still passes AC11** and attaches `role:write` / `user:write` / `tenant:write` to a role. The window is small but it is exactly the "revoked out-of-band, still acting" scenario AC11 exists to defeat — and it is the **first move** in the R-3 chain (T-E16), so the TOCTOU winner mints the dangerous role that opens the propagate side permanently.

**Worse, and sharper than the design states:** the realistic failure is not calling the private helper (it is `private`, in a different service — not callable). It is an implementer **copying its shape**: `findActiveAssignmentViews(actor.userId(), tenantId).stream().anyMatch(a -> TENANT_ADMIN.equalsIgnoreCase(a.roleName()))`. That is doubly wrong — non-locking **and** it bypasses Q3 entirely, converting AC11 from an *assignment* check into a *role-name* check, which is precisely the weakness AC11 was created to avoid. It would pass every functional test, satisfy AC11's letter, and produce no failing build. *(For completeness: even that broken form would not make the T-D7 squat exploitable, because the squatted role cannot be assigned to anyone — but it would still lose the TOCTOU property and reintroduce name-based reasoning into the story's most security-critical gate.)*

**Existing mitigation — strong.** §5.2 pins AC11 as `Q3 → Q11` inside the write transaction, in bold, three times (§0 D-summary, §3.1 sequence note, §5.2 callout). `/breakdown` must carry `RoleManagementAdminGateIT` including **a concurrent admin-revocation case**, explicitly described as *"the only test that distinguishes the mandated locking read from the forbidden non-locking shortcut."* That test is the right control and must not be descoped.

**Required mitigation (RC-5, part 1).** One mechanical guard the design does not have. Add to `/breakdown` an assertion — an ArchUnit rule or a targeted unit test on the collaborator set — that **`RoleManagementService` never calls `UserRoleAssignmentPort#findActiveAssignmentViews`**. It has no legitimate reason to (it has no target user, and §4.2 injects `UserRoleAssignmentPort` for `hasActiveAdminAssignment` *only*, per its own inline comment). This converts "don't copy that shape" from a prose instruction into a build failure, which is exactly what D8 does for the visibility trap. Cost: one rule.

**Residual after mitigation: Low.** Without it: **Medium**, resting entirely on one IT surviving review.

---

### T-E15 — AC7 is a pure application-layer control on `role_permissions`, with MEMBER-role amplification · **High threat / Medium residual** · ❌ change required

**Verified exposure.** `GRANT SELECT, INSERT, DELETE ON nexus.role_permissions` (grants line 33). The table has no soft-delete column and **no trigger** — V5's only trigger is `trg_user_roles_no_delete` on `user_roles` (V5:96). Contrast `roles`, which has no `UPDATE`/`DELETE` grant at all and therefore *does* have a DB backstop against renames and `is_system_role` flips. **So for the two write endpoints that AC7 actually governs, there is no backstop whatsoever below the application layer.** The design states this plainly (§5.3 item 2, RES-5) — credit where due.

**The amplification the design does not state.** The seeded system roles are `TENANT_ADMIN` (all 7 permissions) and `MEMBER` (`user:read` only) — `V5:119-135`. `RoleAssignmentService`'s own Javadoc line 268 confirms **"every self-registered `MEMBER`"** holds that role. Therefore:

> **A single successful `POST /api/v1/roles/{MEMBER_role_id}/permissions` with `permissionId = role:write` grants `role:write` to every self-registered user in the tenant, retroactively and prospectively.**

That is the highest-impact single request in this entire story — higher than anything on the `TENANT_ADMIN` path, because escalating `TENANT_ADMIN` requires already being able to reach it, whereas escalating `MEMBER` escalates *the whole tenant at once*. And by the pinned check ordering (§8.6), **AC7 fires before AC11** — so for a caller who *is* a legitimate admin, AC7 is the **sole** control standing between a fat-fingered or malicious admin and tenant-wide `role:write`. There is no second gate and no DB backstop.

**Existing mitigations (all app-layer or process):**
- Single shared `requireMutableRole(view)` guard called by both write endpoints (§4.2), not per-controller copies — the correct structure, and story risk R9's own stated mitigation.
- D8's two ArchUnit rules, closing the silently-unenforced-`@RequiresPermission` vector (T-E19).
- Per-endpoint negative-control 403 tests.
- D12's `RBAC_SYSTEM_ROLE_MUTATION_BLOCKED` WARN + `nexus.domain.conflict{code="RBAC_003"}` counter with a ">3 in 15m" ticket alert (§9.3) — genuinely valuable, since `handleConflict` logs at DEBUG (verified `GlobalExceptionHandler.java:73`) and AC7 attempts would otherwise be invisible in production.
- D9's drift detection on `roles`.

**Are they sufficient?** *Almost.* The structural mitigation (one shared guard, no bypass path) is the right design and I do not think a DB trigger should block Gate 2. But the test coverage has a specific, cheap hole, and the alert threshold is mis-set for the highest-impact case:

**Required mitigation (RC-5, part 2) — two items:**

1. **Name `MEMBER` explicitly in the negative-control test set.** Story Test Scenario 5 is *"Attempt to modify `TENANT_ADMIN`'s permissions"*. `MEMBER` appears in **no** test scenario, in **no** ACs, and **nowhere** in `03-design.md`'s §11.2 test plan. `RolePermissionSecurityIT` must carry, as named cases: *attach `role:write` to the seeded `MEMBER` role → 409 `RBAC_003`* and *detach `user:read` from the seeded `MEMBER` role → 409 `RBAC_003`*. The second matters independently: detaching `user:read` from `MEMBER` would strip read access from every member of the tenant — an availability event AC7 also prevents and which nothing currently tests.
2. **Lower the AC7 alert threshold to `> 0` for system-role *write* attempts.** §9.3 sets `increase(nexus_domain_conflict_total{code="RBAC_003"}[15m]) > 3`. Given that the only way to generate `RBAC_003` is to attempt a write against a system role, and given the MEMBER blast radius, **the first attempt is the signal** — there is no benign client that does this repeatedly by accident, and the D12 WARN already carries `roleId`/`roleName` for triage. `> 0` at ticket severity.

**Recommended, not required (record the decision either way).** A `BEFORE INSERT` / `BEFORE DELETE` trigger on `role_permissions` rejecting any row whose `role_id` resolves to `is_system_role = TRUE` would give AC7 a genuine DB backstop, using a mechanism already present in the same migration (`trg_user_roles_no_delete`, V5:96). It costs a `V6__` migration, which conflicts with the design's headline "no migration" property, and it would need care not to block the seeding path. **I am not making this a Gate 2 condition** — the single-shared-guard structure plus D8 plus the named MEMBER tests is a defensible posture. But the design should record *that the option was considered and declined, and why*, rather than leaving RES-5 reading as though no backstop were possible.

**Residual after RC-5: Medium, accepted** — application-layer-only, with structural single-guard enforcement, mechanical `@RequiresPermission` verification, named negative controls on both system roles, and first-attempt alerting.

---

### T-E16 — Propagate-side escalation: a dangerous custom role is granted by any `user:write` holder (R-3 / D15) · **High** · ⚠️ acceptance agreed, compensating control insufficient

**The chain, verified end to end in code.**

| Step | Actor | Mechanism | Gate | Verified |
|---|---|---|---|---|
| 1 | any `role:write` holder | `POST /roles` | none (correct — an empty role confers nothing) | §8.1 |
| 2 | **must be an active `TENANT_ADMIN`** | `POST /roles/{id}/permissions` with `user:write` | **AC11 — closed by this story** | §5.2 |
| 3 | any `user:write` holder | `POST /users/{id}/roles` granting `CustomRole` **to themselves or anyone** | **AC8 matches role *name* only → never fires** | `RoleAssignmentService.java:107` |
| 4 | the new `CustomRole` holder | full `user:write` authority, unbounded further self-grants of any non-`TENANT_ADMIN`-named role | none | — |

Nothing restricts `targetUserId == actor.userId()` in `assign()` (verified — lines 93-141 contain no such check, and the M-3 Javadoc at 83-84 says so explicitly).

**Reachability.** Unreachable today: only `TENANT_ADMIN` carries `user:write` (`V5:130-135`, TENANT_ADMIN × all 7). Reachable **the first time US-015 is used for its intended purpose**, because step 2 is a legitimate, AC11-permitted, Epic-3-required action.

**My independent assessment of D15 is in §4.** Summary: **I agree with accepting (option a). I do not accept C1 as specified.**

**Existing mitigation.** AC11 closes the mint side. `ROLE_PERMISSION_GRANTED` goes to the PRIORITY audit lane (D7). `nexus.rbac.dangerous_permission_granted{permission}` counter + a review-within-one-business-day ticket alert (§9.2/§9.3). D13's Javadoc amendment prevents the gap being recorded as discharged. C3's successor story.

**Required mitigation (RC-1 in §4 / RC-7 below).** An **exploitation-side** detection signal. See §4.3.

**Residual: High before RC-7, Medium after** — see §5 RES-1 for the full entry with owner and review date.

---

### T-E17 — Revoke-side admin stripping (T-E9 symmetric hole) · **High** · ⚠️ in the same residual, under-stated

**Verified.** `RoleAssignmentService.revoke()` (lines 190-260) has **no admin gate of any kind**. Its Javadoc (180-188) states this: *"there is **no** symmetric check requiring the caller to already be an active `TENANT_ADMIN` to revoke one, unlike `assign()`'s AC8 check for granting one."* Its only guard is at 208-225 and is the **actor-agnostic last-admin count check**: `lockedActiveAdminIds.size() <= 1 && lockedActiveAdminIds.contains(ref.id())`.

**So the design's claim that revoke()'s hole is "symmetric" is correct, but its consequence is materially different from assign()'s and is not spelled out.** Once step 3 of T-E16 gives a non-admin `user:write`, that actor can:

- **Revoke `TENANT_ADMIN` from every genuine administrator except one.** The last-admin guard blocks only the *final* active admin assignment, so a tenant with N admins can be stripped to **1**.
- Do so while holding admin-equivalent authority themselves via `CustomRole`.

Net effect: **a single compromised `CustomRole` holder can reduce a tenant to one genuine administrator while wielding equivalent power** — a tenant-takeover posture, not merely a privilege-escalation one. The last-admin guard prevents total lockout (and fires a `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN at 216-222, which *is* a useful late signal), but it was designed as an anti-footgun control, not an anti-adversary control.

**Why this belongs here.** §10.1 mentions the revoke hole in one clause and §10.2 correctly argues that fixing only `assign()` "would leave an admin-strippable-by-non-admin hole and would be worse than fixing neither" — that reasoning is right and is one of the stronger arguments for D15's option (a). But the residual-risk entry (RES-1) and D13's Javadoc amendment describe the risk as escalation. **An operator reading RES-1 will not learn that the same chain enables admin stripping.**

**Required.** Fold into RES-1 (see §5) and into the D13 Javadoc text: state explicitly that the propagate side has **two** consequences — self-escalation via `assign()` **and** administrator stripping (N→1) via `revoke()` — and that the successor story must gate both. The design's §10.2 item 1 already commits the successor story to both methods; RES-1's *description* must match.

**Residual: covered by RES-1.**

---

### T-E18 — Cross-tenant role access, and AC11's no-seeded-admin branch · **Low** · ✅ closed

**Cross-tenant (AC8).** Uniform across all three role-scoped verbs. Caller tenant from the JWT only; target tenant read **fresh from the DB** (`RoleView.tenantId`), never from request input. Ordering pinned: tenant resolution (404 → 403) always first (§8.6 rule 1), which also avoids leaking system-role status of an inaccessible role through the response code. `GET /roles` satisfies isolation by result-filtering. Mirrors the shipped `resolveRoleInTenant` precedent (`RoleAssignmentService.java:331-341`).

**Fail-closed on Q3 empty (R-10).** In any tenant with no seeded `TENANT_ADMIN` role — every Epic-3-created tenant today — Q3 returns empty. §8.5 row 7 pins this to **403 `NOT_TENANT_ADMIN`**, never a fall-through to allow, with a dedicated IT. **This is the single most important one-line decision in the design**: the alternative would be a silent AC11 bypass for every future tenant. Correct.

**Required.** None.

**Residual: Low.** (The accepted consequence — such tenants cannot attach dangerous permissions at all — is RES-6, correctly rated; it is an adoption constraint, not a security risk, and Epic 3's seeding story is the real fix.)

---

### T-E19 — `@RequiresPermission` silently unenforced · **Medium → Low** · ⚠️ one escape hatch to close

**Attack.** A handler declared non-`public` or `final`, or on a `final` class, cannot be proxied by Spring AOP/CGLIB. `@RequiresPermission` is then **silently never enforced** — no error, no log, no failing test (`SECURITY.md` §3.1). US-015 quadruples this context's annotated-handler count from 2 to 8, on the platform's role-definition surface, where AC7 has no DB backstop.

**Existing mitigation.** D8 adds two ArchUnit rules (§7.2): annotated methods must be `public` and non-`final`; declaring classes must be non-`final`. The class-level rule is the design's own addition over the impact analysis's single-rule recommendation, and it is correct — CGLIB cannot subclass a `final` class. The rules retroactively cover `UserRoleController`. The design correctly documents the limits: ArchUnit catches neither **self-invocation** (an annotated method called from within the same bean bypasses the proxy) nor a **mis-typed permission string**; per-endpoint negative-control 403 tests plus a positive control remain mandatory.

**The escape hatch.** §7.2's closing note tells `/breakdown` to verify the fluent method names against the pinned ArchUnit version and *"if a formulation is unavailable, split into two separate rules rather than dropping the check."* Good intent, but it leaves the outcome to implementer judgment under schedule pressure, and a dropped rule produces **no signal at all** — the same silent-failure property the rule exists to eliminate.

**Required mitigation (RC-5, part 3).** Make the outcome non-optional: *"If neither `notHaveModifier(FINAL)` nor `containAnyMethodsThat(...)` is available in the pinned ArchUnit version, the check must be implemented as a plain reflection-based JUnit test over `@RequiresPermission`-annotated methods discovered by classpath scan. It must not be dropped, weakened, or deferred; a US-015 without a mechanical `@RequiresPermission` visibility check does not meet Gate 2."*

**Residual after mitigation: Low.**

---

### T-E20 — Flag-off is not a privilege rollback (D16) · **High finding / Medium residual** · ❌ change required

**The finding is the design's own, and it is a good catch.** US-012's rollback was trivially safe because its writes were reversible through its own API. US-015 is different: `roles` and `role_permissions` rows written while the feature is live **remain live domain data**. `RoleResolutionService` reads them at every token mint regardless of whether US-015's controllers are registered (verified: `RoleResolutionService.java:57, 64` call `UserRoleQueryPort` directly, with no dependency on US-015 code or the flag). So a custom role carrying `user:write` **keeps conferring `user:write`** after the kill switch is flipped — and, with the endpoints gone, **there is no longer any way to detach the permission or manage the role.** The design correctly states that *"flip the flag and you're back to the pre-US-015 privilege state" is **false** and must not appear in the runbook.*

**Two problems with how it is recorded.**

1. **It is not in the residual-risk table.** Verified: §12.5 contains RES-1…RES-8 and D16 appears **only** as prose in §12.3, with **no severity rating**. Every other accepted residual in this story has a row and a rating. An operator or an auditor reading §12.5 as the risk register — which is what a residual-risk table is for — will not see the one finding that says the kill switch does not do what a kill switch is assumed to do. It must be RES-9 with a severity.
2. **The remediation path has a missing step.** §12.3 step 3 says to *"revoke the assignments of the offending role via US-012's still-live `DELETE /api/v1/users/{userId}/roles/{roleId}` — this is the fastest containment and needs no DB access."* That is the right instruction and the reason this is a manageable rather than a blocking rollback. **But it presupposes knowing *which users* hold the offending role, and there is no reverse lookup.** US-012 exposes `GET /api/v1/users/{userId}/roles` — per-**user**, not per-**role**. There is no "who holds role X" endpoint anywhere in the platform. During an incident, an operator following step 3 literally would have to iterate every user in the tenant, or reconstruct holders from `ROLE_ASSIGNED` audit rows via an unindexed JSON-path query — which, per T-R6, is also not written down anywhere.

**Required mitigation (RC-6).** Three changes:
1. **Add D16 to §12.5 as RES-9** with severity **Medium** (High impact, low likelihood, well-understood remediation): *"Flag-off removes the API but not the privileges granted through it. Custom roles keep conferring their permissions; with the endpoints gone, only assignment revocation (US-012) or DBA-level DML can neutralise them."* Compensating controls: the `ROLE_PERMISSION_GRANTED` PRIORITY-lane audit trail, the `dangerous_permission_granted` alert history, and the documented remediation path.
2. **Add the reverse-lookup step to the runbook**, before step 3, as a DBA/read-only query: `SELECT BIN_TO_UUID(user_id) FROM user_roles WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL;` — with an explicit note that **no API provides this** and that it is therefore a DB-read step even though step 3 itself is not.
3. **State the ordering constraint:** revoke assignments (step 3) **before** flipping the flag off where possible, because flipping first removes the ability to inspect the role's permissions via `GET /roles/{id}/permissions`, making it harder to know which roles are offending. The current step order (flag off first) optimises for stopping the bleeding and is defensible — but the trade should be written down, not discovered.

**Also worth one line:** with the flag off, `GET /roles` and `GET /roles/{id}/permissions` are gone too, so an operator loses read access to the very data they need. Steps 2 and 3 depend on audit history and DB reads. That is acceptable but must not be a surprise.

**Residual after mitigation: Medium, accepted** (as RES-9).

---

## 4. Independent assessment of D15 / R-3 (design condition **C2**)

The design (§10.2, §13 item 15) explicitly invites the security reviewer to overturn this decision and states that if I do, §0's conditional ADR trigger fires and the story returns to Gate 1. I have assessed it on its merits rather than deferring to it.

### 4.1 Verdict: **I agree with the decision to accept (option a). I do not accept condition C1 as specified.**

### 4.2 Where I agree, and why

The design's four arguments for not expanding scope hold up under adversarial reading:

1. **The fix is genuinely not small or contained.** The minimum honest version touches **both** `assign()` **and** `revoke()`. §10.2's observation that fixing only `assign()` "would leave an admin-strippable-by-non-admin hole and would be worse than fixing neither" is correct and is confirmed by the code — `revoke()` (`RoleAssignmentService.java:190-260`) has no admin gate at all, only the last-admin count guard. A half-fix would create a false sense of closure over T-E17.
2. **It changes the authorization contract of a shipped, flag-enabled API.** Roles assignable today by any `user:write` holder would become admin-only. That is a breaking behavioural change to US-012's live endpoint.
3. **The open questions are real and are not Gate-2-answerable.** What happens to pre-existing assignments of dangerous roles? Is the privilege test evaluated at assign time or at grant time? How does a revoke-side admin gate interact with AC5's last-admin lockout guard — an administrator who cannot revoke a dangerous role from a departing employee is a *new* operational failure mode, and a plausible one. I could not answer any of these from the code, and neither should a Gate 2 design review.
4. **Reachability requires a legitimate admin action first.** Step 2 of the chain is AC11-gated. The chain does not open by itself.

Two further points in the design's favour that it does not make for itself: **AC11 genuinely does close the harder half.** Without it, any `role:write` holder could mint the dangerous role unilaterally — reachability would be immediate and unconditional. And **D13's refusal to delete the M-3 Javadoc** is the right instinct; recording a gap as discharged is worse than recording it as open.

### 4.3 Where I disagree: C1 detects the wrong event

C1 ships `nexus.rbac.dangerous_permission_granted{permission}` with a review-within-one-business-day ticket alert. §10.2 item 4 argues: *"The window between 'reachable' and 'noticed' is minutes, not months."*

**That sentence is true and it is not the relevant window.**

Map the counter onto the chain (T-E16's table):

| Chain step | What it is | Does C1 fire? |
|---|---|---|
| 2 — admin attaches `user:write` to `CustomRole` | **Legitimate.** AC11-permitted, Epic-3-required, expected to happen routinely | ✅ **Yes** |
| 3 — non-admin self-grants `CustomRole` via US-012 | **The attack.** The moment escalation actually occurs | ❌ **No** |
| 4 — the new holder strips administrators (T-E17) | **The takeover** | ❌ **No** |

Step 3 emits a `ROLE_ASSIGNED` audit row **indistinguishable from every routine role assignment in the platform**, and it triggers no alert of any kind. So the compensating control alerts on a legitimate action and is silent on the illegitimate one. What C1 actually provides is a **risk-register update signal** — "this tenant has now entered the exposed state" — which is genuinely useful and worth shipping, but it is not detection of the threat. The design's own §9.3 wording gives it away: the action is *"Confirm intent with the tenant; note the role id in the risk register."* That is asset management, not intrusion detection.

Consequence: after the first legitimate dangerous grant in a tenant, that tenant sits in the exposed state indefinitely with **zero** exploitation-side monitoring. The window between exploited and noticed is unbounded, and the design's headline reassurance does not address it.

### 4.4 Required strengthening of C1 (RC-7)

C1 must ship an **exploitation-side** signal alongside the precondition-side one. Two options; I recommend the first because it is nearly free.

**Option A — self-assignment detection (recommended).** Nothing in the platform currently flags a role assignment where the actor and the target are the same user. `RbacAuditEvent` already carries both `targetUserId` and `actorUserId` (verified: the record's shape, and `RbacAuthEventAdapter.java:105, 149-151` writes `user_id` = target and `<actorFieldName>` = actor). Self-assignment is the **highest-signal shape** of the T-E16 attack — step 3's whole point is "including themselves" — and it is close to nonexistent in benign use (an admin assigning themselves a role is rare and, when it happens, worth a look).

Implementation, in `RoleAssignmentService.assign()`'s existing post-commit block (lines 151-171) — no new query, no new port method, no schema change:
```
if (targetUserId.equals(actor.userId())) → counter nexus.rbac.self_role_assignment{} + WARN
```
Alert: `increase(nexus_rbac_self_role_assignment_total[15m]) > 0` → ticket, escalating to **page** in any tenant where `nexus_rbac_dangerous_permission_granted_total > 0` — i.e. precisely the tenants C1 has already flagged as exposed. **This composes the two signals into actual detection of the chain**, which is what a compensating control for T-E16 has to do.

Caveat to record honestly: this is a one-line behavioural addition inside `RoleAssignmentService`, and §12/D13 currently commit to *"Javadoc only, no behaviour, no signature"* for that class. Adding an observability counter in an existing post-commit block is not an authorization-contract change and does not require a US-012 Gate 1 reopen — but the design must say so explicitly, so `/breakdown` does not treat the Javadoc-only constraint as forbidding it.

**Option B — dangerous-role assignment detection.** At assign time, test whether the granted role carries any dangerous permission (the same Q7-shaped query the successor story needs anyway) and alert if so. Higher fidelity; more code; and it builds half of the successor story's machinery in this one, which cuts against §10.2's own reasoning. **Not recommended for this story**, but worth naming in C3 as the successor's natural first increment.

**If neither is adopted, I would move to reject the D15 acceptance** — because the acceptance rests entirely on the claim that the risk is *detected*, and without an exploitation-side signal that claim does not hold.

### 4.5 The owner and review date C2 requires

The design's C2 requires *"a threat-model entry with a named owner and an expiry/review date."* **RESOLVED at Gate 2 sign-off:** the accountable-owner placeholder below has been substituted with a named individual, per C2.

> **Amended 2026-09-13 by US-016 (T-021, per RC-8.2 — do not flip this register wholesale to "closed"; see `docs/features/US-016/03-design.md` §12.2 item 6, §12.3 RES-1(a)/(b), ADR-0017).** The successor story named by C3 below has shipped as US-016. Its outcome, precisely: **T-E17 is closed** (revoke() now carries the same privilege gate as assign(); no surviving variant of admin-stripping was constructible). **T-E16 is closed for the direct propagate side only** — a non-admin `user:write` holder can no longer grant themselves (or anyone) a role that is *already* dangerous at assign time. **The scope-of-acceptance row below is therefore only partially discharged**: the row's `revoke()`/administrator-stripping half is fully closed; its `assign()`/self-escalation half is closed for existing-dangerous roles but **not** for a role made dangerous *after* assignment (attach-after-assign) — that residual is real, is not touched by US-016's gate (the gate evaluates at assign/revoke time, not at attach time), and is carried forward, **not** deleted, as **US-016 RES-1(b) / T-E21**, in `docs/features/US-016/03-design.md` §12.3. Every row below is left as originally written; only this note and the two follow-up notes on the Hard-expiry and Closure-condition rows are added, per this file's own precedent of annotating entries in place (see RES-3/RES-9's "(after RC-...)" markers) rather than rewriting history.

| Field | Value |
|---|---|
| **Risk** | RES-1 / T-E16 + T-E17 — propagate-side escalation and administrator stripping via US-012 `assign()` / `revoke()` |
| **Owner (accountable)** | **Md Nisar Ahmed (nisar.a@entomo.co), RBAC bounded-context tech lead.** |
| **Owner (responsible — remediation)** | Principal Architect (successor-story design) |
| **Owner (responsible — detection)** | Application Security Engineer (C1 + RC-7 signals, alert routing, runbook procedure) |
| **Accepted on** | 2026-08-27 (Gate 2, US-015) |
| **Scope of acceptance** | Both `RoleAssignmentService.assign()` (self-escalation) **and** `revoke()` (administrator stripping, N→1). Explicitly **not** the mint side, which AC11 closes. **[US-016, 2026-09-13] `revoke()`/stripping (T-E17): closed. `assign()`/self-escalation (T-E16): closed for the direct propagate path; the attach-after-assign path is not covered by this gate and survives as US-016 RES-1(b)/T-E21.** |
| **Compensating controls** | C1 `nexus.rbac.dangerous_permission_granted{permission}` + ticket alert (precondition-side) **and RC-7's exploitation-side signal** (self-assignment counter, escalating to page in exposed tenants). `ROLE_PERMISSION_GRANTED` in the PRIORITY audit lane. D13's amended Javadoc on both methods |
| **Scheduled review** | **2026-11-27** (90 days). **[US-016] This date is not reset by the partial closure — it transfers unchanged to the surviving component, RES-1(b), per `docs/features/US-016/03-design.md` §12.3.** |
| **Early-trigger review** | **Immediately, and the successor story becomes P0**, on the first firing of `nexus.rbac.dangerous_permission_granted` in any environment — per C3. Reviewed by the accountable owner within **1 business day**. **Discharged as a trigger by US-016 shipping; the underlying alert continues to run against the surviving RES-1(b) path.** |
| **Hard expiry** | **Epic 3 kickoff.** This acceptance must **not** be silently inherited by Epic 3. Epic 3's Tenant Admin UI is the feature that makes dangerous grants *routine* rather than exceptional, which invalidates the "requires a rare deliberate admin action" premise the acceptance rests on. If the successor story has not shipped by Epic 3 kickoff, the risk must be **re-accepted explicitly by the accountable owner**, in writing, with the then-current alert history attached — not carried forward by default. **[US-016, 2026-09-13] The successor story (US-016) has shipped, but this expiry clause is not satisfied by that alone — it transfers unchanged, with the same owner and the same 2026-11-27 date, to RES-1(b)'s standing primitive, which US-016 D13 mitigates (visibility) but does not close.** |
| **Closure condition** | The *"Privilege-aware role assignment gating"* story ships, gating **both** `assign()` and `revoke()` on a privilege-carrying test rather than a role-name match. On closure, D13's Javadoc note is **replaced with a closure reference, never deleted**. **[US-016, 2026-09-13] That story has shipped as US-016 and gates both methods as specified. Per US-016 §12.3, this closes T-E17 outright and T-E16 for the direct path; it does not reach the "no gate evaluates at attach time" scenario, which was not this closure condition's target and is RES-1(b)'s subject.** |
| **Verification of C3** | The successor story must exist in the Epic 3 backlog with an id **before this story merges**. `/breakdown` must carry this as an explicit non-code merge checklist item — otherwise C3 is unverifiable and the acceptance is incomplete. **Discharged: the successor story shipped as US-016.** |

---

## 5. Residual risk register

Existing entries reference the design's §12.5 numbering where they correspond; new entries continue it.

| # | Residual | Severity | Why accepted | Compensating control | Owner / review |
|---|---|---|---|---|---|
| **RES-1** | **Propagate-side escalation (T-E16) *and* administrator stripping N→1 (T-E17)** via US-012 `assign()` / `revoke()` name-matching. **[US-016, 2026-09-13] Partially closed — do not read this row as fully closed.** T-E17 (admin stripping) is **closed**: `revoke()` now carries the same privilege gate as `assign()`, symmetric per US-016 ADR-0017. T-E16 (self-escalation) is **closed for the direct propagate path only** — assigning a role that is *already* dangerous. The **attach-after-assign** path (a role made dangerous *after* it is already held) is **not** closed by US-016's gate, which evaluates only at assign/revoke time; it survives as the standing primitive **US-016 RES-1(b) / T-E21**, mitigated (holder-count visibility, D13) but not closed, in `docs/features/US-016/03-design.md` §12.3 | **High** *(surviving component, RES-1(b): High → Medium once US-016 D13 shipped — it has)* | Fixing it changes a shipped authorization contract and raises questions requiring their own Gate 1 (§4.2). AC11 closes the mint side. **US-016 was that fix for the propagate/stripping paths; the attach-after-assign path needed a materially larger decision (re-validating existing assignments at attach time) deliberately not taken by US-016 either — see design §4.7's rejected alternatives** | C1 (precondition) **+ RC-7 (exploitation)**; PRIORITY-lane `ROLE_PERMISSION_GRANTED`; D13 Javadoc on both methods; C3 successor story (**shipped as US-016**). **Surviving component's own control: US-016 D13** — holder count on `ROLE_PERMISSION_GRANTED`, a WARN when non-zero, and a bounded bucket-tag alert (`nexus_rbac_dangerous_permission_granted_to_holders`, see `docs/features/US-015/monitoring.md` §1/§2, amended by US-016 T-021) | **Full entry in §4.5, amended in place 2026-09-13 — not superseded.** Named owner: Md Nisar Ahmed; review **2026-11-27**; hard expiry **Epic 3 kickoff**. **These three transfer unchanged to RES-1(b)** (`docs/features/US-016/03-design.md` §12.3) — they are not reset by US-016 shipping |
| **RES-2** | **AC10 staleness ≈ 30 min** (cache TTL + access-token lifetime); refresh does not shorten and may extend it | **Medium** | ADR-0013 D4 ratified, not reopened — only the documented window was wrong (twice) | Corrected wording per **RC-2** everywhere it appears; runbook states assignment-revocation as the immediate-effect path | Architect; with the runbook at `/breakdown` |
| **RES-3** | `GET /roles` unbounded/unpaginated; `POST /roles` unthrottled | **Low** (after RC-4) | Pagination is machinery with no user today (D11); a cap is the smaller control | **RC-4 per-tenant role cap**; `{"data":…}` envelope keeps pagination additive; `ROLE_CREATED` out of PRIORITY; growth panel + revisit trigger | Architect |
| **RES-4** | 403-vs-404 existence oracle on `{roleId}` | **Low** | Deliberate Gate 1 OQ4 trade; UUIDv7 ids; authenticated population | 403 branch loud (WARN + counter + alert); 404 DEBUG-only | Accepted as-is |
| **RES-5** | **AC7 has no DB backstop on `role_permissions`**, with MEMBER-role tenant-wide amplification (T-E15) | **Medium** | The table needs `INSERT`/`DELETE`; a trigger costs a migration and was declined | Single shared guard; D8 ArchUnit; **RC-5 named MEMBER negative controls**; **RC-5 `RBAC_003` alert at `> 0`**; D9 drift detection on `roles` | Architect; trigger option to be recorded as considered-and-declined |
| **RES-6** | A tenant with no seeded `TENANT_ADMIN` cannot attach dangerous permissions at all (AC11 fails closed) | **Low** | Fail-closed is correct; the alternative is a silent bypass for every Epic-3 tenant | Explicit 403 branch (§8.5 row 7) + dedicated IT; Epic 3 seeding is the real fix | Epic 3 |
| **RES-7** | The 3 new audit types are **invisible to the standard actor-indexed query** (T-R6) | **Low** (after RC-6) | Preserving "`user_id` is the subject" across 26 types is worth more than one query path | JSON-path forensic query **written into the runbook**, stated as mandatory in addition to the `user_id` query | Security; runbook at `/breakdown` |
| **RES-8** | `uq_roles_tenant_name` is accent-insensitive as well as case-insensitive | **Low** | The constraint does the right thing; only the docs were narrow | Documented; `DuplicateRoleNameException` promises nothing about matching rules; one accent test case | Accepted as-is |
| **RES-9** *(new)* | **Flag-off is not a privilege rollback (T-E20 / D16).** Custom roles keep conferring permissions after the kill switch; with the API gone, only US-012 assignment revocation or DBA DML can neutralise them | **Medium** | Inherent to the feature — the story's writes are domain data consumed by `RoleResolutionService` independently of the flag | PRIORITY-lane grant audit trail; `dangerous_permission_granted` alert history; **RC-6 remediation path incl. the reverse-lookup query and the flag-ordering trade** | Architect + Ops; runbook at `/breakdown` |
| **RES-10** *(new)* | **AC11 denials are not durably audited** (T-R7); asymmetric with US-014 AC4's `ROLE_ASSIGNMENT_DENIED` | **Medium** | AC12 does not require it; the branch is cheaply loopable | Either add `recordRolePermissionDenied` on the **STANDARD** lane, **or** record the asymmetry and mandate that the `RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED` WARN be **retained at least as long as `auth_events`** | **PM decision required** — AC-level, not architect-level |
| **RES-11** *(new)* | **`description` is tenant-controlled text under a weak allow-list, safe only because it is never logged or audited** (T-T9) — an invariant with no enforcement | **Low** (after RC-3) | Free-form prose must stay usable, so no allow-list is possible | **RC-3**: exclude U+2028/U+2029; state the never-log/never-audit invariant in code Javadoc; Epic 3 render-as-text forward note. `RoleAuditEvent` structurally omits the field | Architect; Epic 3 for the render note |

---

## 6. Cross-references to prior threat models

| Prior threat | Status in US-015 |
|---|---|
| **T-E1** (US-009) — escalation to the all-permissions `TENANT_ADMIN` | **Extended.** US-015 opens a second, name-independent route to admin-equivalent authority. AC11 closes the mint side; T-E16 is the residual |
| **T-E5** (US-009) — *"`is_system_role` is inert until this story's AC7 ships"* | **Discharged.** AC7 activates it — as a **pure application-layer control** on `role_permissions` (T-E15) |
| **T-T1 / T-T5** (US-009 / US-012) — JSON injection into `auth_events.metadata` | **Widened and re-mitigated.** `roleName` is tenant-controlled for the first time; two layers verified (T-T8) |
| **T-E13** (US-012) — Jackson-2-vs-3 `ObjectMapper` ambiguity | **Carried forward correctly.** §6.3 mandates the injected `tools.jackson.databind.ObjectMapper` for the new overload; verified at `RbacAuthEventAdapter.java:17, 54, 152` |
| **T-E7** (US-012) — AC8 must be a live, locking read, never a JWT claim | **Reused as AC11's mechanism.** T-E14 is the implementation-time risk of losing the locking property |
| **T-E9** (US-012) — `revoke()` has no symmetric admin check | **Still open; consequence sharpened.** T-E17 — enables N→1 administrator stripping once US-015 is used as intended |
| **T-E10** (US-012) — raw authentication data must not cross into `..application..` | **Preserved.** §4.2's self-policed invariant + two ArchUnit rules |
| **T-R3** (US-012) — best-effort audit loses a committed change | **Inherited unchanged** as T-R5, with the compensating controls extended to three new operations |
| **T-I5** (US-012) — `assignedBy` redaction | **Not applicable.** US-015's DTOs carry no user identifiers at all (§0.3) |
| **T-R4 / O-1** (US-012) — `FOR UPDATE` privilege under the column-scoped grant | **Closed, not inherited.** Empirically settled by `UserRolesPrivilegeIT`; `FOR SHARE` is no stricter |
| **T-E11 / R-5** (US-012) — `@RequiresPermission` visibility trap | **Mechanically closed** for the first time by D8 (T-E19), retroactively covering `UserRoleController` |
| **T-E12** (US-012) — production may not connect as `nexus_app` | **Inherited, and now more load-bearing.** D9 extends drift detection; §12.1 step 2 gates staging on `rbacDbPrivilege` being UP with the new tables covered |

---

## 7. Threats requiring design changes

**These must go back to the architect before Gate 2 can close.** All are small; none reopens Gate 1; none requires an ADR. They are separate from the residual risks in §5, which I assess as acceptable as-is once the corresponding change lands.

---

### RC-1 — Reserve `RbacRoleNames` on role creation *(T-D7, Medium)*

**Change.** `RoleManagementService.createRole` must reject a `name` case-insensitively equal to any reserved system-role name (`TENANT_ADMIN`, `MEMBER`) → **409**. Promote `RbacRoleNames` to expose a `RESERVED` set and a case-insensitive `isReserved(String)`, mirroring `RbacDangerousPermissions`' shape.

**Why it cannot wait.** §6.5's fail-closed tracing is correct for *escalation* — I verified both gates — but the outcome is a **permanent, application-unremediable denial of service**: AC11 becomes unsatisfiable in that tenant forever, Epic 3's per-tenant seeding is blocked by `uq_roles_tenant_name`, and `nexus_app` has neither `UPDATE` nor `DELETE` on `roles`, so only a DBA can undo it. The design declines on the grounds that reserving names "would be inventing an AC at Gate 2"; I disagree — this is input validation on an AC1 field whose value is already security-load-bearing in Q3, exactly the class of decision D6 already makes unilaterally.

**Cost.** ~10 lines, two unit tests, one IT. **Sections:** §4.4, §8.1, §6.5.

---

### RC-2 — Correct the AC10 staleness window to ~30 minutes and name the immediate-effect path *(T-I8, Medium)*

**Change.** Replace the "up to 15 minutes" wording in §5.5, RES-2, §8.8 UI copy, Test Scenario 8, and the runbook with the composite window, and add the operational escape hatch:

> *"Up to the permission-cache TTL **plus** one access-token lifetime — currently **up to ~30 minutes** (900 s + 900 s). A token refresh does not shorten this window and, if it occurs while the cache entry is still stale, **extends** it by re-minting the stale permission set into a fresh token. To revoke effective access immediately, revoke the user's **role assignment** (US-012) rather than detaching the permission from the role."*

**Why.** Verified: `application.yml:143` = 900 s cache; `application.yml:185` = 900 s access token; `RoleResolutionService.java:17-18` is consulted only at mint time, so a stale resolution is baked into a full-lifetime token. The design already corrected one error here (a refresh does not help); the corrected figure is still short by 100%, and it is about to be written into a runbook an operator will use during an access-revocation incident. The assignment-revocation path is the actionable half and appears nowhere.

**Cost.** Documentation, plus one Test Scenario 8 assertion change. **Sections:** §5.5, §8.8, §12.5 RES-2, §11.2.

---

### RC-3 — Harden and document the `description` field *(T-T9, Medium)*

**Change.** Three parts:
1. Tighten to `@Pattern("^[^\\p{Cntrl}\\u2028\\u2029]*$")` — Java's `\p{Cntrl}` is `[\x00-\x1F\x7F]` and does **not** exclude the two Unicode line terminators.
2. State as a security constraint, in `CreateRoleRequest`'s and `RoleView`'s Javadoc: **`description` must never be written to a log, a metric tag, or an audit payload.** It is the only tenant-controlled field in this story not covered by an allow-list strong enough for those sinks, and §8.1's safety argument depends entirely on that invariant — which is currently undocumented and untested.
3. Add to §8.8's Epic 3 forward notes: *"`description` is untrusted tenant-controlled text. Render as text content only — never `innerHTML` / `[innerHTML]` / `bypassSecurityTrust*`."*

**Why.** The current allow-list admits `"`, `\`, `<`, `>`, `&`, U+2028 and U+2029 — the exact corpus the design mandates as the adversarial test for `roleName`. `RoleAuditEvent` correctly omits the field structurally, which is the strongest part of the current position; the rest rests on a prose assertion nothing enforces.

**Cost.** One character class, two Javadoc paragraphs, one forward note. **Sections:** §8.1, §4.4, §8.8.

---

### RC-4 — Add a per-tenant role cap *(T-D6, Medium)*

**Change.** Enforce a configurable per-tenant role ceiling in `RoleManagementService.createRole` (suggest `nexus.rbac.max-roles-per-tenant`, default **500** — an order of magnitude above D11's stated realistic ceiling), returning **409** on breach.

**Why.** D11's "the realistic ceiling is a hand-curated list" is an assumption about benign use. `POST /roles` is unthrottled, `GET /roles` is unpaginated, and this story is the mechanism that removes the previous ≤2-roles-per-tenant bound — so a write-once loop amplifies **every subsequent read by every user in the tenant** (~35 MB per `GET /roles` at 100 k roles), and `nexus_app` holds no `DELETE` on `roles`, so **the application cannot clean it up**. The existing control is a weekly ad-hoc SQL panel against a loop that runs in seconds. A cap is one `COUNT(*)` on an already-indexed predicate and is strictly smaller than pagination or rate limiting — I am not asking for either.

**Cost.** One count query, one config property, one test. **Sections:** §4.2, §8.1, §8.2 (D11 revisit trigger), §12.5 RES-3.

---

### RC-5 — Close three enforcement gaps in the test and architecture plan *(T-E14 / T-E15 / T-E19, High/Medium)*

**Change (three parts, all in §7.2 / §9.3 / §11.2):**

1. **Ban the forbidden shape mechanically (T-E14).** Assert — ArchUnit rule or targeted collaborator test — that **`RoleManagementService` never calls `UserRoleAssignmentPort#findActiveAssignmentViews`**. It has no legitimate use for it (no target user; the port is injected for `hasActiveAdminAssignment` only). The realistic F1 failure is not calling the private helper — it is **copying its shape**, which is doubly wrong: non-locking *and* it bypasses Q3, turning AC11 from an assignment check into a name check. That copy would pass every functional test.
2. **Name `MEMBER` in the AC7 negative controls, and alert on the first attempt (T-E15).** `MEMBER` appears in no AC, no test scenario, and nowhere in §11.2 — yet attaching `role:write` to it escalates **every self-registered user in the tenant** (`V5:119-135`; `RoleAssignmentService.java:268`), and AC7 fires *before* AC11 (§8.6), making AC7 the sole gate for an admin caller. Add named cases: *attach `role:write` to seeded `MEMBER` → 409 `RBAC_003`* and *detach `user:read` from seeded `MEMBER` → 409 `RBAC_003`*. Change §9.3's `RBAC_003` alert from `> 3` to **`> 0`** — no benign client attempts a system-role write repeatedly by accident.
3. **Remove the D8 escape hatch (T-E19).** §7.2 tells `/breakdown` to split the rules "if a formulation is unavailable". Make the outcome non-optional: *"If neither `notHaveModifier(FINAL)` nor `containAnyMethodsThat(...)` exists in the pinned ArchUnit version, implement the check as a reflection-based JUnit test over `@RequiresPermission`-annotated methods. It must not be dropped, weakened, or deferred."*

**Why.** Each converts a prose instruction into a mechanical control, which is the design's own stated philosophy for D8. **Cost:** one rule, two test cases, one threshold, one sentence.

---

### RC-6 — Promote D16 to the residual table and complete its remediation path *(T-E20 + T-R6, Medium)*

**Change.**
1. **Add D16 to §12.5 as RES-9, severity Medium.** It is currently prose in §12.3 with **no rating**, while every other accepted residual has a row — so the one finding stating that the kill switch does not do what a kill switch is assumed to do is absent from the risk register.
2. **Add the reverse-lookup step to the runbook**, before §12.3's step 3: `SELECT BIN_TO_UUID(user_id) FROM user_roles WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL;` — with an explicit note that **no API provides this** (US-012 exposes per-*user*, not per-*role*), so step 3's "needs no DB access" claim holds only for the revocation itself, not for discovering whom to revoke.
3. **Record the flag-ordering trade:** flipping the flag off first stops the bleeding but also removes `GET /roles/{id}/permissions`, the read path needed to identify offending roles. Defensible; must be written down, not discovered mid-incident.
4. **Reword RES-7 (T-R6)** from "not queryable by the indexed column" to "**invisible to the standard actor query; a JSON-path query is mandatory**", and put that query in the runbook: `... WHERE JSON_UNQUOTE(JSON_EXTRACT(metadata,'$.grantedBy')) = ?` (and `$.createdBy` / `$.revokedBy`).

**Cost.** One table row, three runbook paragraphs, one rewording. **Sections:** §12.3, §12.5, §6.3, and the `/breakdown` runbook.

---

### RC-7 — Strengthen D15's condition C1 with an exploitation-side detection signal *(T-E16, High)* — **the most important change in this list**

**Change.** C1 currently ships only `nexus.rbac.dangerous_permission_granted{permission}`, which fires on the **legitimate admin action that creates the precondition** and is **silent on the actual exploitation**. Add a signal on step 3 of the chain. **Recommended (Option A, near-free):** in `RoleAssignmentService.assign()`'s existing post-commit block, emit `nexus.rbac.self_role_assignment` + WARN when `targetUserId.equals(actor.userId())`. No new query, no new port method, no schema change — both ids are already in hand. Alert at `> 0` (ticket), escalating to **page** in any tenant where `nexus_rbac_dangerous_permission_granted_total > 0`, which composes the two signals into genuine detection of the chain.

The design must also state explicitly that adding an observability counter inside an existing post-commit block is **not** an authorization-contract change and therefore does not require a US-012 Gate 1 reopen — otherwise §12/D13's *"Javadoc only, no behaviour"* constraint will be read as forbidding it.

**Why this is a Gate 2 condition.** The D15 acceptance rests on the claim that the risk is *detected*. §10.2 item 4's *"the window between reachable and noticed is minutes, not months"* is true of the **precondition** and says nothing about the **exploitation**, for which the window is currently unbounded — step 3 emits a `ROLE_ASSIGNED` row indistinguishable from any routine assignment, with no alert. Self-assignment is the highest-signal shape of the attack (step 3's own definition is "including themselves") and is close to nonexistent in benign use.

**I agree with accepting D15 as option (a) — but the acceptance is only sound with this control.** Without an exploitation-side signal I would move to reject the acceptance, which under §0's conditional ADR trigger would return the story to Gate 1. **Adding RC-7 is by far the cheaper path and preserves the design's decision intact.**

**Cost.** ~5 lines in an existing block, one counter, one alert rule, one clarifying sentence. **Sections:** §9.2, §9.3, §10.2 item 4, §10.3 (C1's definition), §13 item 15.

---

## 8. Gate 2 recommendation

**Conditional pass.** The design is thorough, adversarially self-aware, and correct on every claim I was able to verify against code — including the two it flags as the story's most likely silent failures. I found no Blocker and no Critical finding, and no reason to reject the D15 risk-acceptance decision on its merits.

**Conditions for closing Gate 2:**

1. **RC-1 … RC-7** folded into `03-design.md` (all small; none reopens Gate 1; none requires an ADR).
2. ~~A named individual substituted for the accountable-owner placeholder in §4.5~~ — **done**: Md Nisar Ahmed, §4.5.
3. **C3 verified**, not assumed: the *"Privilege-aware role assignment gating"* successor story exists in the Epic 3 backlog **with an id, before this story merges**, and `/breakdown` carries that as an explicit non-code merge-checklist item.

**Not conditions, but must not be quietly descoped in `/breakdown`:** `RoleManagementAdminGateIT`'s concurrent admin-revocation case (the only test distinguishing the mandated locking read from the forbidden shortcut), `RolePermissionsPrivilegeIT` (the only test catching a production-only `Role` dirty-flush), the adversarial `roleName`/`permissionName` JSON corpus, and the per-endpoint negative-control 403 tests.

**Deferred to the Phase 7 code audit** (Mode B), recorded rather than skipped: `./mvnw dependency:tree` CVE review and `npm audit`. This story proposes **zero** new dependencies and **zero** frontend file changes, so there is nothing to scan at design time; both are mandatory at implementation review.

---

### Cross-references

- `docs/story/2-rbac/US-015.md` — authoritative AC1–AC12
- `docs/features/US-015/01-requirements.md` — Gate 1; §11 Resolutions OQ1–OQ6 binding, never reopened here
- `docs/features/US-015/02-impact.md` — F1/F2/F3, R-1…R-14; §6's "threat-model refresh required at Gate 2" list is discharged by §3 of this document
- `docs/features/US-015/03-design.md` — the artifact under review; §14's cross-reference list of required coverage is discharged item by item (D15/R-3 → §4 + RES-1; F1 → T-E14; `roleName` JSON injection → T-T8; AC7 DB backstop → T-E15/RES-5; §6.5 reserved name → T-D7; D16 → T-E20/RES-9; AC10 staleness → T-I8/RES-2)
- `docs/features/US-012/03b-threat-model.md` — severity scale, STRIDE table format, threat-ID sequence, and the T-E7/T-E9/T-E10/T-E13/T-R3/T-I5 entries this document extends
- `docs/features/US-009/03b-threat-model.md` — T-E1, T-E5, T-T1, T-S2, T-R1
- `docs/adr/0011-*.md` §1 (audit retry-buffer lanes: capacity 200, drop-newest, depth-critical ≥180) · `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` (D1, D2, D3, **D4 — cache fan-out, ratified and not reopened; only its documented window is corrected by RC-2**) · `0014` D5/D6 · `0015` D7/D8 · `0016` D3/D4
- `SECURITY.md` §3.1 — `RBAC_001` response shape; the `@RequiresPermission` visibility and self-invocation pitfalls (T-E19); gains the D3 error-code register
- Code verified this session, with line references throughout §0.1 and §3: `rbac/application/RoleAssignmentService.java`, `rbac/application/RoleResolutionService.java`, `rbac/application/port/out/UserRoleAssignmentPort.java`, `rbac/application/port/out/PermissionCachePort.java`, `rbac/domain/RbacRoleNames.java`, `common/security/TenantAwarePermissionEvaluator.java`, `common/web/GlobalExceptionHandler.java`, `identity/infrastructure/audit/RbacAuthEventAdapter.java`, `identity/domain/AuthEventType.java`, `db/migration/V5__rbac_schema.sql`, `nexus-database/mysql/init/02-grants-post-schema.sql`, `src/main/resources/application.yml`
