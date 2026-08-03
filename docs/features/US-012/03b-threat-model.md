# US-012 — STRIDE Threat Model: Enable role assignment and revocation API

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md`. Feeds `/breakdown` (Phase 4) and closes `03-design.md` §12 O-4._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-012 · **Reviewer:** Application Security Engineer · **Status:** Gate 2 review

---

## 0. Scope, verification basis, and headline result

**Scope.** The design in `docs/features/US-012/03-design.md`: the first controller in the `rbac` bounded context (`UserRoleController`, 3 endpoints), `RoleAssignmentService` and its four outbound ports, the M1–M6 query set, the `nexus_app` column-scoped privilege boundary, the `RbacAuthEventAdapter` audit path, the D11 feature flag, and the D9/R-10 architectural controls. US-009's schema and US-011's enforcement are in scope only as **trust dependencies**.

**This story is the actual control for a Critical threat.** Per the story's Background and US-009 T-E1, AC8 + AC4 are the only things standing between a self-registered bootstrap-tenant member and the all-permissions `TENANT_ADMIN` role. Nothing in the schema backstops them.

### 0.1 Verification basis — code and database re-read this session, not trusted from the design doc

| Claim under test | Verified how | Result |
|---|---|---|
| D2: load-mutate-save emits a multi-column UPDATE the grant rejects | Read `rbac/domain/UserRole.java` | **Confirmed** — `userId`/`roleId`/`tenantId`/`assignedBy` are plain updatable mappings; only `assignedAt`/`activeKey` are `updatable=false` |
| R-1: single-column UPDATE permitted, multi-column denied | **Live MySQL 8.4.10 as `nexus_app` with the production grant set** | **Confirmed** — `SET revoked_at` → 1 row; multi-column → `ERROR 1143 (42000) … denied … for column 'user_id'` |
| **R-4 / O-1: is `SELECT … FOR UPDATE` grantable under column-scoped `UPDATE (revoked_at)`?** | **Live MySQL 8.4.10 as `nexus_app`** | **RESOLVED — IT SUCCEEDS.** See §0.2 |
| R-3 / D1: lock set is one tenant's admin rows, not the table | `EXPLAIN` + two concurrent sessions with `innodb_lock_wait_timeout` | **Confirmed** — `type=ref key=fk_user_roles_role key_len=16`; unrelated tenant's row updated freely while the lock was held; in-range row blocked (`ERROR 1205`). `tenant_id`-driven shape → `type=ALL` (the R-3 hazard is real) |
| R-8: CHECK violation is untranslated → 500 | Live MySQL | **Confirmed** — `ERROR 3819 (HY000)`, not in Spring's error-code map |
| M6 trap: plain `current_timestamp` loses microseconds | Live MySQL | **Confirmed** — `CAST(CURRENT_TIMESTAMP AS DATETIME(6))` = `…:16.000000` vs `NOW(6)` = `…:16.613594`. The trap would *cause* R-8 |
| T-T1: native JSON column behaviour under injection | Live MySQL | **Confirmed + refined** — invalid JSON rejected (`ERROR 3140 (22032)`); valid injected JSON silently accepted and `JSON_EXTRACT` returns the forged value. MySQL keeps the **last** duplicate key (see T-T5) |
| §8.5: `handleNotFound` = DEBUG, no metric; `handleInsufficientPermission` = WARN + counter | Read `common/web/GlobalExceptionHandler.java` | **Confirmed** — this asymmetry undercuts half of §8.5's "loud by design" claim (T-I4) |
| D15: `handleFieldValidation` already exists → zero new handler code | Read `GlobalExceptionHandler:64-70` | **Confirmed** |
| Res. 9 / §6.5: live-role fingerprint makes eviction non-load-bearing | Read `rbac/application/RoleResolutionService.java` | **Confirmed** — `findActiveRoleNames` re-read on every `resolve()` and compared to the cached role set; a US-012 role change is always reflected on the next mint even with Redis down |
| §6.5: real cache keys | Read `RedisPermissionCacheAdapter` | **Confirmed** — `{prefix}:rbac:roleset:…` and `{prefix}:rbac:permset:…`; AC6's `permissions:{t}:{u}` does not exist |
| R-10: the ArchUnit rule that constrains the design exists | Read `HexagonalArchitectureTest:69-75` | **Confirmed** — `resideInAnyPackage("..domain..", "..application..")` matches `rbac.application` |
| §4.8 / D6: `ObjectMapper` injectable, zero new dependency | `./mvnw dependency:tree` (198 artifacts) | **Confirmed but ambiguous — see T-E13.** Boot 4.1 ships Jackson **3** (`tools.jackson.core:jackson-databind:3.1.4`); Jackson **2** (`com.fasterxml…:2.21.4`) also present via `jjwt-jackson`/springdoc |
| §5.1: no migration needed; `roles.name` bounds the injection payload | Read `V5__rbac_schema.sql` | **Confirmed** — every column/index/constraint/trigger present; `roles.name` is `VARCHAR(64)`, which bounds but does **not** prevent a T-T5 payload |
| `RbacDbPrivilegeHealthIndicator` cannot detect a *missing* grant | Read the indicator | **Confirmed** — checks only over-grant (`DELETE`/root/`ALL PRIVILEGES`) |
| Randomness / crypto hygiene | Read `UuidV7Generator`; grepped `Math.random` | **Clean** — `UuidCreator.getTimeOrderedEpoch()` (ADR-0005); zero `Math.random` in the backend |

### 0.2 Headline result: R-4 / O-1 is resolved empirically, in the favourable branch

The design calls R-4 "the one genuinely open item this design cannot close by reading code" and sequences a blocking verification task ahead of the lockout-guard implementation. This was resolved in a throwaway MySQL 8.4.10 container reproducing `V5`'s `user_roles` shape and the exact grant set from `nexus-database/mysql/init/02-grants-post-schema.sql`:

```
GRANT SELECT, INSERT, UPDATE (`revoked_at`) ON `nexus`.`user_roles` TO `nexus_app`@`%`
```

| §5.3 assertion | Result as `nexus_app` |
|---|---|
| 1. `UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ?` | **SUCCEEDS** (1 row) — D2 defeats R-1 |
| 2. multi-column UPDATE (the load-mutate-save shape) | **DENIED** `ERROR 1143 (42000) … for column 'user_id'` |
| 2b. `UPDATE … SET tenant_id = ?` | **DENIED** `ERROR 1143 (42000) … for column 'tenant_id'` |
| **3. `SELECT … WHERE role_id=? AND tenant_id=? AND revoked_at IS NULL FOR UPDATE`** | **SUCCEEDS — returns and locks the rows** |

**Consequences for Gate 2:**

1. **D1 ships as designed.** No grant widening, no ADR; the conditional ADR trigger in §0 **does not fire**.
2. **The §5.3 lock-free fallback is not needed.** Demote it to an appendix or delete it — it is the weaker design (T-D4) and leaving it inline as a co-equal branch invites an implementer to choose it.
3. **O-1 changes character**: from a *blocking discovery task* to a *permanent regression assertion*. `UserRolesPrivilegeIT` remains **mandatory** — it is the only control catching a future grant tightening silently breaking the lockout guard (T-E12). Assert error **1143** (not 1142) alongside SQLState `42000`.
4. A locking read is now *known* available cheaply, making the T-E7 hardening a one-annotation change rather than a privilege question.

*Caveat:* verified on MySQL 8.4.10, `nexus_app`@`%` matched from localhost, 4-row table. It proves the **privilege** semantics conclusively and the **lock-scope** semantics for an index-driven plan. It does not substitute for `UserRolesPrivilegeIT` in CI, nor for staging verification that production connects as `nexus_app` at all (T-E12).

### 0.3 Explicit review attestation (standing policy — auth, crypto, PII never approved silently)

- **Authentication** — reviewed. US-012 adds no authentication code; it consumes `Authentication` produced by `JwtAuthenticationFilter` and validated by `JwtRs256Service.verify` (RS256 pinned, alg-confusion guarded — reviewed under US-011 T-01/T-02, unchanged). The new authentication-adjacent surface is the controller's unwrapping of principal + `details.tenantId`, reviewed under T-S3/T-S4. **The inherited trust dependency on US-011 T-02 (tenant-provenance invariant) is unchanged and still load-bearing.**
- **Authorization** — reviewed in depth; this is the story's substance. `@RequiresPermission` coverage (T-E11), tenant isolation on all three verbs (T-E8), AC8 self-escalation (T-E7), AC5 lockout (T-D3), the `user:write`-revokes-admin asymmetry (T-E9).
- **Cryptography** — reviewed. No new crypto. The only new primitive-adjacent code is D13's `UuidV7IdGenerator`, verified to duplicate `UuidCreator.getTimeOrderedEpoch()` (ADR-0005, `SecureRandom`-backed). Zero `Math.random` in the backend. `user_roles.id` is never exposed in any DTO, so UUIDv7 time-ordering creates no enumeration surface. **No cryptographic findings.**
- **PII** — reviewed against the organisation's no-PII rule. `RoleAssignmentResponse` carries `userId`, `roleId`, `roleName`, `assignedAt`, `assignedBy` — **UUIDs, a role label, a timestamp; no email, name, or credential** (§8.3's assessment is correct and confirmed). `RbacAuditEvent` and the metadata JSON carry only UUIDs, `roleName`, `traceId`. `auth_events.ip_address`/`user_agent` are pre-existing columns fed by the established `RequestContext.of` path (512-char cap verified). Logs emit `userId`/`tenantId` as UUIDs only. **No PII exposure introduced.** One non-PII disclosure finding stands on its own merits: T-I5.

**Severity scale:** Blocker / Critical / High / Medium / Low.

**Threat ID numbering** continues US-009's STRIDE-lettered scheme, which allocated T-S1–S2, T-T1–T4, T-R1–R2, T-I1–I3, T-D1–D2, T-E1–E6. US-012 therefore begins at T-S3, T-T5, T-R3, T-I4, T-D3, T-E7. US-011's parallel `T-01…T-13` sequence is disjoint and not extended.

---

## 1. Trust boundaries and data flow

```
[ Internet / hostile client — may hold a VALID token for a low-privilege tenant member ]
        |  POST/GET/DELETE /api/v1/users/{userId}/roles[/{roleId}]  + Bearer JWT
        v
=== TB1: network -> app ================================================
  CorrelationIdFilter -> LoginRateLimitFilter (login/refresh only — NOT these paths)
  -> JwtAuthenticationFilter : RS256 verify; principal(sub) + details{tenantId,
     permissions, emailVerified, tokenVersion}; MDC userId/tenantId
        |  invalid/absent -> 401 AUTH_003, chain short-circuits
        v
=== TB2: filter chain -> dispatcher ====================================
  .anyRequest().authenticated()          <-- authN only, NOT permission
  @ConditionalOnProperty feature flag    <-- bean absent => 404 (fail-closed)
        v
=== TB3: dispatcher -> method-security proxy ===========================
  @RequiresPermission("user:write" | "user:read")
     -> TenantAwarePermissionEvaluator.hasPermission
        == FLAT Set.contains on the JWT permissions[] claim. ZERO tenant comparison. ==
        == Cannot express AC4 or AC8. Both are service-layer logic. ==
        v
=== TB4: interfaces -> application (the Spring-Security-free boundary) =
  UserRoleController: validates path/body UUID *strings*, then parses;
     actor = RoleChangeActor(principal, details.tenantId)   <-- JWT-only provenance
        |  ArchUnit: no org.springframework.security type may cross into ..application..
        v
  RoleAssignmentService @Transactional
     -> UserDirectoryPort.findTenantId(target)       [AC4 — tenant of the SUBJECT]
     -> UserRoleAssignmentPort.findRole(roleId)      [AC4 — tenant of the ROLE]
     -> M5 hasActiveAssignment(caller, adminRole, tenant)   [AC8 — LIVE DB read]
     -> M1 lockActiveAssignmentIds (FOR UPDATE)      [AC5 — lockout guard]
     -> M2 pre-check / INSERT / M6 bulk UPDATE
        v
=== TB5: app -> MySQL as `nexus_app` (least-privilege) =================
  SELECT, INSERT on user_roles + UPDATE (revoked_at) ONLY. No DELETE, no LOCK TABLES.
  DELETE trigger + column-scoped grant = the tamper-evidence layer for T-S3.
        v
=== TB6: post-commit, best-effort side effects (D14 afterCommit) =======
  PermissionCachePort.evict  -> Redis      (fail-open, never throws)
  RbacAuditPort.recordRole*  -> RbacAuthEventAdapter -> SecureEventService(REQUIRES_NEW)
                             -> AuthEventPort -> JpaAuthEventAdapter -> auth_events
  ^^ neither may throw or block; a failure here leaves a COMMITTED privilege change
     with no audit trail (T-R3) and no cache eviction (bounded, see §0.1)
```

**Components.** **C1** `UserRoleController` + DTOs · **C2** `RoleAssignmentService` · **C3** `UserRoleAssignmentPort`/adapter + M1–M6 · **C4** `UserDirectoryPort`/adapter · **C5** `RbacAuditPort`/`RbacAuthEventAdapter` → `SecureEventService` → `AuthEventRetryBuffer` · **C6** `PermissionCachePort`/`RedisPermissionCacheAdapter` · **C7** the `nexus_app` DB privilege boundary · **C8** architectural controls (D9 ArchUnit, R-10, D11 flag) · **C9** `common` deltas (D5, D12) · **C10** `TenantAwarePermissionEvaluator` (dependency, unmodified).

---

## 2. Component-by-component STRIDE table

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **C1** Controller + DTOs | `assignedBy` not modelled — spoofing closed structurally (T-S3 ✅). Principal parse can 500 (T-S4) | Path/body `String`+BeanValidation → 400 not 500 (D15 ✅) | — | Malformed-UUID 400 carries only the field name (✅) | Unauthenticated never reach here (401 at TB1); no rate limit but authN-gated (T-D5) | R-2 package-private handler → silent non-enforcement (T-E11) |
| **C2** RoleAssignmentService | Actor is a plain `RoleChangeActor`; no client-input path (T-S3 ✅) | Owns every authz semantic `@RequiresPermission` cannot express | Side effects post-commit → a thrown 403/409 emits nothing (✅ correct) | Error messages are static literals, no ids/counts/SQL (✅) | — | **AC8 (T-E7), AC4-on-GET (T-E8), `user:write` revokes admin (T-E9)** |
| **C3** Port/adapter + M1–M6 | — | M3 hands a **managed entity** to the write path → R-1 footgun (T-T6); RBAC_004 message may leak constraint names (T-T7) | — | — | **M1 lock scope proven tenant-confined (T-D3 ✅)**; fallback TOCTOU (T-D4) | M6 affected-row count is the only concurrency guard (no `@Version`) — verified sound |
| **C4** UserDirectoryPort | — | Read-only, single method (✅) | — | Existence oracle via 403-vs-404 (T-I4) | Single indexed PK read (✅) | **Not specified as called on GET (T-E8)** |
| **C5** Audit path | Actor attribution JWT-sourced (✅ closes US-009 T-R1) | `role_name` JSON injection — closed by D6 (T-T5 ✅) | **Audit loss bypasses the retry buffer entirely (T-R3)**; STANDARD-lane drop-newest (T-R4) | Metadata holds UUIDs + roleName + traceId only (✅ no PII) | Unbounded `auth_events` growth under churn (T-D5) | — |
| **C6** Cache | — | Eviction failure ⇒ stale entry, but role-set fingerprint makes it non-load-bearing (✅ verified) | — | — | Fail-open on Redis outage (✅ verified) | — |
| **C7** `nexus_app` boundary | — | **Column-scoped grant blocks `assigned_by`/`user_id` rewrite — empirically proven (T-S3/T-E12 ✅)** | DELETE trigger + no DELETE grant preserve history (✅) | — | — | Grants never applied / prod-as-root undetected by the health indicator (T-E12) |
| **C8** ArchUnit / R-10 / flag | — | — | — | — | Flag off ⇒ 404, fail-closed (✅) | Structural not runtime; `Principal`/`Map` laundering bypass (T-E10) |
| **C9** `common` deltas | — | Purely additive enum constants; no dispatch change (✅) | — | — | Bounded cardinality (5 reasons) (✅) | Makes AC8 attempts separately alertable (✅ genuine gain) |
| **C10** Evaluator (dep.) | Inherits US-011 T-02 residual | — | — | Echoes `requiredPermission` (US-011 T-09, accepted) | In-memory `Set.contains` (✅) | Zero tenant comparison — by design; **this is why C2 must be right** |

---

## 3. Findings

---

### [Medium] T-E8 — Tenant isolation on `GET` is asserted in prose but not specified in the design's own component contract; the likely implementation silently returns `200 {"data":[]}` instead of `403`

**Component:** C2/C4. **STRIDE:** Elevation of Privilege / Information Disclosure. **OWASP:** A01, A09.

**This is the one finding that materially weakens a Gate-1 resolution and should be fixed before `/breakdown`.**

Verification of Gate 1 Resolution 6 ("tenant isolation applies uniformly to POST, GET, DELETE"):

| Verb | `findTenantId(target)` + tenant equality | `role.tenantId` equality |
|---|---|---|
| `POST` | ✅ Explicit in §3.1 (steps 6–8) | ✅ Explicit in §3.1 (step 10) |
| `DELETE` | ✅ Explicit in §3.2 | ✅ Explicit in §3.2 |
| `GET` | ⚠️ **Only implied** — "Identical shape for `GET`" (§3.3 closing line) and an `AC4` tag on `listActive`'s Javadoc (§4.2). No sequence step, no explicit statement | n/a — `GET` carries no `roleId`; role-tenancy is covered by M4's `r.tenantId = :tenantId` predicate (✅ adequate) |

The gap is not cosmetic, because **M4 already contains `ur.tenantId = :tenantId AND r.tenantId = :tenantId`**. An implementer reading §4.2's `listActive(RoleChangeActor actor, UUID targetUserId)` signature will reasonably conclude M4's predicates *are* the AC4 enforcement for `GET` and skip `findTenantId` — it looks redundant. The result is functionally "safe" (no cross-tenant data returned) but **wrong in three ways that matter**:

1. **Contract violation.** §8.4 row 5 and §3.3 both state `403 CROSS_TENANT_TARGET` for all three verbs. A cross-tenant `GET` would return `200 {"data": []}`.
2. **The security signal is destroyed** — precisely the failure mode §8.5 point 3 argues against. No `InsufficientPermissionException` ⇒ no WARN log, no `nexus.rbac.permission_denied{reason="CROSS_TENANT_TARGET"}` counter, no `nexus_rbac_cross_tenant_attempt` alert. **Cross-tenant reconnaissance via `GET` becomes completely silent** — and `GET` is the cheapest, most natural probe verb.
3. **The 404 for an unknown `userId`** (§8.4 row 8) also disappears — an unknown user returns `200 {"data": []}`, indistinguishable from a real user with no roles.

**Risk:** a Tenant-A member with `user:read` (i.e. **every** self-registered `MEMBER`) can probe arbitrary user UUIDs across tenant boundaries with zero detection, and the story ships believing Res. 6 is implemented on all three verbs.

**Mitigation as designed:** insufficient — it exists only as a prose aside, and the surrounding design makes the wrong implementation look correct.

**Required mitigation (DESIGN CHANGE):**
1. Add `GET` to §3.3 as an explicit sequence showing `UD.findTenantId(targetUserId)` → empty ⇒ 404 `USER_NOT_FOUND` → mismatch ⇒ 403 `CROSS_TENANT_TARGET`, executed **before** M4.
2. State in §4.2's `listActive` Javadoc that the check is **mandatory and not redundant with M4's predicates**, with the reason (it converts a silent empty result into an alertable denial).
3. `/breakdown`: `RoleAssignmentSecurityIT` must assert `GET` cross-tenant returns **403 with `reason=CROSS_TENANT_TARGET`** and unknown-user returns **404** — explicitly *not* `200` with an empty `data` array.

**Residual after mitigation:** Low — identical to `POST`/`DELETE`.

---

### [Low] T-E7 — AC8's live-admin check closes the ~15-minute stale-JWT window (verified), but a residual REPEATABLE READ snapshot race lets a concurrently-revoked admin's in-flight request still grant `TENANT_ADMIN`

**Component:** C2/C3 (M5). **STRIDE:** Elevation of Privilege. **OWASP:** A01, A07.

**Does §3.1 actually call M5 rather than a JWT-claim check? Yes.** §3.1 step 12 is `S->>AP: hasActiveAssignment(actor.userId, role.id, actor.tenantId)` annotated "M5 - LIVE DB read, never the JWT roles[] claim (R-5)". §5.2's M5 block states "R-5 is closed here and nowhere else"; the port Javadoc repeats "MUST be a fresh DB read"; §11.3 mandates the only test that catches a claim-based implementation (an actor holding a still-valid token whose assignment was revoked out of band). The mitigation is **real, correctly placed, and correctly tested.** Verified also *why* it is necessary: `RoleResolutionService.resolve` re-reads roles live at **mint** time, so the JWT is a point-in-time snapshot with the documented ~15-min lifetime; checking `authentication.getAuthorities()` would re-open T-E1 for a full token lifetime.

**The race.** M5 is a plain, non-locking `SELECT COUNT(*)`. Under MySQL's default **REPEATABLE READ**, a consistent read is served from the snapshot established by the transaction's *first* read — which in §3.1 is `UD.findTenantId` (step 6), several statements *before* M5 (step 12). Therefore:

- A concurrent `DELETE` revoking the **caller's own** `TENANT_ADMIN` assignment, committing any time after the assign transaction's first statement, is **invisible to M5**. M5 returns "still an admin", and the INSERT proceeds.
- Nothing serialises them: the revoker's M1 lock covers `role_id = adminRole` rows; the assigner's INSERT creates a *different* row and never locks its own admin row. M1's next-key/gap locks over the `role_id` index range *would* block a concurrent INSERT **of a `TENANT_ADMIN` assignment** — so "admin A being revoked while granting `TENANT_ADMIN` to accomplice B" is partially serialised, but the ordering is not guaranteed in either direction.
- Window: the duration of the assign transaction (single-digit ms).

**Risk:** an insider admin who knows they are about to be de-privileged spams `POST … {"roleId": <TENANT_ADMIN>}` for an accomplice; any request whose snapshot predates the revocation commit succeeds, minting a new admin *after* the revocation committed. This is the "revoke the rogue admin" incident-response scenario — exactly when it matters.

**Assessment: Low, not Medium.** The design reduces the window from ~15 minutes to ~milliseconds — the substance of R-5, genuinely achieved. But it is not closed, and the design implies it is.

**Required mitigation (DESIGN CHANGE — now cheap):**
1. Make **M5 a current read**: `@Lock(LockModeType.PESSIMISTIC_READ)` (renders `FOR SHARE`) or `PESSIMISTIC_WRITE`, over an entity-root query rather than a `COUNT` (§5.2's own note that `@Lock` on a scalar projection is implementation-defined applies equally — mirror M1's shape and return ids). A current read observes the latest committed state **and blocks** on an uncommitted revocation, closing the window by the same mechanism §3.2 uses for AC5. **§0.2 proves the privilege is available.**
2. If declined, state the residual in §5.2's M5 block rather than "R-5 is closed here and nowhere else".

**Residual after mitigation:** negligible. Without: Low.

---

### [Medium] T-R3 — A committed role change can lose its audit record **silently and without entering the retry buffer at all**, because the failure surfaces at the `REQUIRES_NEW` commit boundary, outside `JpaAuthEventAdapter`'s catch

**Component:** C5. **STRIDE:** Repudiation. **OWASP:** A09, A08.

§6.4/D14 states the audit write inherits durability "for free" from the retry buffer, and §12 dismisses this as "identical exposure to every existing identity audit path". **Tracing the actual chain shows the inheritance is weaker than claimed on this path.**

Verified chain: `RbacAuthEventAdapter` → `SecureEventService.recordEvent` (`@Transactional(REQUIRES_NEW)`) → `JpaAuthEventAdapter.record` → `authEventRepository.save(event)`.

- `JpaAuthEventAdapter.record` wraps `save()` in `catch (DataAccessException)` → WARN → `retryBuffer.enqueue(event)`. That is the entire durability mechanism.
- But `AuthEvent` has an **assigned** `@Id` (pre-generated UUIDv7) and `save()` is called **inside** an active transaction, so Hibernate defers the `INSERT` to flush/commit. A DB-level rejection — and the most likely one demonstrably exists: `ERROR 3140 (22032) Invalid JSON text` on `metadata`, plus any constraint or connection failure — is raised when the **`REQUIRES_NEW` transaction commits**, inside `SecureEventService`'s proxy, **after** `record` has already returned normally.
- Consequence: **the adapter's `catch` never fires, so `retryBuffer.enqueue` is never called.** The exception propagates into `RbacAuthEventAdapter`, whose §4.8 catch-all converts it to a single WARN. **No retry, no `nexus.audit.retry.*` counter, no `RETRY_EXHAUSTED` alert, no buffer-gauge movement — the event is simply gone.**

The catch-all is *correct* for availability (without it, an exception from an `afterCommit` callback propagates to the caller of `commit`, turning a successful privilege change into a 500). But it converts a durable-retry path into a **silent** drop, on the one endpoint family where the audit record *is* the security control.

**Secondary loss paths:** the retry buffer is an **in-process `ArrayBlockingQueue`** — a JVM restart loses everything buffered; genuine exhaustion drops with a WARN + `RETRY_EXHAUSTED` alert (loud, acceptable). §6.4's claim is accurate for the *inline synchronous* failure mode, inaccurate for the *commit-boundary* mode.

**Risk:** an admin assigns `TENANT_ADMIN` to an accomplice; the `user_roles` row commits; the audit write fails at the commit boundary (malformed-metadata bug, `auth_events` lock, transient connection loss, or a full pool — the last *more* likely precisely because `REQUIRES_NEW` borrows a second pooled connection). The platform has a privilege escalation with **no audit trail and no signal that a trail is missing.** Directly falsifies AC7 and re-opens US-009 T-R1/T-S2's non-repudiation intent.

**Existing mitigations that genuinely help:** D14's `afterCommit` ordering releases M1 row locks before the second connection is borrowed (verified — a real improvement over an inline `REQUIRES_NEW` call, and it does reduce pool pressure); D12's INFO structured log `event=ROLE_ASSIGNED` is an **independent** operator-visible record. That INFO log is in practice the actual compensating control — but it is a log line, not an append-only attributable record, and the design does not present it as the fallback.

**Required mitigation (DESIGN CHANGE — small, high value):**
1. **Make the loss loud.** `RbacAuthEventAdapter`'s catch-all logs at **ERROR** with a distinct structured event (e.g. `event=RBAC_AUDIT_WRITE_LOST`) carrying `tenantId`, `targetUserId`, `roleId`, `actorUserId`, `traceId` — enough to reconstruct the lost record.
2. **Add a counter and alert.** `nexus.rbac.audit_write_failed{operation}`, or reuse `AuditAlertPort.raise(...)` (injectable at zero plumbing cost — `RbacAuthEventAdapter` sits in the same package as `LoggingAuditAlertAdapter`). Add a **page**-severity alert to §9.3: a lost privilege-change audit record is at least as serious as `nexus_rbac_self_escalation_attempt`, already a page.
3. **Serialise the metadata JSON before the port call**, inside `RbacAuthEventAdapter` and outside the `REQUIRES_NEW` boundary, so a `JsonProcessingException` — the one failure mode fully under our control — is caught before a transaction opens and cannot become a commit-time DB rejection.
4. **Restate AC7 honestly.** "100% of role assignment/revocation events audited" is unachievable with a best-effort post-commit write. It should read: *every successful assignment/revocation attempts an audit write; any failure is recorded at ERROR, counted, and alerted.* Flag to PM via O-6's docs task.

**Residual after mitigation:** Low. **Without mitigation: Medium**, and AC7 is factually unmet.

---

### [Medium] T-R4 — D10 routes the platform's highest-privilege state change into the retry buffer's drop-newest STANDARD lane, sharing capacity with `LOGIN_FAILURE` floods

**Component:** C5. **STRIDE:** Repudiation. **OWASP:** A09.

D10 excludes `ROLE_ASSIGNED`/`ROLE_REVOKED` from `AuthEventType.PRIORITY`, reasoning that "a successful role assignment is expected traffic" and "the forensically interesting RBAC signal is the denial".

Verified consequence: `AuthEventRetryBuffer` routes by `isPriority()` into two independent fixed-capacity `ArrayBlockingQueue`s with **drop-newest on overflow**. `PRIORITY` = `{LOCKOUT, TOKEN_REFRESH_REUSE, PASSWORD_CHANGED, ACCOUNT_LOCKED_WRITE_FAILED}`. **`LOGIN_FAILURE` is STANDARD.** So during an `auth_events` outage combined with a credential-stuffing flood — a plausible *correlated* pair, since both are attacker-generated — the STANDARD lane fills with `LOGIN_FAILURE` and **`ROLE_ASSIGNED` is the newest arrival that gets dropped.** The two-lane design exists precisely to stop a login-failure flood evicting high-value events (US-008 T-D1); D10 places US-012's events on the wrong side of that protection.

**Assessment — disagree with D10 on its merits.** The rationale conflates *volume* with *forensic value*. `PRIORITY` exists for **low-volume, high-value** events; a role assignment is exactly that profile — arguably more so than `PASSWORD_CHANGED`, which is already PRIORITY. For incident reconstruction, "who obtained `TENANT_ADMIN`, when, granted by whom" is answered *only* by `ROLE_ASSIGNED`; a denial answers "who tried and failed", valuable for detection but not for establishing what happened. Capacity-dilution cost is near-nil: role changes are single-digit-per-tenant-per-month administrative events.

**Required mitigation (DESIGN CHANGE — recommended, one line + one test):** add `ROLE_ASSIGNED` and `ROLE_REVOKED` to `AuthEventType.PRIORITY`. Cost: §6.2 notes `AuthEventTypeTest#should_returnFalse_when_isPriorityCheckedOnAllNonPriorityTypes` uses `EnumSource(EXCLUDE)` and auto-covers them as non-priority — so this becomes a small explicit test edit instead of a silent auto-pass. That is a *better* outcome: the lane assignment of a security-critical event type should be an explicit reviewed assertion.

**If declined:** add a §9.3 alert on `increase(nexus_audit_buffer_dropped_total{lane="standard"}[15m]) > 0` at ticket severity, and record here that role-change audit records are droppable under correlated load. Silence is not an acceptable mitigation for a repudiation risk on this surface.

**Residual after mitigation:** Low.

---

### [Medium] T-T6 — M3 returns a **managed** `UserRole` entity onto the revocation write path, re-opening the exact R-1 footgun the design closes everywhere else

**Component:** C3. **STRIDE:** Tampering / Insecure Design. **OWASP:** A04, A05.

The design is rigorous about keeping entities off the write path. §4.3's M1 Javadoc: *"Ids only, never entities: the caller must not be able to load-mutate-save a `UserRole` (R-1)."* §4.3's closing paragraph: *"Only the two hot write paths (`lockActiveAssignmentIds`, `revoke`) deliberately avoid entities."*

But **M3 is also on the write path** — it is the `DELETE` flow's step that fetches the assignment to revoke (§3.2, between the M1 lock and M6) — and its signature is `Optional<UserRole> findActiveAssignment(...)`. That hands `RoleAssignmentService` a **managed, dirty-trackable** entity whose `userId`, `roleId`, `tenantId`, `assignedBy` are all plain updatable mappings (verified). One future line — `assignment.revoke(clock.instant())`, which is *the entity's own documented API* and which the design explicitly retains (§5.2: "`UserRole#revoke(Instant)` becomes unused on the production write path… It stays") — causes Hibernate to flush a five-column `UPDATE` at commit.

That failure is **invisible to the entire test suite** (every `*IT` connects as the Testcontainers superuser) and manifests **only in production** as `ERROR 1143 … UPDATE command denied for column 'user_id'` — the precise Critical failure mode R-1 exists to prevent, empirically confirmed in §0.2 assertion 2.

**Risk:** production-only availability failure on the revoke endpoint; or, if someone "fixes" it by widening the grant to table scope, silent loss of the `assigned_by`/`user_id`/`role_id` immutability that is the DB-level backstop for US-009 T-S2 and T-T1.

**Required mitigation (DESIGN CHANGE — small):**
1. Change M3 to return a **projection**: `Optional<UUID> findActiveAssignmentId(UUID userId, UUID roleId, UUID tenantId)`, or a tiny `record ActiveAssignmentRef(UUID id, Instant assignedAt)` if the M6 fallback clamp needs `assignedAt`. The service only ever uses the id (for M6 and the M1 `contains(targetAssignmentId)` invariant check).
2. Extend the R-1 rationale in §4.3 from "the two hot write paths" to "**every** method reachable from `revoke`".
3. `/breakdown`: keep `UserRolesPrivilegeIT` assertion 2 (multi-column UPDATE denied, `ERROR 1143`/`42000`) as a **permanent** regression test — the only automated control for this class, and it works because it connects as `nexus_app`.

**Residual after mitigation:** negligible.

---

### [Low] T-T5 — `role_name` JSON injection into `auth_events.metadata` is genuinely closed by D6 (Jackson), and the hand-rolled-escaper alternative would have been exploitable in a narrower way than expected

**Component:** C5. **STRIDE:** Tampering (audit-record integrity). **OWASP:** A03, A09.

**Does D6 close it? Yes, for the right reason.** `objectMapper.writeValueAsString(map)` produces RFC 8259-correct escaping **by construction** — quotes, backslashes, and the full `U+0000`–`U+001F` range escaped by the generator, not a hand-maintained `switch`. The design's justification for rejecting "replicate `RequestContext#jsonEscape`" is sound: `jsonEscape` is currently correct, but it is a security-critical 20-line loop and a second hand-maintained copy is a divergence waiting to happen. Infrastructure is the right layer for Jackson (the reason `common.domain.RequestContext` hand-rolls it — domain types avoid a Jackson dependency — genuinely does not apply). Verified zero new dependency.

| Edge case | Assessment |
|---|---|
| **Extremely long names** | **Bounded by schema, not code.** `roles.name` is `VARCHAR(64)`; `metadata` is native `JSON` (~1 GB / `max_allowed_packet`). No length-based DoS or truncation escape. |
| **JSON structural characters** | Closed by Jackson. Confirmed MySQL *would* accept a successfully-injected payload as valid JSON — the escaper is the only control, there is no DB-side safety net. |
| **Injection payload budget** | A working payload — `x","assignedBy":"FORGED-ADMIN` — is **29 characters**, comfortably inside `VARCHAR(64)`. "Names are short" is **not** a mitigation. |
| **Which keys are forgeable (if the escaper broke)** | **Refined and non-obvious:** MySQL normalises an object by keeping the **last** duplicate key (verified: `{"assignedBy":"FORGED","assignedBy":"REAL-ACTOR"}` → `"REAL-ACTOR"`). With §6.3's order (`traceId`, `roleId`, `roleName`, `assignedBy`), an injected duplicate `assignedBy` is **overridden by the legitimate trailing value**, but `traceId` and `roleId` — emitted *before* `roleName` — **would be forged**, plus arbitrary new keys US-014 might consume. **This is an accident of ordering, not a control, and must not be relied on.** |
| **Unicode / lone surrogates** | The one residual. A lone high surrogate survives Jackson's string escaping as an unpaired UTF-16 unit; UTF-8 encoding at the JDBC boundary can then fail or substitute. The failure mode is an **audit write rejection** → **T-R3** (silent loss), not corruption. Hence §11.2's adversarial tests **must execute against MySQL** — §11.3's `RoleAssignmentAuditIT` with `JSON_VALID()`/`JSON_EXTRACT` is the right harness. |
| **Key ordering at rest** | Implementation note: MySQL's binary JSON **normalises key order** (verified — keys returned sorted by length, not insertion order). §6.3's "ordered map" does not survive persistence; tests must assert via `JSON_EXTRACT`, never string equality. §11.3 already specifies `JSON_EXTRACT` — keep it. |

**Assessment: mitigated as designed. No design change required.**

**Required verification (already in the design — keep mandatory):** §11.2's adversarial `roleName` set and §11.3's `JSON_VALID`/`JSON_EXTRACT` round-trip. **Add one case:** a `roleName` containing `","traceId":"forged` asserting `JSON_EXTRACT($.traceId)` returns the **real** trace id — per the key-ordering analysis, this is the case that actually distinguishes a working escaper from a broken one.

**Residual:** Low — a lone-surrogate `role_name` could fail the audit insert (→ T-R3); US-015 should constrain role-name character classes at creation time (forward-flag to US-015).

---

### [Low] T-I4 — The cross-tenant existence oracle is correctly accepted, but two parts of §8.5's justification do not survive scrutiny and should be corrected

**Component:** C4/C2/C9. **STRIDE:** Information Disclosure. **OWASP:** A01, A09.

**Bottom line: the decision (403 cross-tenant, 404 nonexistent) is correct and endorsed. Two of the five supporting arguments are wrong, and one of them is the compensating control §12 leans on.**

**What holds:**
- **Argument 3 is decisive**, and the premise verified: `handleNotFound` logs **DEBUG with no metric**; `handleInsufficientPermission` logs **WARN + `nexus.rbac.permission_denied{permission,reason}`**. Collapsing cross-tenant to 404 moves an authorization failure from an alertable WARN+metric to a production-invisible DEBUG — materially worse than the oracle, exactly as argued.
- **Argument 2 holds** (valid JWT + `user:read`/`user:write` in the caller's own tenant; not internet-facing). **Arguments 4/5 hold.**

**What does not hold:**

1. **Argument 1's "UUIDv7 unguessability" is false for `roleId`.** True for `userId` (runtime UUIDv7). **Not** for `roleId`: the bootstrap tenant's role IDs are low-entropy, sequential, and *published* — `019f6839-1810-…-00000000000a` (`TENANT_ADMIN`), `019f6839-1811-…-00000000000b` (`MEMBER`) appear in `V5`, ADR-0014, US-009's threat model, `02-impact.md` §11.1, and `03-design.md` §11.1. US-009 T-I2 explicitly accepted that seeded reference IDs are well-known. So §8.4 row 6 vs row 9 is a **freely probeable** oracle for the two system roles. *Practical leak: nil* — it confirms only public knowledge. But the reasoning is unsound and will be copied by US-015, which introduces tenant-created roles where the distinction is more sensitive.
2. **"Loud by design" is only half true.** §12 states the compensating control is "WARN + metric on **every attempt**". It is WARN + metric on every **cross-tenant** attempt (the 403 branch). The **404 branch is silent** — DEBUG, no counter. A probe campaign consisting mostly of misses generates no telemetry; only hits are visible. Adequate for detecting a *successful* probe, but the claim overstates the control.

**Something the justification missed:** the oracle is **two-dimensional and ordered**. §3.1 resolves the user first (404 vs 403) and the role second, so a caller can independently determine, for any UUID they hold, "is this a user, and is it mine?" *and* "is this a role, and is it mine?". Dimension one is a genuine privacy signal: given a user UUID obtained out of band — a shared support ticket, a leaked log line, a screenshot URL — a tenant admin can confirm *that person has an account on this platform, in someone else's tenant*. That is cross-customer information, not merely structural. Remains **Low** (UUIDv7s unguessable; population is authenticated tenant admins).

**Assessment: ACCEPTED residual — decision unchanged.** Masking would cost more in detection than it buys.

**Required mitigation (documentation only):**
1. Correct §8.5 argument 1 to distinguish `userId` (runtime UUIDv7 — argument holds) from `roleId` (seeded, published — argument does not hold, but the leak is nil). Add the forward note that US-015's tenant-created roles get runtime UUIDv7s and inherit the `userId` reasoning.
2. Correct §12's wording from "WARN + metric on every attempt" to "on every **cross-tenant** attempt; the not-found branch is DEBUG-only by design".
3. No status-code change.

---

### [Low–Medium] T-I5 — `GET` lets **any** `user:read` holder — i.e. every self-registered `MEMBER` — enumerate the tenant's complete admin roster and who granted it

**Component:** C1/C2. **STRIDE:** Information Disclosure. **OWASP:** A01.

`GET /api/v1/users/{userId}/roles` requires `user:read` (EPIC-002 API table line 144, restated §4.1). Verified in `V5`'s seed: `MEMBER` holds exactly `user:read` — and `MEMBER` is the role every self-registered user is expected to receive. So **any ordinary member can, for any user UUID in their tenant, retrieve that user's active roles plus `assignedBy`**.

§8.3 addresses this only from the PII angle and correctly concludes `assignedBy` is "a UUID, contains no PII" — true, and confirmed. But STRIDE surfaces a different concern: **this is target selection for privilege escalation.** Combined with T-E1's co-tenancy, a member who wants admin can enumerate exactly *which* accounts hold `TENANT_ADMIN` and *which* of those grant roles — an authoritative list of the highest-value phishing/credential-stuffing/session-theft targets, plus the social-engineering pretext ("X granted my role, so X can grant this one"). §8.3 notes this is "the only place an admin can see *who* granted a role without `audit:read`" — the significant word is that it is **not** restricted to admins.

Mitigating context: the caller is an authenticated tenant member; role membership inside an organisation is not usually secret. **Not a Blocker and not a reason to hold Gate 2.**

**Required mitigation (recommended; a PM/architect decision, as it deviates from the epic's API table):**
- **(a)** narrow `GET` to self-or-admin (reading *another* user's assignments requires an active `TENANT_ADMIN`, reusing M5); or
- **(b)** keep `user:read` for the role list but omit `assignedBy` unless the caller is an active `TENANT_ADMIN`; or
- **(c)** accept explicitly and record it here, noting Epic 3's admin UI is the only intended consumer.

Recommend **(b)**: removes the granter graph (the part with no member-facing use case) for one conditional in the DTO mapper, leaving AC3 and the Epic-3 contract intact. Whichever is chosen, `/breakdown` should carry it as an explicit decision, not an omission.

**Residual:** Low under (a)/(b); Low–Medium under (c).

---

### [Low] T-D3 — The AC5 lockout guard's lock scope is genuinely tenant-confined; D1's reasoning is correct and verified empirically

**Component:** C3 (M1). **STRIDE:** Denial of Service. **OWASP:** A04.

| Design claim (§5.2 M1, §3.2) | Verification | Result |
|---|---|---|
| Driving predicate is `ur.role_id` on the FK index — never the unindexed `tenant_id` | `EXPLAIN` on the exact predicate | `type=ref`, `key=fk_user_roles_role`, `key_len=16`, `Extra: Using index condition; Using where` — **confirmed** |
| The `tenant_id`-driven shape would lock every row (the R-3 hazard) | `EXPLAIN` on the `tenant_id`-only predicate | `type=ALL`, `possible_keys=NULL` — **hazard is real**, so the insistence on the access path is load-bearing, not stylistic |
| Lock set is "this tenant's admin rows only, NOT the whole table" | Session A holds `FOR UPDATE`; session B revokes a row in a **different role in a different tenant**, `innodb_lock_wait_timeout=3` | B **succeeded immediately** (1 row) — **confirmed not serialised** |
| Concurrent revocation inside the range blocks (the R-3 TOCTOU closure) | Same, targeting a row **inside** A's range | `ERROR 1205 Lock wait timeout exceeded` — **confirmed blocked**, the exact serialisation Res. 8 requires |
| `roles` is never locked (one table in the `FROM`) | Query-shape review | **Confirmed** — no join, no `FOR UPDATE OF` needed; the improvement over `02-impact.md`'s join suggestion is sound (dialect-independent) and avoids an X-lock on a row US-015's `role:write` flows will want |
| `SELECT … FOR UPDATE` grantable at all | §0.2 | **Confirmed** |

**Assessment: mitigated as designed. No design change.** The DoS is closed: revocations serialise only against other revocations of the *same tenant's* admin assignments — the minimum the AC5 invariant requires. The gap-lock side effect (blocking a concurrent `TENANT_ADMIN` insert over that range) is real, is a correctness benefit, and partially — only partially — mitigates T-E7.

**Note for `/breakdown`:** MySQL 8.4 reports the index as `fk_user_roles_role`, which is what the `EXPLAIN` returned — the design's hedge "(or the FK index name MySQL 8.4 reports)" resolves to that literal. The specified assertions (`key`, `type = ref`, emitted SQL contains `for update`) matched measurements exactly.

---

### [Low] T-D4 — The §5.3 lock-free fallback is the weaker design and should be removed now that R-4 is resolved, not carried as a live branch

**Component:** C3. **STRIDE:** Denial of Service / Elevation of Privilege (tenant lockout). **OWASP:** A04.

**As a standalone design, the fallback rates Medium** — a real rating, not the design's hedge. Collapsing the guard into the `UPDATE`'s `WHERE` clause means the count subquery is evaluated during statement execution; under REPEATABLE READ, InnoDB *does* take shared next-key locks on rows read by a subquery inside DML, which is why the "narrows" instinct is right. But: (a) exact locking is version- and plan-dependent; (b) the ambiguous `0 affected rows` outcome requires a **second, non-locking** read to disambiguate 409-from-404, reintroducing a small TOCTOU on the *error classification*; (c) the design concedes it cannot assert closure. A "probably serialised" guard on a **tenant-lockout** invariant — an availability failure needing DBA intervention to repair, since `nexus_app` cannot re-`INSERT` an admin without an admin — is Medium, not Low. The design's own instinct to pair it with "a compensating detection control: a health indicator or scheduled check alerting when any tenant has zero active `TENANT_ADMIN` assignments" is the correct treatment and confirms the rating.

**But the branch is moot** — §0.2 resolves the decision tree to "Ship D1 as designed."

**Required mitigation (DESIGN CHANGE — subtractive):**
1. Update §5.3 with the empirical result; resolve the tree to **Succeeds**; remove the conditional ADR trigger from §0.
2. **Demote the fallback SQL to an appendix or delete it.** It needs only `SELECT` + column-scoped `UPDATE`, so nothing stops an implementer under pressure from picking it.
3. **Keep the two artifacts the fallback branch would have required, regardless of branch:** the 8-thread `CyclicBarrier` concurrent-revocation test (already mandated in §11.3), and **the zero-active-admins detection control** — the only thing that catches an AC5 bypass from *any* cause (a bug, a future grant change, a `roles.name` casing mismatch, a raw SQL path). Adopt it unconditionally; `RbacDbPrivilegeHealthIndicator` is the pattern to copy.

**Residual after mitigation:** none from the fallback. The zero-admins control reduces the residual on the whole AC5 family, including T-E9.

---

### [Low] T-D5 — Authenticated assign/revoke churn grows two append-only tables with no application-level remediation path; US-009 T-D2's forwarded rate-limiting obligation is declined without reconciliation

**Component:** C3/C5/C7. **STRIDE:** Denial of Service (storage amplification). **OWASP:** A04.

Res. 10 puts rate limiting out of scope. **US-009's threat model forwarded this as a P1 US-012 obligation** (T-D2: "US-012 assign/revoke endpoints must be **authenticated + rate-limited**"). The authenticated half is satisfied; the rate-limited half is declined. A forwarded threat-model obligation closed as out-of-scope should be an explicit recorded reconciliation — that is how cross-story security debt disappears.

**The risk is Low but has an unusual property.** A `user:write` holder looping assign→revoke→assign writes per iteration: one new `user_roles` row (re-assignment after revocation is a plain INSERT, since `active_key` is NULL for revoked rows), one `revoked_at` UPDATE, two `auth_events` rows. Both tables are **append-only by construction** — `user_roles` has a `BEFORE DELETE` trigger *and* no `DELETE` grant; `auth_events` has both triggers *and* no `DELETE` grant. So **there is no application-level path to reclaim the space**; remediation requires a DBA with superuser rights to drop a trigger. Intended (audit preservation), but the abuse is unbounded-and-irreversible rather than unbounded-and-cleanable.

Bounding: the actor must hold `user:write`, which today means they already hold `TENANT_ADMIN` — insider vandalism, not escalation. Rows are small and `active_key`'s unique index tolerates unlimited NULLs without write amplification.

**Assessment: accepted residual — rate limiting is not warranted here.** Cross-cutting throttling for an admin-only endpoint reachable solely by the tenant's most privileged principal is disproportionate.

**Required mitigation (cheap, replaces the declined control):**
1. **Reconcile explicitly** in §12: US-009 T-D2's rate-limiting obligation is **consciously declined for US-012**, with the reasoning above.
2. **Substitute detection for prevention.** `http.server.requests{uri="/api/v1/users/{userId}/roles"}` exists for free (§9.1). Add one §9.3 ticket-severity alert on anomalous sustained rate on these three URIs — an admin endpoint at sustained high RPS is either abuse or a broken client, and both want a ticket. Zero new instrumentation.
3. Forward to O-8 that if US-015 grants `user:write` to non-admin custom roles (T-E9), the abuse population widens and this should be revisited.

---

### [Low] T-E9 — `user:write` alone suffices to **revoke** `TENANT_ADMIN`: AC5 stops total lockout but nothing stops a non-admin from removing one of several admins. Unreachable today; live the day US-015 ships

**Component:** C2. **STRIDE:** Elevation of Privilege (via de-privileging others) / Denial of Service. **OWASP:** A01, A04.

This is the design's O-5.

**Classification.** Primarily **Elevation of Privilege**, not merely DoS. The asymmetry: **AC8 gates *granting* `TENANT_ADMIN` on holding an active `TENANT_ADMIN`; nothing gates *revoking* it beyond generic `user:write`.** An attacker with a `user:write`-bearing custom role gains no admin, but can **remove every admin except one** (AC5 blocks only the last). In a two-admin tenant that reduces the tenant to a single point of administrative control, which the attacker may then target — a *staged* escalation. Secondary **Repudiation** dimension: US-009 T-R1 named "de-privileging an account before an attack" as the canonical revocation abuse, and `user_roles` records no `revoked_by` column at all — attribution exists **only** in `auth_events`, precisely the record T-R3 shows can be silently lost. The two findings compound.

**Reachability today: none — verified.** `V5`'s seed grants `user:write` exclusively to `TENANT_ADMIN` (`MEMBER` → `user:read` only). US-015 (`role:write`, `POST /api/v1/roles/{id}/permissions`) lets a tenant mint a custom role carrying `user:write` — at which point the threat is live and no AC covers it.

**Decision: record as an accepted deferred risk (US-015), plus one small US-012 change.**

A full AC8-symmetric check in US-012 is not justified: it is unreachable, and the natural implementation would be dead code with no reachable test path — worse than absent code, because it *looks* like a shipped control. **But US-012 should not ship the asymmetry silently**, because US-012 is where a reader looks to understand the model:

**Required mitigation:**
1. **(US-012, documentation — do this)** Javadoc on `RoleAssignmentService.revoke` recording that revocation of `TENANT_ADMIN` is gated **only** by `user:write` + AC5's last-admin guard; that this is asymmetric with AC8 by conscious decision; that it is unreachable while `user:write` is `TENANT_ADMIN`-exclusive; and that **US-015 must add the symmetric check as a prerequisite of enabling custom roles with `user:write`.** A design decision that becomes a vulnerability on another story's merge must be discoverable from the code it lives in.
2. **(US-015, blocking prerequisite — flag to PM now)** A new AC symmetric to AC8: *only an active `TENANT_ADMIN` may revoke a `TENANT_ADMIN` assignment.* This must be an **entry criterion for US-015**, not a follow-up, because US-015's merge makes T-E9 exploitable. Same treatment US-009 gave T-E1 when it forwarded a hard AC to US-012 — and that precedent is why AC8 exists at all.
3. The zero-active-admins detection control (T-D4) partially covers the complete-removal case.

**Residual:** None today. Medium from the moment US-015 ships without the symmetric AC — hence the entry-criterion framing.

---

### [Low–Medium] T-E10 — D9 and R-10 are **structural** controls: they prevent a class of import regression but do not prevent an `Authentication` from reaching the service, and two concrete laundering paths keep ArchUnit green

**Component:** C8. **STRIDE:** Elevation of Privilege. **OWASP:** A04, A05.

**What they genuinely prevent (verified, and real value):**
- `domain_and_application_must_not_depend_on_spring_security` — `noClasses().that().resideInAnyPackage("..domain..", "..application..").should().dependOnClassesThat().resideInAnyPackage("org.springframework.security..")`. `com.example.nexus.rbac.application` matches, so `RoleAssignmentService` genuinely cannot declare an `Authentication` parameter, call `AuthenticatedRequestDetails.fromAuthentication(Authentication, String)`, or reference `@PreAuthorize`. This forces `RoleChangeActor` and delivers the real property: **authorization semantics execute on plain values whose provenance is fixed at a single controller line**, so there is exactly one place to audit for "where did `tenantId` come from".
- `rbac_must_not_depend_on_identity` (D9) — converts a Gate-1 decision and US-010's drifting code-review finding into a build failure. Verified currently green (`rbac` has zero `identity` imports in `src/main`; the `RedisRateLimitStore` Javadoc `{@link}` is not a bytecode dependency). Genuine value at near-zero cost; also correctly forces D13.

**What they do not prevent — three concrete bypass paths:**

1. **`java.security.Principal` laundering.** `org.springframework.security.core.Authentication` **extends `java.security.Principal`**, a JDK type. A controller declaring `roleAssignmentService.assign(Principal principal, …)` passes the live `UsernamePasswordAuthenticationToken` into the application layer with **ArchUnit fully green** — the declared type matches no banned package. Not hypothetical: Spring MVC injects `java.security.Principal` into handler methods as a first-class supported parameter type.
2. **`Map` laundering.** `authentication.getDetails()` returns `Object`, concretely a `Map<String, Object>`. Passing that map — or `AuthenticatedRequestDetails`, which lives in `common.security` and is therefore **also not in a banned package for this rule** — keeps ArchUnit green while moving raw authentication-detail handling inward. The design's controller use of `fromAuthentication` is correct; the risk is a future refactor pushing the type in.
3. **`common` laundering for D9.** The rule bans `..identity..` only. A shared helper placed in `common.*` and consumed by both contexts recreates the coupling D9 exists to prevent, with the rule green.

**And the fundamental limit — the actual answer:** ArchUnit constrains **types**, never **values**. No rule can detect a controller bug passing the *wrong* plain `UUID` — the classic instance being `RoleChangeActor(UUID.fromString(userId /* the PATH VARIABLE */), tenantId)` instead of the principal, which would make every caller able to act as the user they target, sailing through both rules, the compiler, and any test that happens to use the same user as actor and target. **That specific bug is the one thing standing between this design and a total AC8/AC4 bypass, and no architectural control covers it.**

**Required mitigation:**
1. **(DESIGN CHANGE — small, recommended)** Constrain the *signature*: state in §4.2 that `RoleAssignmentService`'s public methods accept **only** `RoleChangeActor`, `UUID`, and `RequestContext` — no `Principal`, no `Map`, no `AuthenticatedRequestDetails`. Optionally add an ArchUnit rule that no `..rbac.application..` method declares a `java.security.Principal` or `java.util.Map` parameter. Closes paths 1 and 2 mechanically.
2. **(Test, mandatory)** `UserRoleControllerTest` must include the **provenance** assertion no ArchUnit rule can express: a request where the path `userId` **differs** from the JWT `sub` must produce an actor whose `userId` is the **JWT `sub`**, with the service invoked with `targetUserId` = the path value. Direct analogue of US-011 T-02's required provenance contract test, and the only automated control for the value-level bug. §11.2 currently says "Principal unwrapping; `RoleChangeActor` construction" — make the differing-ids case explicit.
3. **(Test, mandatory)** A negative case asserting the persisted `assignedBy` equals the JWT `sub` and **not** any request-supplied value (see T-S3).
4. Extend D9's `because(...)` clause to name the `common`-laundering path.

**Residual after mitigation:** Low.

---

### [Low] T-S3 — `assigned_by` / actor identity cannot be spoofed from client input: verified end-to-end, and the DB backstop is now empirically proven (closes US-009 T-S2)

**Component:** C1→C2→C3→C7. **STRIDE:** Spoofing / Tampering. **OWASP:** A01, A08.

**Traced all four hops plus the DB layer. The claim holds, and it is stronger than the design states.**

| Hop | Mechanism | Verdict |
|---|---|---|
| **HTTP → DTO** | `record AssignRoleRequest(String roleId)` — one field. **No** `assignedBy`, no `tenantId` to populate. §4.9's framing is exactly right: *"enforced by **not modelling the field**, which is stronger than validating it away."* An absent field cannot be bound, cannot be forgotten in a validator, and cannot be re-added without a visible DTO change. | ✅ |
| *(caveat)* | `fail-on-unknown-properties` is `false` platform-wide (verified as configured nowhere), so `{"roleId":"…","assignedBy":"…"}` is **silently ignored** rather than rejected. Safe because the field does not exist — the design's "risk here is nil" is correct. Noted only because a *future* author adding an `assignedBy` field gets silent binding rather than a 400. | ✅ (note) |
| **Controller → actor** | `actor = RoleChangeActor((String) authentication.getPrincipal(), UUID.fromString(details.tenantId))`, `details` from `AuthenticatedRequestDetails.fromAuthentication`. **Never the path, never the body** (§4.1, explicit). `tenantId` provenance is the JWT claim written by `JwtRs256Service.issue` from `user.getTenantId()` (US-011 T-02's verified invariant). | ✅ |
| **Service → port** | `assign(actor, targetUserId, roleId, ctx)` → `port.assign(targetUserId, roleId, actor.tenantId(), actor.userId())`. R-10's rule guarantees no `Authentication` is present to misuse. | ✅ |
| **Port → entity** | `new UserRole(idGenerator.newId(), userId, roleId, tenantId, assignedBy)` — the only constructor. | ✅ (see risk note) |
| **Entity → DB** | **Empirically proven backstop (§0.2):** `nexus_app` holds `UPDATE (revoked_at)` only, so **post-insert tampering of `assigned_by` is denied by the database** (`ERROR 1143 (42000)`). With the `BEFORE DELETE` trigger and no `DELETE` grant, an inserted attribution is **immutable and undeletable via the application credential**. | ✅ **proven** |
| **Audit** | `AuthEvent.userId` = target (matching identity's `LOCKOUT` convention); `tenantId` JWT-sourced per `AuthEvent.withTenantId`'s Javadoc; actor in `metadata.assignedBy`/`revokedBy`. Satisfies US-009 T-R1. | ✅ |

**This closes US-009 T-S2 and T-R1**, upgrading T-S2's mitigation from "server-side population is a US-012 obligation, not enforceable in schema-only US-009" to "populated from the principal **and** rendered immutable by a column-scoped grant, both verified".

**One residual worth a test, not a design change.** `UserRole`'s constructor is five positional `UUID`s; the port method four more. A transposition (`assignedBy` ↔ `userId`, or `targetUserId` ↔ `actor.userId()`) compiles cleanly, passes any test reusing the same UUID for actor and target, and produces a **silently forged attribution** — precisely US-009 T-S2's harm, arrived at by accident. The type system provides zero protection.

**Required mitigation (test, mandatory):** `RoleAssignmentIT` must assert, with **four distinct** UUIDs (actor ≠ target ≠ role ≠ tenant), that the persisted row has `user_id` = target, `assigned_by` = the JWT `sub`, `tenant_id` = the JWT `tenant_id`; and `RoleAssignmentAuditIT` must assert `metadata.assignedBy` = the JWT `sub` while `auth_events.user_id` = the target. §11.3 does not currently pin distinctness.

**Residual:** Low.

---

### [Low] T-S4 — An unparseable principal fails **open into a 500** rather than closed into a 403, unlike the tenant parse on the adjacent line

**Component:** C1. **STRIDE:** Spoofing (fail-mode) / Information Disclosure. **OWASP:** A05, A07.

§4.1 specifies fail-closed for one of the two values it unwraps but not the other:
- `UUID.fromString(details.tenantId())` → *"fails closed to `InsufficientPermissionException(perm, DenialReason.MISSING_TENANT)`"* ✅
- `(String) authentication.getPrincipal()` → no handling specified. `UUID.fromString` on a non-UUID throws `IllegalArgumentException`; the cast throws `ClassCastException`. Verified `GlobalExceptionHandler` is a plain `@RestControllerAdvice` with no handler for either → **500 `INTERNAL_ERROR`**.

Same class as US-011 T-13 and as what D15 fixes for path/body UUIDs — the design fixes the *client-supplied* malformed-UUID path thoroughly and leaves the *principal* path unhandled.

**Attacker-reachability: none today.** The filter sets principal to the JWT `sub`; `issue()` always writes a UUID `sub`; an attacker cannot mint a signed token; `.anyRequest().authenticated()` plus `@RequiresPermission`'s details validation keep anonymous principals out. Latent robustness gap, not an exposure — hence Low.

**Why fix anyway:** (1) ~2 lines in the helper that already handles the tenant; (2) it defends the platform's most sensitive endpoints against 500s, which §8.6 opens by caring about; (3) a 500 here is *less* safe in one concrete way — `handleUnexpected` logs at ERROR **with a full stack trace**, whereas the fail-closed path logs a structured WARN, so an unexpected principal shape produces noisier, higher-severity output than the equivalent tenant problem, inverting the intended signal hierarchy.

**Required mitigation (DESIGN CHANGE — trivial):** extend §4.1's fail-closed rule to the principal — a null / non-`String` / non-UUID principal throws `InsufficientPermissionException(requiredPermission, DenialReason.MALFORMED_AUTHENTICATION)`, reusing an **existing** constant (no `common` change beyond D5's two). Add the case to §11.2's `UserRoleControllerTest` alongside the planned `MISSING_TENANT` case.

---

### [Low] T-T7 — `DuplicateRoleAssignmentException`'s message is constructed while holding a `DataIntegrityViolationException`, and `ConflictException`'s message is echoed verbatim to the client

**Component:** C3/C9. **STRIDE:** Information Disclosure. **OWASP:** A01, A05.

Verified: `handleConflict` returns `problem(HttpStatus.CONFLICT, e.code(), e.getMessage())` — the message becomes the RFC-7807 `detail` sent to the caller. §5.2's insert path is `catch (DataIntegrityViolationException) → throw new DuplicateRoleAssignmentException(...)`. The natural implementation — `new DuplicateRoleAssignmentException(e.getMessage())` — would echo MySQL's constraint text (`Duplicate entry '…' for key 'user_roles.uq_user_role_active'`), leaking the constraint name, the index name, and a hex fragment of `active_key` — which is `CONCAT(user_id, role_id)`, i.e. **the raw target user and role ids**.

Exactly the obligation US-009 forwarded as T-I3. §8.4 asserts the outcome ("Neither leaks internals — no user ids, no counts, no SQL") but never pins the literal, and the translation happens in the adapter, far from §8.4's table.

**Required mitigation (test + implementation constraint):**
1. Pin both messages as **static literals** in the exception classes. D4 already argues for dedicated classes partly to keep "the code literal and message in one place" — extend that to forbidding a caller-supplied message; give `DuplicateRoleAssignmentException` a no-arg or ids-only constructor that formats nothing from the cause.
2. `DuplicateRoleAssignmentExceptionTest` (already planned for the 0.90 gate) asserts `getMessage()` equals the fixed literal; `RoleAssignmentIT`'s duplicate-`POST` case asserts the 409 body's `detail` contains **neither** `uq_user_role_active` **nor** any request UUID. Same for the `SQLSTATE 45000` trigger path if reachable.
3. Record T-I3 as **closed by US-012**.

---

### [Low] T-E11 — R-2's "silently unenforced `@RequiresPermission`" is correctly mitigated, but the design's stated *reason* is only partly right — which is why the per-endpoint negative control is the real control

**Component:** C1/C8. **STRIDE:** Elevation of Privilege. **OWASP:** A01, A05.

§4.1 mandates "Every handler is `public` and non-`final` (R-2)", citing `UserProfileController#me()` (verified: package-private, and verified to carry no `@RequiresPermission` today) and `RequiresPermission`'s Javadoc: *"Spring AOP cannot proxy `final` or `private` methods…"*

**The mandate is right and is endorsed.** The *reason* is imprecise: the Javadoc's list is `final` and `private`, but the cited template is **package-private** — a different case. Spring Boot defaults to CGLIB, and a CGLIB subclass generated in the same package **can** override a package-private method, so such a handler may well be enforced depending on proxy strategy, package, and classloader. This cuts **both ways**: a developer reasoning "package-private is never enforced" may draw the wrong conclusion — and more importantly **nobody should be reasoning about it at all.**

**Assessment: mitigated as designed, for the right operational reason.** The design identifies the only trustworthy control: *"A negative-control 403 test **per endpoint** is the only mechanism that catches a regression here."* Correct — an empirical assertion is agnostic to proxy semantics. The **positive** control matters equally (US-011 T-10's reasoning): a pair proving reachability *with* the permission and 403 *without* distinguishes "genuinely enforced" from "always fail-closed for an unrelated reason" (e.g. a missing `AnnotationTemplateExpressionDefaults` bean, which degrades to a literal `{value}` and denies everyone).

**Required mitigation (test emphasis, no design change):**
1. Make the **pair** non-negotiable per endpoint — 403 without, 2xx with, ×3. §11.3 specifies the negative; make the positive explicit as a *paired* assertion in `RoleAssignmentSecurityIT`.
2. Soften §4.1's parenthetical: the accurate statement is "visibility-dependent proxying makes enforcement non-obvious, therefore never reason about it; assert it per endpoint."
3. **D11 interaction:** with the flag absent the controller bean does not exist and **every** request 404s, so a negative-control test in a context missing `@ActiveProfiles("test")` would "pass" for entirely the wrong reason. §10.1 flags the 404 trap; the security tests must assert **403**, never merely "not 2xx".

---

### [Low] T-E12 — The `nexus_app` privilege boundary is now a **verified** defense-in-depth control rather than an assumed one; the residual is that nothing detects it being absent

**Component:** C7. **STRIDE:** Tampering / Elevation of Privilege. **OWASP:** A05, A08.

**§0.2 changes the framing: the control is verified directly, so it is proven at the semantic level.** What remains is a *provisioning and detection* gap — narrower than the design's "unverified" framing.

**Now proven:** column-scoped `UPDATE (revoked_at)` permits the single-column revoke (R-1 closed by D2), **denies** every other column including `user_id`, `tenant_id`, `assigned_by` (the T-S3 immutability backstop is real), and **permits** `SELECT … FOR UPDATE` (R-4 closed).

**The residual, precisely:**
1. **Nothing verifies the grants were ever applied.** `02-grants-post-schema.sql` runs as an `afterMigrate.sql` Flyway callback from a one-shot compose service (verified in the header). If skipped, or if an environment provisions differently, the app may run as a superuser with **no** column scoping — and the T-S3 immutability argument evaporates silently.
2. **`RbacDbPrivilegeHealthIndicator` cannot detect this.** Verified: it checks only *over*-grant (`DELETE` on `user_roles`, `ALL PRIVILEGES`, `root`). It has **no positive assertion** that the intended grants are present and column-scoped. A missing `UPDATE (revoked_at)` is loud at first revoke; the *inverse* — **table-scoped** `UPDATE` instead of column-scoped — is **silent, reports UP, and is exactly the state that re-opens US-009 T-T1**, which ADR-0015 D7 tightened the grant specifically to close.
3. **Prod-connects-as-`root`** remains the US-008 T-E2 / US-009 T-E3 residual. The indicator *does* catch that (`isRoot`) — genuine coverage, provided someone watches `/actuator/health`'s aggregate, from which it is deliberately not excluded.
4. **Every `*IT` connects as the Testcontainers superuser**, so CI structurally cannot exercise this except via a raw-`DriverManager` test.

**Required mitigation:**
1. **`UserRolesPrivilegeIT` stays mandatory** — role changes from *discovery* to *regression*. Keep all four §5.3 assertions and **add a fifth**: assert the grant is **column-scoped** — `SHOW GRANTS` matches `UPDATE (\`revoked_at\`)` and *not* a bare table-level `UPDATE` on `user_roles`. This protects ADR-0015 D7 from silent reversal and is not in §5.3's current list (assertion 4 says the grant set "matches the expected set" — make it explicit about column scope). The denial is `ERROR 1143`, SQLState `42000`.
2. **(DESIGN CHANGE — recommended, small)** Extend `RbacDbPrivilegeHealthIndicator` with a **positive** check: DOWN (or at minimum WARN) if `information_schema.COLUMN_PRIVILEGES` lacks `UPDATE` on `user_roles.revoked_at` for the current user, **or** if `TABLE_PRIVILEGES` shows a table-scoped `UPDATE` on `user_roles`. It already reads both views for the DELETE check — a few lines in an existing class, and the only runtime control that catches a reverted grant in production.
3. **Staging gate** — §10.2 step 2 ("Enable in staging **with the app connected as `nexus_app`**") is the single most valuable item in the rollout plan. Keep it as a hard evidence gate; add "`/actuator/health` shows `rbacDbPrivilege: UP` **and** the new positive grant check passes" to its exit criteria.

**Residual after mitigation:** Low. **Without mitigation 2:** Medium — the silent table-scope reversal reverts US-009 T-T1 with no signal.

---

### [Low] T-E13 — `RbacAuthEventAdapter`'s injected `ObjectMapper` is ambiguous on Spring Boot 4: two Jackson majors are on the classpath, and the only in-repo precedent uses the one that is **not** a Spring bean

**Component:** C5. **STRIDE:** Elevation of Privilege (via fail-mode) / availability. **OWASP:** A05, A06.

`./mvnw dependency:tree` (198 artifacts) shows **both** lineages:

| Artifact | Version | Reached via |
|---|---|---|
| `tools.jackson.core:jackson-databind` (**Jackson 3**) | 3.1.4 | `spring-boot-starter-webmvc` → `spring-boot-starter-jackson` → `spring-boot-jackson`; also `flyway-core` |
| `com.fasterxml.jackson.core:jackson-databind` (**Jackson 2**) | 2.21.4 | `io.jsonwebtoken:jjwt-jackson`, `springdoc-openapi-starter-webmvc-ui` |

Spring Boot **4.1.0** (verified in `pom.xml`) auto-configures the Jackson **3** `tools.jackson.databind.ObjectMapper` as the managed bean. §4.8's constructor — `RbacAuthEventAdapter(SecureEventService, UuidGenerator, ObjectMapper)` — does not say which. The **only existing `ObjectMapper` usage in the codebase** (`LoginRateLimitFilter`, verified) imports `com.fasterxml.jackson.databind.ObjectMapper` and does `new ObjectMapper()` — Jackson **2**, self-instantiated, deliberately not injected. Grep confirms **zero** `tools.jackson` references in `src/`.

So the most likely implementation — copy the in-repo precedent's import, then constructor-inject it as §4.8 says — asks Spring for a bean **that does not exist**, and the context fails to start.

**Security relevance.** Direct consequence is fail-fast, caught by the first `*IT` — hence Low. It matters for two second-order reasons: (1) an implementer may "fix" it by instantiating `new ObjectMapper()` inline, copying the precedent, putting **the security-critical escaping mechanism of T-T5 on an unmanaged, unconfigured, undocumented-version object** — the exact "two copies diverge later" failure mode D6 exists to avoid; (2) the two majors differ in lone-surrogate and non-ASCII write behaviour, which is precisely what §11.2's adversarial tests probe, so a test written against one and shipped against the other proves nothing.

**Required mitigation (DESIGN CLARIFICATION — one line, before `/breakdown`):**
1. State the **fully-qualified** type in §4.8: `tools.jackson.databind.ObjectMapper` (Jackson 3, the Spring-managed bean), **injected, not instantiated**, with an explicit note that `LoginRateLimitFilter`'s `new ObjectMapper()` is **not** the pattern to copy.
2. `RbacAuthEventAdapterTest` must exercise the **same** `ObjectMapper` type the adapter receives in production, so the adversarial-`roleName` assertions are meaningful.
3. Record for O-8 that two Jackson majors are co-resident — a normal Boot-4 transition state, not a US-012 defect, but a source of this ambiguity for every future story.

---

## 4. Threats considered and found adequately mitigated (no action)

| Threat | STRIDE | Why adequate (verified) |
|---|---|---|
| Forged / tampered / `permissions`-injected JWT | S/T | RS256 verify + alg pinning reject tamper before any US-012 code runs → 401 `AUTH_003`. Reviewed under US-011 T-01; unchanged. |
| Cache-invalidation failure leaves stale permissions | T/E | **Verified non-load-bearing.** `RoleResolutionService.resolve` re-reads `findActiveRoleNames` on **every** call and treats a cached entry whose role set differs as stale. A US-012 assign/revoke *always* changes the role set, so it is reflected on the very next login/refresh **even with Redis down and no eviction at all**. §6.5 is accurate; eviction is a latency optimisation. `evict` also catches every exception and fails open (verified). |
| Duplicate-assignment TOCTOU | T | `uq_user_role_active` on the `active_key` generated column is the true guard; M2 is only the clean-error path; the adapter translates to 409 `RBAC_004`. One winner, no duplicate row, no 500. |
| Double-revoke / lost race on `DELETE` | T | `UPDATE … WHERE id = :id AND revoked_at IS NULL` + affected-row count is the guard absent `@Version` (verified the entity has none, so the reasoning is necessary). `1` ⇒ 204, `0` ⇒ 404; never two 204s. |
| `revoked_at < assigned_at` → 500 (R-8) | D/I | `FUNCTION('now', 6)` sets it DB-side: one clock, no skew. **Verified the trap is real** — `CURRENT_TIMESTAMP` truncates to seconds, which would *cause* `ERROR 3819`, and 3819 is genuinely untranslated → 500. Both mandated verifications (`revoked_at >= assigned_at`, `MICROSECOND(revoked_at) <> 0`) are correctly specified. |
| Malformed path/body UUID → 500 (R-12) | D/I | D15: `String` + `@Pattern` / a helper throwing `FieldValidationException`; `handleFieldValidation` and `handleBodyValidation` both verified present → 400 with `details[]`, zero new handler code. The diagnosis (incl. that `HandlerMethodValidationException` is also unhandled) is correct. |
| SpEL / JPQL / SQL injection | T | `@RequiresPermission` values are compile-time constants (no request input in SpEL). M1–M6 are parameterised JPQL with `@Param`; the JPQL-over-native rationale (auto-applied `UuidV7Converter`) verified against the existing repository. No string-concatenated queries. **No injection.** |
| Log injection (CRLF) via `roleName` | T | §9.2 mandates SLF4J `addKeyValue("roleName", …)`, never concatenation — the correct control per `observability-standards.md`. `roleName` is the only tenant-controlled string (≤64 chars); `userAgent` is capped at 512 and not logged by US-012. |
| R-9: `TENANT_ADMIN` by hardcoded seeded UUID | E | §5.2 resolves it as *the role the request names*, after verifying `role.tenantId == actor.tenantId` **and** `equalsIgnoreCase(role.getName())`, then binds that `role.getId()` to M1/M5 — structurally cannot resolve another tenant's admin role. The `equalsIgnoreCase` requirement is a genuine catch (`utf8mb4_0900_ai_ci` makes `uq_roles_tenant_name` case-insensitive, so a row may be stored `Tenant_Admin` and a case-sensitive compare would silently disable **both** AC5 and AC8); §11.2 mandates the mixed-case test. |
| Feature flag (D11) fail-mode | E/D | Flag absent/false ⇒ bean unregistered ⇒ 404. **Fails closed.** Unauthenticated callers get 401 at the filter chain, so flag state is not disclosed pre-auth. Overriding the story's "Feature flag required: No" is right for the platform's only control on a Critical threat, and §10.1's two traps (`@ActiveProfiles("test")`; flag in profile YAML not `DynamicPropertyRegistrar`, per the known Boot-4 precedence gotcha) are correctly identified. |
| D13 `IdGenerator` duplication | T/A02 | `UuidV7Generator` is a one-line `UuidCreator.getTimeOrderedEpoch()` (ADR-0005, `SecureRandom`-backed); the rbac-local copy is one line behind an interface. `user_roles.id` is never exposed in any DTO and is not an authorization input, so time-ordering creates no enumeration surface. Low hygiene risk only (drift), bounded by O-9. **No crypto finding.** |
| D5 `DenialReason` additions | E/A09 | Purely additive; consumed only by the exception and the handler's `reason` field/tag; no dispatch change; cardinality bounded at 5. **A security *improvement*** — the mechanism by which AC8 attempts become separately alertable (`nexus_rbac_self_escalation_attempt`, page). O-3's grep task is the right precaution. |
| D12 `nexus.domain.conflict{code}` | A09 | Closes a real gap: verified `handleConflict` logs **DEBUG with no metric**, so `RBAC_002` would be invisible at production log levels. Generic, code-tagged, bounded cardinality. |
| No new migration / no `UserRole` change | A08 | Verified `V5` carries everything; verified `assignedAt` is `insertable=false, updatable=false` with **no** `@Generated`, so §5.4 is exactly right — an *entity* re-read returns the session's instance with a null `assignedAt`; only the M4a **projection** reads through. `ddl-auto=validate` stays green. |
| `auth_events` append-only invariants | R/A08 | Verified both `trg_auth_events_no_update` and `trg_auth_events_no_delete` exist, and `nexus_app` holds only `INSERT, SELECT`. New `VARCHAR(64)` event-type values need no DDL. Records, once written, are immutable via the app credential. (Their *being written* is T-R3.) |

**A06 (Vulnerable & Outdated Components) — scans run.**
- **Backend:** `./mvnw dependency:tree` executed (198 artifacts). US-012 introduces **zero** new dependencies — `ObjectMapper` (via `spring-boot-starter-webmvc`), `UuidCreator` (`uuid-creator:6.1.1`), and Spring Data JPA locking are all present. Notable versions: Boot 4.1.0, Spring Framework 7.0.8, Spring Security 7.1.0, Hibernate 7.4.1, `mysql-connector-j` 9.7.0, jjwt 0.12.6. The one observation is the **dual Jackson major** (T-E13) — a normal Boot-4 transition state, not a vulnerability.
- **Frontend:** `npm audit` executed — **14 advisories (1 critical, 4 high, 6 moderate, 3 low)**, all in **dev/build tooling** (`@angular/cli`, `angular-eslint`, `@babel/core`, `esbuild`, `postcss`, `tar`, `brace-expansion`, `immutable`, `fast-uri`, `@hono/node-server`, `@modelcontextprotocol/sdk`). None are runtime dependencies shipped to the browser, and **US-012 changes zero frontend files**. **Pre-existing platform hygiene debt, out of scope for US-012** — recorded for O-8, not a finding against this design.
- A CVE-versus-version review of the *implemented* code belongs to the Phase-7 code audit (US-011's precedent); noted as a Phase-7 requirement.

---

## 5. Residual risk summary

| ID | Sev | Threat | Status / residual after recommended mitigations |
|---|---|---|---|
| **T-E8** | Medium | Tenant isolation on `GET` unspecified → silent `200 {"data":[]}` instead of 403 | **Needs design change.** Low once §3.3/§4.2 mandate `findTenantId` and the IT asserts 403/404, not 200-empty. |
| **T-R3** | Medium | Committed role change can lose its audit record silently, bypassing the retry buffer | **Needs design change.** Low with ERROR log + counter + page alert + pre-transaction JSON serialisation. AC7's "100%" must be restated. |
| **T-R4** | Medium | Role-change audit events in the drop-newest STANDARD lane with `LOGIN_FAILURE` floods | **Needs design change** (add to `PRIORITY`) or an explicit drop alert. Low either way. |
| **T-T6** | Medium | M3 returns a managed entity onto the write path → R-1 production-only footgun | **Needs design change.** Negligible once M3 returns a projection/id. |
| **T-E10** | Low–Medium | ArchUnit is structural; `Principal`/`Map`/`common` laundering stays green; no rule catches a value-level provenance bug | Low with a signature constraint + the mandatory differing-ids provenance test. |
| **T-I5** | Low–Medium | Any `user:read` holder (every `MEMBER`) can enumerate the admin roster + granter | **Decision needed.** Low under option (a)/(b). |
| **T-E7** | Low | REPEATABLE READ snapshot race lets a concurrently-revoked admin's in-flight request still grant `TENANT_ADMIN` | Negligible once M5 is a current/locking read (now proven cheap). The ~15-min stale-JWT window — the substance of R-5 — **is** closed as designed. |
| **T-S4** | Low | Unparseable principal → 500 instead of fail-closed 403 | Negligible after extending §4.1's rule to the principal. Not attacker-reachable today. |
| **T-E13** | Low | Ambiguous `ObjectMapper` (Boot 4 = Jackson 3; in-repo precedent is Jackson 2) | Negligible once the FQN is pinned. |
| **T-T7** | Low | `RBAC_004` message may echo constraint/index names and target ids | Negligible with static literals + body-content assertion. Discharges US-009 T-I3. |
| **T-E12** | Low | Grants may never be applied, or silently revert to table scope, undetected | Semantics **proven**. Low with the column-scope IT assertion; Medium if the positive health check is declined. |
| **T-T5** | Low | `role_name` JSON injection | **Mitigated by D6.** Residual: a lone-surrogate name could fail the audit insert (→ T-R3); US-015 should constrain role-name characters. |
| **T-I4** | Low | Cross-tenant existence oracle (403 vs 404) | **Accepted** — decision endorsed; two justification corrections required. |
| **T-D5** | Low | Append-only churn, no application-level reclamation; US-009 T-D2's rate-limit obligation declined | **Accepted** with explicit reconciliation + a rate-anomaly alert. |
| **T-E9** | Low (today) | `user:write` alone can revoke `TENANT_ADMIN` | **Accepted as deferred.** Becomes **Medium** the day US-015 ships without the symmetric AC ⇒ **US-015 entry criterion** + US-012 Javadoc. |
| **T-S3** | Low | `assigned_by` / actor spoofing | **Mitigated end-to-end and proven immutable at the DB.** Closes US-009 T-S2/T-R1. Residual: positional-`UUID` transposition, closed by the distinct-UUID test. |
| **T-D3** | Low | AC5 lock-scope DoS (R-3) | **Mitigated — empirically verified.** No change. |
| **T-D4** | Low | §5.3 fallback's unclosed TOCTOU | **Moot** — R-4 resolved favourably. Remove the fallback; adopt zero-active-admins detection unconditionally. |
| **T-E11** | Low | `@RequiresPermission` silently unenforced (R-2) | Mitigated by the mandate; bounded by mandatory **paired** controls per endpoint. |
| *inherited* | — | US-011 **T-02** tenant-provenance invariant | **Unchanged and still load-bearing.** Guarded by `only_jwtAuthenticationFilter_sets_authentication_details` (verified present). US-012 adds no second producer. |

---

## 6. Verdict

### APPROVE WITH CONDITIONS

**This is a strong design** — the most thoroughly reasoned of the three RBAC threat models reviewed to date, and its central claims survive adversarial verification rather than merely reading well:

- **AC8/R-5 is correctly mitigated.** §3.1 genuinely calls M5 (a live DB read), not the JWT `roles[]` claim; the port Javadoc, query, and mandated revoked-token test all reinforce it. The ~15-minute stale-claim escalation window — the substance of R-5 and the live half of US-009 T-E1 — **is closed**.
- **AC5's lock scope is correct, and it was proven**: `type=ref` on the `role_id` FK index, unrelated tenants provably unblocked, in-range revocations provably serialised. The R-3 platform-availability hazard is real and deliberately avoided.
- **`assigned_by` cannot be spoofed from client input**, verified through all four hops, and the column-scoped grant makes attribution **immutable at rest** — confirmed against live MySQL. US-009 T-S2 and T-R1 are discharged.
- **D6's Jackson decision is right**, and the deviation from the impact analysis's "replicate `jsonEscape`" instruction should be upheld.
- **D2 defeats R-1**, and **R-4 — the design's headline unknown — resolves favourably**, established empirically. D1 ships as designed; no ADR fires; the fallback is unnecessary.
- **No Blocker- or Critical-severity findings. Nothing here is exploitable as written by an external attacker.** Both Critical-rated properties (AC8 escalation, AC4 isolation) are substantively implemented.

The conditions are the gap between "reasoned correctly" and "specified so it cannot be built wrong". Most are small; two are important.

### (c) Threats that need the architect to revise the design before `/breakdown` proceeds

Ranked. Items 1–2 are the ones to hold the gate on; 3–8 should land in the same revision pass.

1. **T-E8 — Specify the `findTenantId` + tenant-equality check on `GET`.** The most important item. As written, the natural implementation returns `200 {"data":[]}` for a cross-tenant target, violating §8.4 row 5 and Res. 6, and **silently destroying** the WARN + `CROSS_TENANT_TARGET` metric that §8.5 itself argues is worth more than closing the existence oracle.
2. **T-R3 — Make audit-write loss loud, and restate AC7.** The retry-buffer durability §6.4 claims is bypassed because the failure lands at the `REQUIRES_NEW` **commit** boundary, outside `JpaAuthEventAdapter`'s catch — `enqueue` is never called, and the design's own catch-all turns a durable retry into a silent drop. Add an ERROR log with reconstruction fields, a counter, a **page** alert, and serialise the JSON before the transaction opens.
3. **T-T6 — Change M3 to return a projection/id, not a managed `UserRole`.** Extend the no-entities rule to everything reachable from `revoke`.
4. **T-R4 — Reconsider D10:** add `ROLE_ASSIGNED`/`ROLE_REVOKED` to `AuthEventType.PRIORITY`, or add a standard-lane drop alert.
5. **T-E7 — Make M5 a current (locking) read.** One annotation; §0.2 removes the privilege objection.
6. **T-S4 — Extend §4.1's fail-closed rule to the principal** (`MALFORMED_AUTHENTICATION`, an existing constant).
7. **T-E13 — Pin the `ObjectMapper` FQN** to `tools.jackson.databind.ObjectMapper`, injected not instantiated.
8. **§5.3 / O-1 — Fold in §0.2's empirical result:** resolve the decision tree to "Succeeds", drop the conditional ADR trigger, demote the fallback to an appendix, and adopt the **zero-active-admins detection control** unconditionally.

Also requiring an architect/PM decision, though not a design defect: **T-I5** — whether `GET`'s `assignedBy` (and other users' role lists) should be visible to every `user:read` holder. Recommendation: option (b), gate `assignedBy` on an active `TENANT_ADMIN`.

### (b) Threats the design explicitly and adequately accepts as residual risk with stated justification

- **T-I4** — the 403-vs-404 oracle (§8.5, §12). **Decision endorsed**; the "collapsing to 404 destroys the security signal" argument is decisive and its premise verified. Two justification corrections required; outcome unchanged.
- **Cache-invalidation failure** (Res. 9, §6.5) — accepted, and **verified genuinely benign** via the live-role fingerprint.
- **Unbounded `GET` list** (D7) — accepted; provably bounded, additive-pagination envelope, recorded revisit trigger.
- **No `Idempotency-Key`, no `fail-on-unknown-properties`** (§8.6) — correctly identified as pre-existing platform gaps with nil concrete risk here. On the O-8 backlog.
- **T-D5 / no rate limiting** (Res. 10) — accepted, **but the acceptance must explicitly reconcile US-009 T-D2's forwarded P1 obligation** and substitute a rate-anomaly alert.
- **T-E9** — accepted as **deferred**, unreachable today, with a **US-015 entry criterion** and a US-012 Javadoc note.

### (a) Threats fully mitigated by the design as written — no action

**T-T5** (JSON injection — D6) · **T-D3** (AC5 lock scope — empirically verified) · **T-S3** (actor provenance — verified end-to-end + proven DB immutability; one test added) · **T-E11** (R-2 — mandate + paired controls) · **R-8** (DB-side `NOW(6)`) · **R-9** (`TENANT_ADMIN` by name, `equalsIgnoreCase`) · **R-12/D15** (400 not 500, zero new handler code) · **R-11** (single projection join) · **R-7** (real cache keys; vacuous-test trap flagged) · **D11** (fail-closed flag) · **D5/D12** (observability — genuine security improvements) · **D13** (crypto/randomness reviewed clean) · injection, duplicate-TOCTOU, double-revoke, and the `auth_events` immutability chain.

### Gate 2 recommendation

**Approve for Gate 2 conditional on items 1–8** (1 and 2 before `/breakdown` decomposes tasks, since both change the component contract and the test list; 3–8 may land in the same revision). No finding invalidates the architecture, decision set D1–D15, or risk analysis — the conditions tighten specification and detection rather than redirect the approach. **O-1 is now closed empirically in the favourable direction, removing the story's only blocking pre-implementation unknown and shortening `/breakdown`.**

---

### Cross-references

- Design under review: `docs/features/US-012/03-design.md` (§0 D1–D15; §3.1–3.3; §4.1–4.9; §5.1–5.5; §6.1–6.5; §7.1–7.4; §8.1–8.7; §9; §10; §11; §12 O-1…O-9)
- Requirements: `docs/features/US-012/01-requirements.md` §11 Resolutions 1–11 · Impact: `docs/features/US-012/02-impact.md` §13 R-1…R-12, §14 items 1–12
- Story / epic: `docs/story/2-rbac/US-012.md` (AC1–AC8) · `docs/story/2-rbac/EPIC-002.md` (API table lines 144–146)
- Prior threat models: `docs/features/US-009/03b-threat-model.md` (T-E1, T-S2, T-R1, T-T1, T-I2, T-I3, T-D2, T-E3 — all forwarded obligations addressed above) · `docs/features/US-011/03b-threat-model.md` (T-02 inherited unchanged; T-09, T-10, T-13 patterns reused)
- ADRs: 0002, 0003, 0005, 0012, 0013, 0014, 0015 (D7 column-scoped `UPDATE`, D8), 0016
- Standards: `SECURITY.md` §3, §7, §10, §12 · `docs/observability-standards.md` · `docs/TESTING.md`
- Code verified this session: `common/security/{AuthenticatedRequestDetails,TenantAwarePermissionEvaluator,RequiresPermission}.java` · `common/web/GlobalExceptionHandler.java` · `common/domain/{RequestContext,ResourceNotFoundException,ConflictException}.java` · `rbac/domain/UserRole.java` · `rbac/application/RoleResolutionService.java` · `rbac/infrastructure/persistence/JpaUserRoleRepository.java` · `rbac/infrastructure/cache/RedisPermissionCacheAdapter.java` · `rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java` · `identity/domain/{AuthEvent,AuthEventType,UuidGenerator}.java` · `identity/application/service/SecureEventService.java` · `identity/application/port/out/AuthEventPort.java` · `identity/infrastructure/persistence/JpaAuthEventAdapter.java` · `identity/infrastructure/audit/AuthEventRetryBuffer.java` · `identity/infrastructure/crypto/UuidV7Generator.java` · `identity/interfaces/rest/UserProfileController.java` · `architecture/HexagonalArchitectureTest.java` · `db/migration/{V2__identity_schema,V5__rbac_schema}.sql` · `nexus-database/mysql/init/02-grants-post-schema.sql` · `pom.xml`
- Empirical verification: MySQL 8.4.10 (throwaway container, removed after use) reproducing `V5`'s `user_roles` shape and the exact `nexus_app` grant set — privilege semantics, lock scope, `EXPLAIN` plans, CHECK-constraint error codes, native-JSON injection behaviour. `./mvnw dependency:tree` (198 artifacts). `npm audit` (14 advisories, all dev tooling).

---

## Notes on process

- **Nothing in the repository was modified during this review.** Bash was used only for dependency scans and the MySQL verification; the probe container `nexus-r4-probe` was removed and no repo file was touched.
- **Design doc to revise:** `docs/features/US-012/03-design.md` — sections §0 (drop the conditional ADR trigger), §3.3 + §4.2 (T-E8), §4.1 (T-S4), §4.3 (T-T6), §4.8 (T-E13), §5.2 M5 (T-E7), §5.3 (§0.2 result, demote the fallback), §6.2 (T-R4), §6.4 + §9.2 + §9.3 (T-R3), §8.3 (T-I5 decision), §8.5 + §12 (T-I4 corrections, T-D5 reconciliation, T-E9 deferral).
- Two US-011-inherited items not re-litigated here, and which remain live trust dependencies: the T-02 tenant-provenance invariant, and T-03's deferred "every controller method annotated or explicitly opted out" ArchUnit rule — **US-012 is the first real protected controller, so T-03's Epic-3 entry criterion is now due.** Worth raising with the architect alongside the items above.
