# US-016 — STRIDE Threat Model: Gate role assignment/revocation by actual privileges, not role name

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md`. Feeds `/breakdown` (Phase 4) and discharges the inputs listed in that document's §14._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-016 · **Reviewer:** Application Security Engineer · **Status:** Gate 2 review — **conditional pass, 7 required changes (RC-8…RC-14); one (RC-8) must go back to the Architect before Gate 2 closes**

---

## 0. Scope, verification basis, and headline result

**Scope.** The design in `docs/features/US-016/03-design.md`: the unified privilege gate on `RoleAssignmentService.assign()` / `revoke()` (D1, D4, D5), the two new outbound-port reads M7/M8 (D3) and their adapter/repository implementation, the pinned lock order on `revoke()` (D2), the `DenialReason` reuse (D6), the `privileged`-tagged canary (D7), the new WARN marker (D8), ADR-0017 (D9), the no-new-flag rollout (D10), the unchanged error contract (D11), and the forward-only posture (§10.4). US-012's `RoleAssignmentService`, US-014's audit pipeline, and US-015's `RoleManagementService` / `RbacDangerousPermissions` / `role_permissions` grants are in scope **as trust dependencies** — and, in the case of US-015's `attachPermission`, as the other end of the one escalation path that survives this story.

**The load-bearing fact for this document.** The gate is entirely service-layer logic. `TenantAwarePermissionEvaluator` performs a flat `permissions[]` membership test and cannot express it; `nexus_app`'s grants on `user_roles` and `role_permissions` cannot express it either (`role_permissions` has `INSERT` + `DELETE` and no trigger — US-015 T-E15). There is no backstop above or below. Every Elevation finding below descends from that, exactly as it did in US-015.

### 0.1 Verification basis — code, schema and grants re-read this session, not trusted from the design doc

| Claim under test | Verified how | Result |
|---|---|---|
| `assign()` gates on the role **name** only; `revoke()` has no admin gate at all | `rbac/application/RoleAssignmentService.java:126-143` and `234-304` | **Confirmed.** `assign()`: `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())` at 126. `revoke()`: no admin check anywhere; only the actor-agnostic count guard at 252-269. The M-3 (83-109) and T-E9 (219-232) notes exist verbatim, including the "replace, do not delete" instruction |
| M5 is `PESSIMISTIC_READ` / `FOR SHARE`; M1 is `PESSIMISTIC_WRITE` / `FOR UPDATE` | `JpaUserRoleRepository` `lockActiveAdminAssignment` and `lockActiveAssignmentsByRole` | **Confirmed.** M1 drives off `roleId` (FK-indexed) with `tenantId` as a residual filter, by its own Javadoc; M5's predicate is M1's plus `userId` |
| **D4's containment premise** — `uq_roles_tenant_name` is `UNIQUE (tenant_id, name)` under `utf8mb4_0900_ai_ci` | `V5__rbac_schema.sql:30-40` | **Confirmed.** M8 can only return `role.getId()` when the name matches case-insensitively. D4's generalisation is sound |
| `RbacDangerousPermissions.contains` is case-insensitive and null-safe | `rbac/domain/RbacDangerousPermissions.java:13-24` | **Confirmed.** `NAMES = {role:write, user:write, tenant:write}`; `equalsIgnoreCase` per element, mirroring the column collation. D3's "route the comparison through the already-unit-tested domain type" argument holds |
| **`detachPermission` is NOT admin-gated** | `rbac/application/RoleManagementService.java` (`detachPermission`) — Javadoc: *"No AC11 gate — detaching a permission reduces privilege, a deliberate asymmetry with attachPermission"* | **Confirmed — and it refutes one sentence of D5/RES-2.** Detach requires `role:write` only. See T-E25 |
| **`attachPermission` does not look at, count, or report existing holders of the role** | `RoleManagementService.attachPermission` (full body read) | **Confirmed.** No holder lookup, no holder count in the audit event, no holder count on `nexus.rbac.dangerous_permission_granted{permission, tenantId}`. **This is the basis of T-E21** |
| `user_roles.active_key` is a **STORED** generated column, uniquely indexed | `V5__rbac_schema.sql:60-90` | **Confirmed.** `uq_user_role_active ON user_roles (active_key)`. M6's `UPDATE revoked_at` therefore also mutates an indexed column — relevant to D2's index-record analysis (T-E23) |
| `role_permissions` has `PRIMARY KEY (role_id, permission_id)`, no soft-delete, no trigger; the only V5 trigger is `trg_user_roles_no_delete` | `V5__rbac_schema.sql:45-53, 90-100` | **Confirmed.** M7 is a PK-prefix scan bounded at 7; D5's "there is nothing to lock" reason is factually correct |
| `nexus_app` holds `SELECT` only on `permissions` | `nexus-database/mysql/init/02-grants-post-schema.sql:31-35` (re-read via US-015's verification, unchanged on this branch) | **Confirmed.** D5's production-only-failure reasoning and MC-1 are correct and necessary |
| **`JpaRolePermissionRepository extends JpaRepository<RolePermission, RolePermissionId>`** | `rbac/infrastructure/persistence/JpaRolePermissionRepository.java:14-15` | **Confirmed — and this is a finding.** Injecting it into `JpaUserRoleAssignmentAdapter` (design §4.4) hands that adapter `save`/`delete`/`deleteAll` over `role_permissions`. See T-T13 / RC-12 |
| `JpaUserRoleAssignmentAdapter` already injects `JpaRoleRepository`, which already owns a `(tenantId, name)` lookup | `JpaUserRoleAssignmentAdapter.java:26-37`, design §4.4 | **Confirmed.** M8 genuinely adds zero queries — and the same already-injected repository is a viable host for M7's query, which is why RC-12 is cheap |
| **`RoleAssignmentService.assign()` is the only writer to `user_roles` in `src/main`** | `grep` for `userRoleAssignmentPort.assign` / `roleAssignmentService.` / `INSERT INTO user_roles` across `src/main` | **Confirmed.** One call site, one controller. The gate therefore has complete coverage of the runtime write path; only V5's seed DML bypasses it |
| **MEMBER cannot be made dangerous** (the US-015 T-E15 amplification path) | `RbacRoleNames.RESERVED = {TENANT_ADMIN, MEMBER}`; `SystemRoleImmutableException` Javadoc: *"MEMBER's only gate against a dangerous-permission attach, since AC7 runs before AC11"* | **Confirmed closed by US-015 RC-5b.** The "every self-registered user silently becomes privileged, and self-registration then breaks" scenario is **not** reachable. Recorded because it was the first thing I tested |
| `callerHoldsActiveTenantAdmin` (the wrong, non-locking, name-based helper) still lives three methods from the new gate | `RoleAssignmentService.java:342-347` | **Confirmed.** Impact §1.6 is right; MC-2 is the correct control and is not optional |
| `GlobalExceptionHandler` does not put `reason` in the response body | `common/web/GlobalExceptionHandler.java:159-176` (verified under US-015 §0.1, unchanged on this branch) | **Confirmed.** D6 reason 4's correction of impact §3.3 is accurate: `reason` is a log/metric/audit dimension only |
| No dependency delta on this branch | `git diff --stat main...HEAD -- '*pom.xml' '*package.json' '*package-lock.json'` → empty; design §0 declares "No new dependency" | **Confirmed.** Per the US-015 §0.1 precedent, `./mvnw dependency:tree` and `npm audit` are **deferred to the Phase 7 code audit** — there is no code and no manifest change to scan at Gate 2. Recorded rather than silently skipped |

### 0.2 Headline result

**The design is strong and it closes what it primarily set out to close.** D1's ordering, D4's single generalised call site, D5's non-locking ruling and D2's X-before-S lock order are all, in my judgement, the correct calls, and each is argued from the code rather than from convention. D6 is a genuinely clever piece of engineering: it removes an entire class of "someone forgot to edit the PromQL" regression by construction. §6.4's AC5 narrowing proof is valid — I checked it line by line and it holds.

**Seven things still need to change, and one of them changes what this story is allowed to claim.**

1. **RES-1 is mis-scoped, and the design's instruction to flip US-015's RES-1 / T-E16 to "closed" is too strong** (T-E21, **High**). The forward-only residual is written up as a *historical* exposure window discharged by a one-off audit. It is not. It is a **permanent, repeatable, race-free escalation primitive** available to any `user:write` holder: self-assign every benign custom role in the tenant today (legitimate, `privileged="false"`, "ticket at most" under the new canary semantics), and wait for an administrator to attach a dangerous permission to any one of them. `attachPermission` does not look at existing holders, so the escalation is silent at both ends. **This must go back to the Architect** — not because US-016 must fix it, but because US-016 must not be recorded as closing it.
2. **D2's proof is stated at logical-row granularity; InnoDB locks index records** (T-E23, Medium). The decision is right; the proof has two unstated dependencies (index access path, REPEATABLE READ gap locks) and harness A is homogeneous — it cannot exercise the cross-method interaction that §7.2 property 3 merely *asserts*.
3. **D6 closes the false-negative side of R5 and opens a false-positive side it does not cost** (Medium). A `> 0` **page** alert whose population widens from "a non-admin tried to mint an admin" to "a helpdesk operator tried to offboard an admin" is an alert-quality regression, on two un-rate-limited verbs.
4. **The `privileged="true"` canary pages on the normal Epic-3 admin bootstrap sequence** (claim 7, Medium) and carries no field that discriminates a bypass from that sequence.
5. **`revoke()`'s denial path now holds an exclusive lock over every admin row in the tenant across two extra round trips and a `REQUIRES_NEW` audit write** (T-D11, Medium). RES-4's "adds no new lever" is wrong on hold *duration* and on blast radius.
6. **The adapter gains full CRUD over `role_permissions`** — the one table with `INSERT`+`DELETE` grants and no DB backstop (T-T13, Medium). D3's argument is correct at the application layer and unexamined one layer down.
7. **The §10.4 exposure-audit runbook produces false negatives on exactly the escalation case it exists to find** (T-R8, Medium), and its step 2 points at a Java port method no operator can invoke.

**None is a Blocker.** US-016 is strictly better than the status quo on every path I could construct, and nothing in the design introduces a bypass of its own gate. **Verdict: conditional pass** — Gate 2 may close once RC-8…RC-14 (§7) are folded into `03-design.md`, and RC-8 requires an Architect decision, not an editorial one.

### 0.3 Explicit review attestation (standing policy — auth, crypto, and PII are never approved silently)

- **Authentication — reviewed. No findings.** US-016 adds no authentication code and no new authentication-adjacent surface. It consumes `RoleChangeActor` assembled by `RbacControllerSupport.resolveActor` (three fail-closed branches, reviewed under US-015 T-S5/T-S6, unchanged) from the RS256-validated JWT (`JwtRs256Service`, US-011 T-01/T-02, unchanged). The story's one authentication-relevant property is **negative and it is preserved**: admin status is never derived from a JWT claim. The gate's admin check is M5, a fresh `PESSIMISTIC_READ`, reused verbatim; the port Javadoc that forbids the shortcut (`UserRoleAssignmentPort.java:35-42`) is unchanged; the design mandates extending `RoleAssignmentSecurityIT`'s stale-JWT out-of-band-revocation IT to the new privilege path (§11.3). See **T-S7**.
- **Authorization — reviewed in depth; this is the story's entire substance.** Covered by T-E21 through T-E26, T-D11, T-I10 and T-I11. Specifically reviewed and **confirmed sound**: the unified condition's short-circuit (name-first, so FR-3 cannot be weakened by the new read); the single generalised `hasActiveAdminAssignment` call site fed by M8 (D4/R4); the fail-closed-on-empty-M8 branch (R-10/T-E18 precedent); the 403-before-409 decision order; the AC5 reachability proof; the completeness of the gate's coverage (one write path to `user_roles` in `src/main`, verified by grep, not assumed). Specifically **not** approved: the claim that this closes US-015's RES-1 in full (T-E21).
- **Cryptography — reviewed. No findings.** US-016 introduces no cryptographic code, no key material, no new randomness source, no new id generation. It adds no `Math.random`; the backend still has none. Ids on the new read paths are pre-existing UUIDv7 values from `UuidV7IdGenerator` (`SecureRandom`-backed, ADR-0005), and the two new reads return a `List<String>` of permission names and an `Optional<UUID>` role id respectively — neither is a secret, neither is compared in a timing-sensitive way, and neither feeds a decision that a timing side channel could usefully influence (the gate's outcome is already disclosed by the HTTP status). **No cryptographic findings.**
- **PII — reviewed against the organisation's no-PII rule. No new exposure.** Every field added by this story is a UUID, an enum-like constant, or a boolean: the WARN marker carries `tenantId`, `targetUserId`, `actorUserId`, `roleId`, `roleName`, `operation` (`assign|revoke`), `matchedOn` (`ROLE_NAME|DANGEROUS_PERMISSION`); the counter gains one bounded tag `privileged` (`true|false`). No email, no display name, no IP beyond the pre-existing `RequestContext` triple. The 403 body is unchanged field-for-field and carries no `reason`. **One inherited caveat, recorded not filed:** `roles.name` is tenant-controlled free text under US-015's D6 allow-list (`^[A-Za-z0-9][A-Za-z0-9 ._-]*$`), which permits a personal name — so a role called `Jane Doe Admin` would land in the new WARN marker. This is unchanged from `ROLE_ASSIGNED`'s existing `roleName` handling (US-015 T-I9, closed: the allow-list excludes CR/LF and the encoder is structured), and US-016 adds no new sink. Flagged for Epic 3's role-naming guidance, not as a US-016 defect.
- **Secrets — reviewed. No findings.** No credential, no token, no connection string, no config value is introduced, read or logged. The story adds no feature flag (D10) and no property.

**Severity scale** (consistent with `docs/features/US-012/03b-threat-model.md` §0.3 and US-015 §0.2): **Blocker** / **Critical** / **High** / **Medium** / **Low**.

**Threat ID numbering** continues the epic's STRIDE-lettered sequence. US-009 allocated T-S1–S2, T-T1–T4, T-R1–R2, T-I1–I3, T-D1–D2, T-E1–E6; US-012 extended to T-S4, T-T7, T-R4, T-I5, T-D5, T-E13; US-015 to T-S6, T-T11, T-R7, T-I9, T-D9, T-E20. **US-016 therefore begins at T-S7, T-T12, T-R8, T-I10, T-D10, T-E21.** Required-change numbering continues US-015's RC-1…RC-7 at **RC-8**.

---

## 1. Trust boundaries and data flow

```
[ Internet / hostile client — holds a VALID token for a tenant member with `user:write`
  (and possibly `role:write`), but NO active TENANT_ADMIN assignment.
  Claims may be up to ~30 min stale (US-015 T-I8). ]
        |  POST   /api/v1/users/{userId}/roles          {roleId}
        |  DELETE /api/v1/users/{userId}/roles/{roleId}          + Bearer JWT
        v
=== TB1: network -> app ==================================================
  CorrelationIdFilter -> LoginRateLimitFilter  ** login/refresh ONLY — NOT these paths **
  -> JwtAuthenticationFilter (RS256 verify; MDC userId/tenantId)
        |  ** NO rate limit, NO throttle, NO per-tenant cap on either verb (T-D10) **
        v
=== TB2: filter chain -> dispatcher ======================================
  @ConditionalOnProperty feature.nexus-us012-rbac-role-assignment.enabled  (false in prod)
        |  flag-off => 404 => US-016's gate is a no-op in production at deploy time (D10/§10.2)
        |  ** flag-off is an AVAILABILITY lever, not a security one — it RE-OPENS the hole **
        v
=== TB3: dispatcher -> method-security proxy =============================
  @RequiresPermission("user:write") -> TenantAwarePermissionEvaluator
        == FLAT Set.contains on the JWT permissions[] claim. ZERO admin-status check. ==
        == Cannot express the privilege gate. The gate is 100% service-layer logic.   ==
        v
=== TB4: interfaces -> application (Spring-Security-free boundary) =======
  UserRoleController -> RoleChangeActor(userId, tenantId)   <-- JWT-only provenance
        v
  RoleAssignmentService @Transactional          ** THE COMPONENT THIS STORY CHANGES **
    assign():   [1] verifySameTenant       404/403 + inline denial audit
                [2] resolveRoleInTenant    404/403 + inline denial audit
                [3] nameMatch? --no--> M7 findPermissionNamesForRole  ** NON-LOCKING (D5) **
                [4] if privileged: M8 findRoleIdByName -> empty => FAIL CLOSED
                                   M5 hasActiveAdminAssignment  ** FOR SHARE (S) **
                                   => 403 RBAC_001 / NOT_TENANT_ADMIN + audit + WARN
                [5] M2 duplicate 409 -> INSERT -> M4a
                [6] post-commit: evict, ROLE_ASSIGNED, self_role_assignment{privileged}
    revoke():   [1][2] as above
                [3] M3 findActiveAssignmentRef -> 404          ** 404 stays before 403 **
                [4] nameMatch? --no--> M7                       ** NON-LOCKING **
                [5] nameMatch? --yes-> M1 lockActiveAssignmentIds  ** FOR UPDATE (X) — D2 **
                                       ^^ acquired BEFORE any decision (§6.3) ^^
                [6] if privileged: M8 + M5 (S, inside the X region) -> 403
                [7] AC5 lockout -> 409 RBAC_002   ** now self-revocation only (§6.4) **
                [8] M6 UPDATE revoked_at -> 204
        v
=== TB5: app -> MySQL as `nexus_app` (least-privilege) ===================
  permissions       SELECT           <-- ** a @Lock on M7 fails HERE, in prod only (MC-1) **
  roles             SELECT, INSERT
  role_permissions  SELECT, INSERT, DELETE   <-- ** no trigger, no soft delete, no backstop **
                                                 ** and the adapter is about to gain a
                                                    full JpaRepository over it (T-T13) **
  user_roles        SELECT, INSERT, UPDATE(revoked_at)   <-- M1 FOR UPDATE, M5 FOR SHARE
  auth_events       INSERT, SELECT
        v
=== TB6: denial side effects — INLINE, inside the doomed transaction ====
  recordDenial -> RbacAuthEventAdapter -> SecureEventService(REQUIRES_NEW)
     ** borrows a SECOND pooled connection while M1's X lock is held (RES-5 / T-D11) **
     ** never throws; failure => RBAC_AUDIT_WRITE_LOST ERROR + counter, 403 still returns **
  WARN RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED {operation, matchedOn, ...}
  nexus.rbac.permission_denied{permission="user:write", reason="NOT_TENANT_ADMIN"}
     ** feeds a `> 0` PAGE alert, on an un-rate-limited path (T-D10) **
        v
=== TB7: OUT-OF-BAND — the boundary this story still does not own =======
  US-015 POST /api/v1/roles/{roleId}/permissions   (attach: AC11 admin-gated)
         DELETE .../permissions/{permissionId}      (detach: ** NOT admin-gated **)
     ** attach does not look at, count, or report the role's existing holders **
     ** => a benign role self-assigned yesterday becomes admin-equivalent today,
          with no gate evaluation and no signal at either end (T-E21) **
        v
=== TB8: token mint — the staleness boundary ============================
  RoleResolutionService fingerprint misses permission edits -> ~30 min (US-015 T-I8)
     ** an escalation via T-E21 becomes effective at the next mint, not immediately **
```

**Components under analysis.**
**C1** `UserRoleController` + DTOs (unchanged — re-verified as a boundary) ·
**C2** `RoleAssignmentService.assign()` — the gate on the grant verb ·
**C3** `RoleAssignmentService.revoke()` — the gate, the lock order (D2), and the AC5 interaction (D1/§6.4) ·
**C4** `UserRoleAssignmentPort` M7 / M8 contracts (D3) ·
**C5** `JpaUserRoleAssignmentAdapter` + `JpaRolePermissionRepository` + `JpaRoleRepository` ·
**C6** the `nexus_app` privilege / InnoDB locking boundary ·
**C7** the denial audit path (`recordDenial` → `auth_events`) + the new WARN marker ·
**C8** observability: `permission_denied`, `self_role_assignment{privileged}`, the two composed page alerts, the runbooks ·
**C9** trust dependencies — `RoleManagementService.attachPermission` / `detachPermission` (US-015), `RbacDangerousPermissions`, `TenantAwarePermissionEvaluator`, `RoleResolutionService` / `PermissionCachePort`.

---

## 2. Component-by-component STRIDE table

Legend: **✅** addressed by the design as written · **⚠️** partially addressed, gap identified · **❌** not addressed, change required · **n/a** not applicable.

### C1 — `UserRoleController` + DTOs (unchanged)

| | Threat | Verdict |
|---|---|---|
| **S** | Caller forges actor or tenant via body/path | ✅ Unchanged. `RoleChangeActor` is JWT-only; `assignedBy` is always `actor.userId()` (T-S3 discipline, `RoleAssignmentService.java:158-160`). No DTO change (D11) |
| **T** | Wire contract drift from the new denial | ✅ Verified: the 403 body is unchanged field-for-field. `GlobalExceptionHandler` sets only `code`, `traceId`, `requiredPermission`; `reason` is never wire-visible (D6 reason 4 — confirmed) |
| **R** | — | n/a (unchanged) |
| **I** | New status-code oracle on either verb | ⚠️ **T-I10, Low-Medium** (new privilege oracle on the *target role*, assign side) and **T-I11, Low** (the "already readable via `user:read`" premise is not enforced). D1 also **removes** an oracle — see T-I12 |
| **D** | Unthrottled denial generation | ❌ **T-D10, Medium.** Both verbs remain deliberately un-rate-limited, and this story materially widens the denial population feeding a `> 0` **page** alert and a durable audit row |
| **E** | `@RequiresPermission` silently unenforced | ✅ Inherited and mechanically closed by US-015 D8's ArchUnit rules, which retroactively cover `UserRoleController`. No new handler, no new annotation |

### C2 — `RoleAssignmentService.assign()` (the gate on the grant verb)

| | Threat | Verdict |
|---|---|---|
| **S** | Admin status derived from a stale JWT rather than the DB | ✅ **T-S7, Low.** M5 reused verbatim; port Javadoc unchanged; §11.3 mandates extending the stale-JWT IT to the privilege path |
| **T** | Target role's permission set mutated between check and write (TOCTOU) | ✅ **T-E25, Low.** D5's ruling is correct; one of its three stated reasons is factually wrong and must be corrected (detach is not admin-gated) |
| **R** | New denial path leaves no durable record | ✅ FR-5 satisfied with zero new code — `recordDenial` reused unchanged, `ROLE_ASSIGNMENT_DENIED` on the STANDARD lane. ⚠️ but see **T-R8** on discriminability |
| **I** | The gate discloses whether a role carries dangerous permissions | ⚠️ **T-I10, Low-Medium.** New channel: 403 vs 201/409 on assign tells a `user:write` holder that the target role is privileged, without `role:read` |
| **D** | Denial flood → page storm + audit-row amplification | ❌ **T-D10, Medium** |
| **E** | **Wrong argument to `hasActiveAdminAssignment` → fail open** | ⚠️ **T-E22, Medium.** D4 + MC-3 pin the `roleId` axis correctly. The `userId` axis (`targetUserId` instead of `actor.userId()`) is **not** pinned and fails open identically |
| **E** | Short-circuit exploited to skip the privilege read | ✅ Sound. `privileged = nameMatch \|\| dangerous` — the short-circuit can only skip the read when `nameMatch` is **true**, i.e. when the gate is already going to apply. There is no input that makes the short-circuit skip the read *and* clear `privileged`. Verified against the pseudocode in §6.1 |
| **E** | Empty permission set treated as privileged / non-privileged | ✅ Edge Case 1 handled: `anyMatch` over an empty list is `false` ⇒ not privileged. Correct, and the Mockito default (empty list) means unrelated unit tests fail *safe* |
| **E** | Escalation survives the gate entirely | ❌ **T-E21, High.** Pre-positioning: self-assign benign, wait for a legitimate attach |

### C3 — `RoleAssignmentService.revoke()` (gate + lock order + AC5)

| | Threat | Verdict |
|---|---|---|
| **S** / **T** | As C2 | ✅ / ✅ |
| **R** | Revoke-side denial indistinguishable from assign-side in `auth_events` | ⚠️ **T-R8, Medium** (design rates it Low as RES-6). The compensating control is a log field whose retention relative to `auth_events` is unstated — the exact gap US-015 RES-10 refused to leave open |
| **R** | Attacker induces audit loss to make probing unrepudiable-by-absence | ⚠️ **T-R9, Medium.** Chained from T-D10: flood the denial path, exhaust the pool, `recordDenial` degrades to `RBAC_AUDIT_WRITE_LOST`. Detectable (ERROR + `nexus.rbac.audit_write_failed`), but the denial rows for that window are gone |
| **I** | 409 `RBAC_002` disclosed the tenant's admin roster size to an unauthorized caller | ✅ **T-I12, Low — improved by this story.** D1's 403-before-409 removes a real pre-existing leak. Reasoning confirmed |
| **D** | **Lock-hold and blast-radius amplification on the denial path** | ❌ **T-D11, Medium.** M1's X lock over *every* admin row in the tenant is now held across M8 + M5 + a `REQUIRES_NEW` audit write before the 403 is thrown. RES-4's "adds no new lever" understates both duration and blast radius |
| **D** | **S→X upgrade deadlock on the legitimate admin-revoking-admin path** | ⚠️ **T-E23, Medium.** D2's decision (X first) is correct and option (b)'s rejection is sound. The *proof* is stated at logical-row granularity and rests on two unstated assumptions; harness A cannot exercise the cross-method claim |
| **D** | Pre-existing `assign(TENANT_ADMIN)` × `revoke(TENANT_ADMIN)` cycle | ⚠️ **T-D12, Low (inherited).** Real today, unchanged by this story, and **unnamed** in §7.2 property 3 — which risks it being misattributed to US-016 when a mixed harness finds it |
| **E** | AC5's actor-agnostic branch becomes unreachable, re-opening a lockout path | ✅ **T-E24, Low.** §6.4's proof is **valid** — verified step by step. The ≥1-active-admin invariant is now enforced *more* strongly (by the gate) than before. One corner depends on RR gap locks (RC-9) |
| **E** | Escalation survives the gate | ❌ **T-E21, High** (revoke side: an operator who was pre-positioned can also strip) |

### C4 — `UserRoleAssignmentPort` M7 / M8 (D3)

| | Threat | Verdict |
|---|---|---|
| **S** / **R** | — | n/a |
| **T** | Dangerous-permission **policy** leaks into infrastructure and drifts | ✅ **Design's strongest single call.** M7 returns names; the policy set never crosses the port in either direction. This is genuinely stronger than impact's parameter-passing proposal, and it keeps the case-insensitivity guarantee inside the already-unit-tested `RbacDangerousPermissions` rather than inside MySQL's collation. Confirmed |
| **T** | A future `@Lock` on M7 → production-only rejection | ✅ Port Javadoc forbids it in capitals; **MC-1** makes it mechanical. Correct, and MC-1 is not optional |
| **I** | **M7 is not tenant-scoped** | ⚠️ **T-I13, Low.** `findPermissionNamesForRole(UUID roleId)` takes a bare role id with no tenant parameter — unlike almost every other method on this port. Safe at the one call site (the role is tenant-verified two lines earlier), unsafe as a general contract. The precondition must be in the Javadoc |
| **D** | Unbounded result | ✅ Bounded at 7 by the fixed catalogue; PK-prefix scan. No N+1 |
| **E** | Write capability leaks into `RoleAssignmentService` | ✅ **D3 confirmed at this layer.** `RoleManagementPort` is not injected; the service's constructor is unchanged; `createRole`/`attachPermission`/`detachPermission` remain unreachable from the assignment service |
| **E** | Fail-open when the tenant has no `TENANT_ADMIN` role | ✅ M8's Javadoc mandates fail-closed; §6.1 implements it before M5 is reached; the R-10/T-E18 precedent is followed exactly. The stated asymmetry (impossible on the name-match path ⇒ a data bug) is correct and the WARN's `matchedOn` is the right discriminator |

### C5 — `JpaUserRoleAssignmentAdapter` / `JpaRolePermissionRepository` / `JpaRoleRepository`

| | Threat | Verdict |
|---|---|---|
| **T** | **New constructor dependency grants the adapter full CRUD over `role_permissions`** | ❌ **T-T13, Medium.** `JpaRolePermissionRepository extends JpaRepository<…>` ⇒ `save`, `delete`, `deleteAll`, `deleteAllInBatch`. `nexus_app` holds `INSERT` **and** `DELETE` on that table with no trigger and no soft delete (US-015 T-E15/RES-5), so an accidental call **executes**. D3's write-capability argument was made one layer too high |
| **T** | Injection (JPQL) | ✅ **OWASP A03 clean.** M7's query is a parameterised comma-join JPQL `@Query`; no concatenation; `UuidV7Converter` handles both the predicate and the bind. M8 reuses the shipped `findIdByTenantIdAndName` |
| **T** | De-sargonised `UPPER(name)` on M8 | ✅ Explicitly forbidden by the port Javadoc; `uq_roles_tenant_name` + `utf8mb4_0900_ai_ci` do the case-insensitivity |
| **I** | Managed entity escapes and is load-mutate-saved | ✅ M7 returns `List<String>`, M8 returns `Optional<UUID>`. Neither is a managed entity. Consistent with the port's existing discipline |
| **D** | Extra queries on a hot path | ✅ +1 to +2 bounded indexed lookups on a non-hot, admin-scoped path. Inheriting the epic p95 bar rather than inventing one is the right call |
| **E** | Hardcoded `TENANT_ADMIN` / dangerous names in the adapter | ✅ R-9 discipline preserved and extended by §4.4's Javadoc edit. Confirmed |

### C6 — the `nexus_app` privilege / InnoDB locking boundary

| | Threat | Verdict |
|---|---|---|
| **T** | Locking read on a `SELECT`-only table → production-only failure | ✅ Identified, ruled on (D5), and made mechanical (MC-1). This is the design's second-best call. `RolePermissionsPrivilegeIT`-family additions correctly judged unnecessary because no new locking read is proposed |
| **D** | **Deadlock / lock-wait timeout under concurrency** | ⚠️ **T-E23 / T-D11.** Decision right, proof incomplete, harness insufficient |
| **D** | Isolation-level dependency | ⚠️ **Part of T-E23.** Both D2's containment and §6.4's AC5 proof silently assume REPEATABLE READ (gap/next-key locks). Under READ COMMITTED both weaken. Nothing in the codebase pins or asserts the isolation level for these transactions |
| **E** | Privilege sufficient for `FOR SHARE` under the column-scoped grant | ✅ Settled empirically by `UserRolesPrivilegeIT` (US-012 T-R4, US-015 C5). `FOR SHARE` is no stricter than the `FOR UPDATE` already proven |

### C7 — the denial audit path + the new WARN marker

| | Threat | Verdict |
|---|---|---|
| **S** | Forged actor in a denial row | ✅ `actorUserId` is always `actor.userId()`; the row is always written under `actor.tenantId()`, never the target's (`recordDenial` Javadoc, unchanged) |
| **T** | Log injection (CRLF) via `roleName` in the new WARN | ✅ **Closed, inherited.** US-015 D6's allow-list excludes CR/LF/U+2028/U+2029 and the encoder is structured key-value. US-016 adds no new sink and no new field that is not a UUID or an enum constant |
| **T** | JSON injection into `auth_events.metadata` | ✅ Unchanged path, unchanged mechanism (injected Jackson-3 `ObjectMapper`), no new metadata field. US-015 T-T8 applies as-is |
| **R** | Assign vs revoke denials indistinguishable | ❌ **T-R8, Medium** |
| **R** | Denial row lost under induced pool pressure | ⚠️ **T-R9, Medium** |
| **I** | PII in the marker or the row | ✅ None (§0.3). Every new field is a UUID or a bounded constant |
| **D** | Priority-lane flooding | ✅ `ROLE_ASSIGNMENT_DENIED` is deliberately **excluded** from the PRIORITY lane (`AuthEventType.java:48-49`, verified under US-015). A denial flood therefore cannot displace `ROLE_ASSIGNED`/`ROLE_REVOKED` from the priority lane — it lands on the STANDARD lane. This is a real, pre-existing structural mitigation for T-D10 and is worth stating |

### C8 — observability, alerting, runbooks

| | Threat | Verdict |
|---|---|---|
| **I** | Detection regression: the new gate's denials page nobody | ✅ **D6 confirmed on this axis.** Reusing `NOT_TENANT_ADMIN` means `nexus_rbac_self_escalation_attempt` keeps firing with zero PromQL edits. "A design that cannot regress beats a design that must be remembered" is the right instinct and the right outcome |
| **D** | **Detection regression in the other direction: page precision collapses** | ❌ **Medium, RC-11.** The `> 0` page population widens from "a non-admin tried to mint an admin" (near-zero base rate) to include every routine denied offboarding attempt by a non-admin operator, on two verbs, un-rate-limited. The design costs this as "the metric is coarser than the log" and treats it as an accepted RES-7. It is more than coarseness: it is a page-severity false-positive rate change |
| **D** | **Canary fires on the normal Epic-3 admin bootstrap sequence** | ❌ **Medium, RC-11.** `self_role_assignment{privileged="true"} and on(tenantId) dangerous_permission_granted` will fire on: admin creates custom role → attaches `user:write` → self-assigns it to verify. That is the expected first-use sequence, it pages, and the counter carries **no field** that distinguishes it from the bypass case the canary exists to detect |
| **R** | Operators act on stale alert meanings | ✅ §9.3's seven mandatory doc edits are correctly scoped and correctly made non-optional. The `nexus_rbac_tenant_lockout_blocked` re-meaning (§6.4 corollary) is a genuinely useful catch |
| **I** | Exposure-audit runbook misleads | ❌ **T-R8 part 2, Medium.** §10.4 step 3 compares `assigned_by` against *currently* active admins — a point-in-time error producing **false negatives on exactly the escalation case** (grantor who was not an admin then but is now). Step 2 points at a Java port method no operator can invoke |

### C9 — trust dependencies

| | Threat | Verdict |
|---|---|---|
| **E** | `attachPermission` silently escalates every existing holder | ❌ **T-E21, High.** The one gap that survives US-016, and the one the design mis-describes as closed |
| **E** | `detachPermission` is not admin-gated | ⚠️ **T-E25, Low.** Correctly a deliberate US-015 asymmetry; it makes one sentence of D5/RES-2 factually wrong |
| **E** | `MEMBER` amplification (US-015 T-E15) interacts with the new gate | ✅ **Closed, verified this session.** `RbacRoleNames.RESERVED` + AC7 running before AC11 means `MEMBER` can never carry a dangerous permission, so it can never become gate-privileged and self-registration can never be broken by it |
| **I**/**E** | ~30-min staleness (US-015 T-I8) delays the effect of a gate-blocked change | ✅ Unchanged and, for this story, in the *safe* direction: a denial has no privilege effect to propagate. A **successful** privileged assignment still takes up to ~30 min to become effective — which is a detection window, not a risk |
| **E** | Flag-off re-opens the hole | ✅ **D10 confirmed, and its reasoning is the best in the document.** A dedicated flag whose "off" position is the vulnerability would be the only flag in the codebase that must default `true` to be safe. §10.3's rollback caveat ("flag-off is an availability lever, not a security one") is correct and matches US-015 T-E20 |

---

## 3. Identified threats

Each entry: what an attacker achieves · existing mitigation in the design · required mitigation · residual.

---

### T-E21 — Pre-positioning: self-assign a benign role today, escalate silently when an admin makes it dangerous tomorrow · **High** · ❌ change required (to the *record*, not necessarily to the code)

**The chain, verified end to end in code this session.**

| Step | Actor | Mechanism | Gate after US-016 | Signal after US-016 |
|---|---|---|---|---|
| 1 | any `user:write` holder (**non-admin**) | `POST /users/{self}/roles` for every permission-less / benign custom role in the tenant | **None — correct by design.** `carriesDangerousPermission` returns false, the gate does not apply | `self_role_assignment{privileged="false"}` — which §9.3 documents as *"benign self-service; ticket at most"* |
| 2 | *(wait — hours, days, or a sprint)* | — | — | — |
| 3 | an active `TENANT_ADMIN` | `POST /roles/{R}/permissions` attaching `user:write` to role **R** | **AC11 — passes. This is the legitimate, Epic-3-required action** | `dangerous_permission_granted{permission}` — a ticket alert, reviewed as "this tenant is now in the exposed state" |
| 4 | the attacker from step 1 | *nothing* | **The gate never runs. There is no assign and no revoke to gate.** | **None** |
| 5 | the attacker | next token mint (≤ ~30 min, US-015 T-I8) | — | — |

**What the attacker achieves.** Admin-equivalent authority (`user:write` via R, and `role:write`/`tenant:write` if attached), obtained with **no race, no collusion, no privilege they did not already hold, and no gate evaluation at any point**. Step 1 is a legitimate action that this story explicitly permits and that the new canary semantics explicitly de-prioritise. Step 3 is a legitimate action that US-015 explicitly permits. Neither end sees the other: `attachPermission` does not look at, count, or report the role's existing holders (verified — the full method body contains no holder lookup, and `RoleAuditEvent` has nowhere to carry one).

**Reachability.** Higher than T-E16's, not lower. T-E16 required the attacker to act *after* the dangerous attach, in a window an operator might be watching. T-E21 requires the attacker to act *before*, when nothing is anomalous, and then do nothing at all. It is available to every `user:write` holder in every tenant, permanently, and it is repeatable: an attacker who is revoked from R can simply re-self-assign it the next time it is benign.

**Existing mitigation in the design.** RES-1, rated **Medium**, described as: *"Forward-only enforcement. The gate evaluates at assign/revoke time; a role that becomes dangerous after an assignment exists is not re-validated, and pre-existing non-admin-granted assignments survive (Gate 1 #7, Edge Case 7)."* Disposition: *"Accepted by Gate 1. Mitigated by the §10.4 exposure audit (ops action) and the release-note sentence."*

**Why that is not adequate as written — three distinct problems.**

1. **The mitigation does not match the threat.** A **one-off** exposure audit discharges a **historical** exposure window. T-E21 is not a window; it is a standing primitive that regenerates every time an administrator attaches a dangerous permission. Running the §10.4 query once, at release, mitigates nothing that happens afterwards.
2. **The severity is one notch low.** RES-1's description (*"pre-existing non-admin-granted assignments survive"*) is a data-cleanup framing. The correct framing is a live escalation path with a lower skill floor than the one this story closes. Rated on the same basis US-015 used for T-E16 (High), this is **High**.
3. **§12.2 item 6 instructs the wrong documentation change.** It directs `docs/features/US-015/03b-threat-model.md` §4.5 and §5 to flip *"RES-1 / T-E16 / T-E17 → **closed**, citing US-016."* T-E17 (revoke-side stripping) genuinely is closed — I could construct no surviving variant. T-E16 is closed **only for the at-assign-time path**. Flipping RES-1 wholesale to "closed" would delete the risk register's only record of the surviving path, three weeks before the Epic 3 kickoff that RES-1's own hard-expiry clause names. That is the precise failure mode US-015's D13 Javadoc rule ("replace with a closure reference, never delete") exists to prevent — applied to the code but not, here, to the register.

**Required mitigation (RC-8).** Three parts; the first two are documentation and are mandatory, the third is an Architect decision.

1. **Re-scope RES-1** in `03-design.md` §12.3 to **High**, with the standing-primitive description above, and split the historical component (the US-015→US-016 exposure window, discharged by the §10.4 audit) from the permanent component (T-E21, not discharged by anything currently proposed).
2. **Correct §12.2 item 6.** T-E17 → closed. T-E16 → *"closed for the direct propagate path; the attach-after-assign path is carried forward as US-016 T-E21 / RES-1."* RES-1's owner, review date (2026-11-27) and Epic-3 hard-expiry survive the transition and attach to the surviving component.
3. **Decide, at Architect level, whether the cheap mint-side signal ships here or as a named successor.** The information needed already exists behind a port method this codebase built for exactly this purpose: `UserRoleAssignmentPort.findActiveUserIdsForRole(roleId)` (RC-6, US-015). At `attachPermission`, when `dangerous == true`, one call yields the count of users who are about to be silently escalated. Emitting it — as a field on the existing `ROLE_PERMISSION_GRANTED` WARN/audit event and as a bounded bucket tag (`0`, `1`, `2-10`, `>10`) on `nexus.rbac.dangerous_permission_granted` — converts a silent mass escalation into a reviewable, alertable event, at the cost of one bounded query on a rare admin-only path. It is the exact shape of RC-7, which the same reviewer required of US-015 and which US-015 accepted. **If it does not ship in US-016, it must be a named successor story with an id before US-016 merges** — the same verification condition US-015 §4.5 imposed on US-016 itself, applied for the same reason.

**Residual after mitigation: High → Medium** if part 3 ships; **High, explicitly re-accepted with a named owner and an Epic-3 expiry** if it does not. See RES-1 in §5.

---

### T-E22 — Fail-open on the wrong `userId` argument to `hasActiveAdminAssignment` · **Medium** · ⚠️ one axis unpinned

**Attack.** The generalised call is `hasActiveAdminAssignment(actor.userId(), adminRoleId, actor.tenantId())`. There are **two** ways to get it wrong and both fail **open**:

- **Axis 1 — `roleId`.** Passing `role.getId()` (the target role) instead of M8's `adminRoleId` asks *"does the caller hold the custom role?"* On the self-assignment path, once the attacker holds R even once, that is `true`. Impact §13 R4 named this the story's worst silent bug.
- **Axis 2 — `userId`.** Passing `targetUserId` instead of `actor.userId()` asks *"is the **target** an active admin?"* A non-admin assigning a privileged role to an existing administrator would pass; more usefully to an attacker, on the **revoke** verb it means any non-admin can strip any role from anyone who happens to be an admin — which is T-E17 reopened for the highest-value targets in the tenant.

Both compile. Both pass every test that does not assert the arguments.

**Existing mitigation.** **MC-3** covers axis 1 completely and well: an `ADMIN_ROLE_ID` stub deliberately different from the target `roleId` in every privilege-path unit test, plus `verify(port, never()).hasActiveAdminAssignment(any(), eq(targetRoleId), any())`. **MC-2** guards against the wrong *helper*. Neither touches axis 2, and the existing regression tests do not either: `should_proceedToInsert_when_grantingTenantAdminAndCallerIsActiveAdmin` (line 343) asserts `hasActiveAdminAssignment(actorId, …)` on the **name-match** path only, and several privilege-path fixtures in §11.3's matrix are self-assignment scenarios (FR-4), where `targetUserId == actor.userId()` and the two axes are **indistinguishable**.

**Required mitigation (RC-14).** Extend MC-3 to axis 2, at zero cost:
- every privilege-path unit test that is **not** a deliberate FR-4 self-assignment case must use `targetUserId != actor.userId()`;
- add `verify(port, never()).hasActiveAdminAssignment(eq(targetUserId), any(), any())` alongside the existing MC-3 assertion;
- state in `MC-3`'s row that the control covers **both** arguments, so a future reader does not conclude the `userId` axis was considered and dismissed.

**Residual after mitigation: Low.**

---

### T-E23 — D2's deadlock proof is stated at logical-row granularity; InnoDB locks index records · **Medium** (High if the proof is wrong) · ❌ change required

**I agree with D2's decision and with its rejection of option (b).** Working through it independently:

- **X-before-S is the correct order.** Under the rejected order, two admins revoking each other each hold S on a row the other's X request covers → textbook upgrade cycle. Confirmed.
- **Option (b) genuinely does not fix it.** §7.3's counterexample is sound: promoting the gate's read to `PESSIMISTIC_WRITE` while leaving it *before* M1 leaves A holding X on row A and requesting X over `{A, B, …}` while B holds X on row B and requests the same set. Mode is not the defect; order is. Confirmed. The secondary argument (it would also change `revoke()`'s first-acquired lock, and M5 is shared with the mint side) is correct and independently sufficient.
- **The lock partition is clean on the paths I could enumerate.** On the `nameMatch` path the only locks are M1's X set, an S request contained in it, and M6's UPDATE on a row inside it. On the dangerous-custom-role path M1 is not taken at all, so the locks are S on the caller's `TENANT_ADMIN` row and X on the target's *custom-role* row — disjoint row populations, so two such transactions cannot cycle with each other, and neither can cycle with a `nameMatch` transaction (the `nameMatch` transaction never requests a custom-role row). I could not construct a **new** cycle.

**Where the proof is short.** §7.2 step 1 says: *"The S read asks about a row the transaction already holds X on… InnoDB grants a shared request on a record for which the same transaction already holds an exclusive lock immediately — there is no upgrade, and no wait."* That is true **of the clustered-index record**. It is not automatically true of the whole statement, because **InnoDB sets locks on index records, not on logical rows**, and M1 and M5 do not necessarily use the same index:

- M1 drives off `role_id` — by its own Javadoc, deliberately, via `fk_user_roles_role`. It locks records in that secondary index plus the matching clustered records.
- M5's predicate is `userId = ? AND roleId = ? AND tenantId = ? AND revokedAt IS NULL`. The optimiser may choose `fk_user_roles_user`, `fk_user_roles_role`, or `uq_user_role_active`. Only in the `fk_user_roles_role` case is every lock M5 requests already held. In the others, M5 requests locks on secondary-index records that M1 did not touch — a genuinely **new** acquisition, not a contained one.

I could not construct a concrete deadlock from that gap (the transactions that could hold a conflicting lock on `uq_user_role_active`'s record for the caller's row are, on the paths I enumerated, blocked earlier by M1 itself). But "I could not construct one" is not the standard §7 sets for itself — it calls this "the load-bearing section of this document" — and the property is decided by an optimiser plan, not by the code.

**Second unstated dependency: REPEATABLE READ.** Both D2 and §6.4 rely on gap/next-key locking:
- D2's serialization claim (step 2, *"exactly one transaction is inside the critical section at a time"*) requires M1's range lock to also block **inserts** of new admin assignments into the `role_id = adminRoleId` range. Under READ COMMITTED there are no gap locks and a new admin row can be inserted mid-transaction.
- §6.4's AC5 proof requires that the caller's own admin row, present at M1 time, is the *only* admin row when `size() <= 1`. If a concurrent `assign(TENANT_ADMIN)` could commit between M1 and M5, M5 could return true for a caller whose row was not in M1's set — re-opening the actor-agnostic scenario the proof declares structurally unreachable (harmlessly: the outcome is still a 409, but the proof would be false).

Nothing in the codebase pins the isolation level for these transactions; it works today because MySQL's default is `REPEATABLE-READ`.

**Third gap: harness A cannot prove what §7.2 property 3 claims.** Property 3 — *"any cross-method lock cycle is a pre-existing interaction whose shape this story does not alter"* — is a claim about `revoke()` racing **other methods**. Harness A is 8 threads all executing `revoke(TENANT_ADMIN)`: homogeneous, single-method, single-role. It proves the S-inside-X property and nothing about cross-method behaviour. Harness B is 8 self-revokes: narrower still.

**Required mitigation (RC-9).** Four parts, all cheap:
1. **Restate step 1 at index-record granularity** and pin the access path: an IT that captures `EXPLAIN` for M1 and M5 and asserts the chosen index (reuse `LastAdminLockoutIT`'s `captureHibernateSql` harness plus a `JdbcTemplate` `EXPLAIN`). If M5's plan is not `fk_user_roles_role`, either accept the extra acquisition **with the analysis written down**, or add an index hint / reorder the predicate so it is.
2. **State the REPEATABLE-READ dependency explicitly** in §7.2 and §6.4, and assert it — one `SELECT @@transaction_isolation` assertion in the concurrency IT is sufficient and permanent.
3. **Add harness C — mixed workload.** Same 8-thread `CyclicBarrier` shape, threads split across: `revoke(TENANT_ADMIN)`, `assign(TENANT_ADMIN)`, `revoke(dangerousCustomRole)`, `assign(dangerousCustomRole)`, and a **denied** non-admin `revoke(TENANT_ADMIN)` (which exercises the X-lock-then-403 path of T-D11). Same rule: any unexpected exception type fails loudly.
4. **Name T-D12 in §7.2 property 3.** The pre-existing `assign(TENANT_ADMIN)` × `revoke(TENANT_ADMIN)` interaction (S on the caller's row + insert-intention in the `role_id = adminRoleId` gap, versus M1's next-key range lock) is a real cycle **today**, unchanged by this story. Property 3 is correct that US-016 does not alter it — but if harness C surfaces it, the next reader must not conclude US-016 caused it.

**Residual after mitigation: Low.**

---

### T-D11 — Lock-hold and blast-radius amplification on `revoke()`'s denial path · **Medium** · ❌ change required

**Attack.** A non-admin holding `user:write` issues `DELETE /users/{anyAdmin}/roles/{TENANT_ADMIN}` in a loop. Per §6.2/§6.3, each request:

1. passes the 404 (the attacker enumerates admin holders via `GET /users/{id}/roles`, which needs only `user:read`);
2. acquires **M1's `FOR UPDATE` lock over every active `TENANT_ADMIN` assignment in the tenant** — a lock acquisition that, by D1/D2's deliberate design, precedes any authorization decision (§6.3, RES-4);
3. issues M8, then M5;
4. calls `recordDenial`, which borrows a **second pooled connection** for a `REQUIRES_NEW` transaction and commits it — **while the X lock is still held** (RES-5);
5. throws, rolls back, releases.

**What the attacker achieves.** For the duration of steps 2–5, *every* privileged operation in the tenant is blocked: any other `revoke(TENANT_ADMIN)` (needs M1's X set), and — this is the part that is new — **any admin's own gate check on any privileged assign or revoke**, because M5 now S-locks the caller's own `TENANT_ADMIN` row, which is inside the attacker's X set. Before US-016, an admin attaching a permission or assigning a role took that S lock on far fewer paths; after US-016 every privileged assign and every privileged revoke does. Sustained, this is a per-tenant denial of service against all privileged role administration, driven by a caller who is being denied on every request. Lock waits are bounded by `innodb_lock_wait_timeout` (MySQL default **50 s**), which is the ceiling on how long a victim admin's request hangs, not a mitigation.

**Existing mitigation.** RES-4 and RES-5, both rated **Low**, both accepted. RES-4's reasoning: *"The caller must already hold `user:write` — a tenant-privileged permission — and can trigger the identical X lock **today** with no gate at all, so this adds no new lever."*

**Why that reasoning is incomplete on two counts.**
- **Hold duration.** Today the attacker's request takes M1 and then immediately either 409s (WARN, throw, rollback — no audit write) or performs M6 and commits. After US-016 it takes M1 and then performs **two additional round trips plus a nested transaction on a second connection** before releasing. The lock is held materially longer, per request, deterministically.
- **Blast radius.** Today the X set conflicts with other `revoke(TENANT_ADMIN)` calls and `assign(TENANT_ADMIN)` inserts. After US-016 it also conflicts with the gate's S read on **every** privileged assign and revoke in the tenant. RES-4 assesses the lock as unchanged; it is the *contention graph around* the lock that changed.
- Neither residual composes the two, and neither notes that the path is **un-rate-limited** (T-D10).

**Required mitigation (RC-9 part 5 + RC-10).**
- **Move `recordDenial` off the locked path where it is safe to do so.** On the privilege-gate denial the transaction is doomed and the X lock confers nothing — the audit write does not need to happen inside it. Concretely: record the denial *after* releasing, or (simpler and consistent with US-014 AC4's durability requirement) accept the inline write but **measure and bound it** — a timer on the denial path with a documented ceiling, plus the runbook note RES-5 already promises. Whichever is chosen, §7.5 must show the composed hold time, not the two halves separately.
- **Throttle the path** (RC-10) — the real ceiling on this threat is request rate, not lock duration.
- Re-rate RES-4 and RES-5 as a single composed residual at **Medium**.

**Residual after mitigation: Low.**

---

### T-D10 — Unthrottled denial amplification against a `> 0` page alert and a durable audit row · **Medium** · ❌ change required

**Attack.** Both verbs are deliberately un-rate-limited (US-012's threat model: *"reachable solely by the tenant's most privileged principal"* — a premise this story does not change but does stress, since the denial population is now dominated by callers who are **not** that principal). Every denial produces:

- `nexus.rbac.permission_denied{permission="user:write", reason="NOT_TENANT_ADMIN"}` → matched by `nexus_rbac_self_escalation_attempt`: `increase(...[5m]) > 0`, severity **page**;
- a durable `ROLE_ASSIGNMENT_DENIED` row in `auth_events` (append-only, never pruned by this application);
- a `REQUIRES_NEW` transaction on a second pooled connection;
- a WARN log line.

A single `user:write` holder can therefore generate an unbounded page storm, unbounded `auth_events` growth, and sustained connection-pool churn — with no authentication failure, no 429, and no cap. On the revoke name-match path each iteration also does T-D11's lock dance.

**Existing mitigation.** Partial and largely structural rather than designed:
- `ROLE_ASSIGNMENT_DENIED` is **excluded from the PRIORITY audit lane** (`AuthEventType.java:48-49`), so a flood cannot displace `ROLE_ASSIGNED`/`ROLE_REVOKED`. This is a real mitigation and the design should claim it — it currently does not.
- `RbacAuditPort`'s never-throw contract means pool exhaustion degrades to a slow 403 plus `RBAC_AUDIT_WRITE_LOST`, never a hang or a wrong authorization outcome (RES-5). Correct.
- The existing HikariCP pool alert covers the connection dimension.

**What is missing.** Nothing bounds the request rate, and the design's §1 non-goals dismiss rate limiting in one clause (*"no epic requirement, this endpoint family is intentionally un-rate-limited per US-012's threat model"*). That inheritance was justified when the only denial reachable here was "a non-admin tried to grant literal `TENANT_ADMIN`" — an event with a near-zero base rate. It is no longer justified once the denial population includes every attempt on every privileged role on both verbs.

**Required mitigation (RC-10).** Three parts:
1. **Throttle the denial path, not the endpoint.** A cheap per-`(tenantId, actorUserId)` denial counter with a short window is sufficient and avoids re-litigating the endpoint's un-rate-limited posture: after N denials in a window, return 403 without performing M7/M8/M5, the audit write or the metric increment. Fails safe (still a 403), costs no new dependency, and directly bounds T-D11 and T-R9 as well. If the Architect prefers to reuse `LoginRateLimitFilter`'s mechanism at the filter layer instead, that is equally acceptable — the requirement is a bound, not a mechanism.
2. **Re-tier the page alert** (see RC-11) — `> 0` is not survivable as a page threshold on a floodable path.
3. **State the PRIORITY-lane exclusion as a mitigation** in §9.1, so a future story that adds `ROLE_ASSIGNMENT_DENIED` to the priority lane knows it is load-bearing.

**Residual after mitigation: Low.**

---

### RC-11's threat — Page-alert precision regression and a canary that pages on the happy path · **Medium** · ❌ change required

Two distinct problems with the same root: the design chose "no new counter" (D8) and "no new enum value" (D6), which is right for **detection coverage** and wrong for **detection precision**.

**Problem 1 — `nexus_rbac_self_escalation_attempt` becomes a false-positive generator at page severity.**

D6 reason 2 is correct and I confirm it: reusing `NOT_TENANT_ADMIN` means the existing page alert keeps matching every denial the new gate produces, with zero PromQL edits, and R5's *forgotten-edit* failure mode is closed by construction. That is the right call and I would not overturn it.

But the alert's name is `self_escalation_attempt` and its severity is **page**, and after US-016 its population includes a case that is neither self-escalation nor an attack: **a helpdesk or support operator holding `user:write` but not `TENANT_ADMIN`, attempting to remove an admin role from a departing employee.** That is a routine, well-intentioned, correctly-denied business action. It is also, in most organisations, more frequent than the attack. §9.3's mitigation is a **documentation edit** ("meaning updated to the four denial shapes it now covers"), which does not change the pager's behaviour.

D6 reason 3 answers this — *"precision is preserved where precision belongs… the new WARN marker carries `matchedOn` and `operation`"* — but a log field cannot re-tier a Prometheus alert. §8.3's own closing sentence concedes the instrument: *"If a future need arises to alert differently on the two, the correct instrument is a new counter with an `operation`/`matchedOn` tag, not a sixth enum value."* The need is not future; it arrives with this story.

**Problem 2 — the `privileged="true"` canary fires on the normal Epic-3 first-use sequence.**

D7's retargeted composed alert is `self_role_assignment{privileged="true"} and on(tenantId) dangerous_permission_granted`, severity **page**, with the first runbook step *"confirm the actor holds an active `TENANT_ADMIN` assignment."*

Trace the expected Epic-3 admin bootstrap: an admin creates a custom role → attaches `user:write` (→ `dangerous_permission_granted` fires) → self-assigns the role to verify it works (→ `self_role_assignment{privileged="true"}` fires, and legitimately: the gate passed because the actor **is** an admin). Both series fire, same `tenantId`, same window. **The canary pages on the single most likely legitimate sequence in the feature it was built to watch.**

Worse, it carries no field that resolves the ambiguity. The counter's tags are `{tenantId, privileged}`. The distinguishing fact — whether the actor held an active `TENANT_ADMIN` assignment — **is in hand at the emission point**: on any privileged assignment the gate has already executed M5 and knows the answer. §9.3's runbook therefore asks the operator to go and re-derive, by hand, a boolean the code discarded microseconds earlier.

There is also a structural subtlety worth stating plainly: on the success path a `privileged="true"` self-assignment implies the gate *passed*, which implies M5 returned true. So the canary cannot detect a bypass **around** the gate — only a bypass **inside** it, i.e. M5 answering the wrong question (T-E22's fail-open axes, or an M8 resolution bug). That is a genuinely valuable thing to detect and it is the right canary to have. It just needs to be able to say so.

**Required mitigation (RC-11).** Three parts:
1. **Add the counter D8 declined:** `nexus.rbac.privileged_role_change_blocked{operation, matchedOn}` — emitted at the same throw site as the WARN, from values already computed, **zero** new queries, bounded cardinality 2×2. Retarget the **page** alert to the high-signal shape (`matchedOn="DANGEROUS_PERMISSION"`, or `operation="assign"` with self-target) and demote the remainder to ticket. `nexus_rbac_self_escalation_attempt` stays exactly as written — so D6's zero-PromQL-edit property is preserved as a *floor*, with the new counter providing the precision on top. This resolves the design's own "the right instrument is a new counter" without touching `DenialReason`.
2. **Give the canary its discriminator.** Either add a bounded tag to `nexus.rbac.self_role_assignment` recording the gate's own admin determination, or — cleaner and cheaper — reduce the canary's page condition to the genuinely anomalous shape and leave the legitimate admin self-assignment as a ticket. Whichever is chosen, the alert that **pages** must not fire on "admin created a role, made it dangerous, and tried it".
3. **Rename or re-caption `nexus_rbac_self_escalation_attempt` in `docs/features/US-012/monitoring.md`**, since after this story it no longer describes what it matches. §9.3's edit 2 currently updates the meaning text but leaves a name that will mislead every future on-call.

**Residual after mitigation: Low.**

---

### T-T13 — The adapter gains full CRUD over `role_permissions`, the one table with no DB backstop · **Medium** · ❌ change required

**Verified.** `JpaRolePermissionRepository extends JpaRepository<RolePermission, RolePermissionId>` — so it exposes `save`, `saveAll`, `delete`, `deleteById`, `deleteAll`, `deleteAllInBatch` alongside its two curated `@Query` methods. Design §4.4 gives `JpaUserRoleAssignmentAdapter` a **new constructor dependency** on it, solely to serve one read.

**Why this matters here specifically.** `nexus_app` holds `INSERT` **and** `DELETE` on `role_permissions`, the table has no soft-delete column and no trigger, and US-015 recorded (T-E15 / RES-5) that AC7 is a *pure application-layer control* on it with **no DB backstop of any kind**. This is the only table in the RBAC schema where an accidental repository write from the wrong layer would actually execute: `roles` has no `UPDATE`/`DELETE` grant, `user_roles` has a no-DELETE trigger and a column-scoped `UPDATE`, `auth_events` is append-only. So the design hands the *assignment* adapter unrestricted write authority over precisely the rows whose contents its new gate reads — which is, word for word, the objection D3 raises against Option A one layer up:

> *"Option A would hand `RoleAssignmentService` `createRole`, `attachPermission` and `detachPermission` — write capability over the very `role_permissions` rows its new gate reads, which is precisely the authority the gate exists to protect."*

The argument is correct. It was applied at the application layer and not re-applied at the infrastructure layer, where the same capability arrives by a different route.

**Existing mitigation.** None specific. Generic: code review, and the adapter's "purely mechanical" Javadoc.

**Required mitigation (RC-12).** Cheapest first:
1. **Preferred — do not inject `JpaRolePermissionRepository` at all.** M7's JPQL (`SELECT p.name FROM RolePermission rp, Permission p WHERE rp.id.permissionId = p.id AND rp.id.roleId = :roleId`) does not need to live on the `RolePermission` repository; it is an ordinary JPQL query over two entities and can be declared on the **already-injected** `JpaRoleRepository`. Total new SQL stays at one query, the adapter's constructor gains **zero** dependencies (a strictly better outcome than the design's "one"), and §4.5's new repository method disappears. This also removes the note in §11.3 that `JpaUserRoleAssignmentAdapterTest`'s setup must change.
2. **Fallback** — if the query must stay on `JpaRolePermissionRepository` for cohesion, inject a narrow read-only interface instead of the `JpaRepository`, e.g. declare `interface RolePermissionNameReader { List<String> findPermissionNamesByRole(UUID roleId); }` and have `JpaRolePermissionRepository extends JpaRepository<…>, RolePermissionNameReader`, injecting only the reader into the adapter.
3. Either way, extend §4.4's Javadoc edit to say the adapter holds **no write capability over `role_permissions`**, so the property is stated where a future maintainer would remove it.

**Residual after mitigation: Low.**

---

### T-R8 — Denial rows are not discriminable, and the exposure-audit runbook produces false negatives · **Medium** · ❌ change required

Two problems in one component (the durable record of what happened).

**Part 1 — assign-side and revoke-side denials are indistinguishable in `auth_events`.** Verified: `recordDenial` writes `ROLE_ASSIGNMENT_DENIED` with `metadata = {traceId, roleId, roleName, attemptedBy, reason}`; `RbacAuthEventAdapter`'s `operation` value is a failure-metric tag only, never persisted. So an auditor reading the durable store cannot tell whether a denied actor tried to **grant themselves** admin-equivalent authority or to **strip an administrator** — materially different incidents with different responses. This is the design's RES-6, rated **Low**, with the compensating control *"the new WARN marker carries `operation`, and the audit row's `traceId` correlates to it."*

**That control has an unstated precondition: log retention ≥ `auth_events` retention.** `auth_events` is an append-only durable compliance store that this application never prunes; application logs are shipped to a log platform with a retention policy nobody has cited. If logs are retained for 30 days and audit rows forever, then for any incident older than 30 days the compensating control does not exist. This is the identical gap US-015 refused to accept: **RES-10** resolved it by requiring *"either add `recordRolePermissionDenied`… **or** record the asymmetry and mandate that the `RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED` WARN be **retained at least as long as `auth_events`**."* US-016 should follow its own epic's precedent rather than re-deriving a weaker answer.

**Part 2 — §10.4's exposure-audit procedure is wrong in a way that hides the case it exists to find.** Step 3 reads:

> *"cross-check each holder's `user_roles.assigned_by` against that tenant's active `TENANT_ADMIN` holders; a grantor who is not one is an exposure-window artefact."*

`assigned_by` records **who granted it**; the check compares against **who is an admin now**. Two errors follow:
- **False negative on the escalation case.** An attacker who used T-E16 to obtain admin-equivalent authority, or who was subsequently granted `TENANT_ADMIN` legitimately, appears in the *current* admin set — so their historical, illegitimate grants are cleared by the check. That is precisely the population the audit exists to surface.
- **False positive on legitimate history.** An administrator who has since offboarded is no longer in the current set, so every grant they ever made is flagged as an artefact.

The correct source is point-in-time: the `ROLE_ASSIGNED` history in `auth_events` (which carries the actor), cross-referenced against admin assignment/revocation history. US-015 T-R6/RES-7 already noted the JSON-path forensic query is required and already mandated it be written into a runbook.

**Also, step 2 is not executable by its intended audience.** It says *"reuses `UserRoleAssignmentPort.findActiveUserIdsForRole` … no new code"* — but that is a Java port method with no endpoint, no CLI, and no admin console. An operator following the runbook cannot invoke it. US-015's RC-6 hit this exact problem and resolved it by writing the **DBA SQL** into the runbook (`SELECT BIN_TO_UUID(user_id) FROM user_roles WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL;`) with an explicit note that no API provides it. §10.4 cites RC-6's port method but not RC-6's conclusion.

**Required mitigation (RC-13).**
1. Re-rate RES-6 to **Medium** and resolve it the way US-015 RES-10 was resolved: either persist `operation` in the denial metadata, **or** record the asymmetry and mandate in writing that the `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` WARN be retained at least as long as `auth_events`. Name the retention figure; do not leave it implied.
2. Replace §10.4 step 3 with a point-in-time check against `ROLE_ASSIGNED` audit history, and state plainly that a current-admin-set comparison produces false negatives on the escalation case.
3. Replace §10.4 step 2's port-method pointer with the executable DBA SQL, per US-015 RC-6.
4. State the audit's two blind spots that no query fixes: it sees only **currently active** assignments (a revoked escalation leaves no trace in `user_roles`), and only roles that are **currently** dangerous (a role that was dangerous and has been detached is invisible). Both are audit-history questions, not `user_roles` questions.

**Residual after mitigation: Low.**

---

### T-I10 — New privilege oracle on the target role · **Low-Medium** · ⚠️ accept explicitly

**Attack.** After US-016, a caller holding `user:write` learns, from the status code alone, whether an arbitrary role in their tenant carries a dangerous permission: `POST /users/{self}/roles {roleId}` returns **403 `RBAC_001`** if the role is privileged and **201 / 409** if it is not. This is a new channel: the only other way to learn a role's permission set is `GET /roles/{id}/permissions`, which requires **`role:read`** — a permission a `user:write` holder need not have (the permission catalogue is a flat set of independent strings; nothing in the schema, the seed data or the evaluator implies `user:write ⊇ role:read`).

**What it is worth to an attacker.** Target selection. It identifies, without `role:read`, exactly which roles are worth pre-positioning against (T-E21), which are worth attempting to strip, and — read in reverse over time — **when a previously benign role became dangerous**, i.e. when an administrator performed step 3 of T-E21. That last one is the most useful: it converts T-E21 from "self-assign and hope" into a polled trigger.

**Existing mitigation.** None stated — the design's §6.2 information-disclosure analysis considers only the 404-vs-403 ordering, not the 403-vs-201 outcome. Two real mitigating factors exist and should be claimed rather than left implicit:
- **Probing is loud.** Every probe emits a WARN, a `permission_denied` increment, and a **durable audit row**, and (today) trips a page alert. An attacker enumerating a tenant's roles generates one durable, attributable record per probe.
- Once RC-10 lands, probing is also **rate-bounded**.

**Required mitigation.** None beyond RC-10 — but the design must **record it**. §6.2's claim *"No new oracle"* is true for the ordering it analyses and false for the story as a whole; leaving that sentence unqualified is how a future reviewer concludes the question was asked and answered. Add one row to §12.3 (RES-8) stating the oracle, its bound (loud + rate-limited), and the fact that it is the acquisition step for T-E21's target selection.

**Residual: Low, accepted.**

---

### T-I11 — The 404-before-403 rationale rests on an unenforced permission implication · **Low** · ⚠️ correct the reasoning

§6.2 justifies keeping the gate after the 404 partly on the ground that *"the information it leaks to an unauthorized caller — 'this user does not hold this role' — is already freely readable by any `user:read` holder in the tenant via `GET /users/{id}/roles`."*

The decision is right (and the tripwire test `should_neverCallLockActiveAssignmentIds_when_adminRoleAssignmentNotFound` is an excellent mechanical control for it). The *justification* assumes the DELETE caller also holds `user:read`. `@RequiresPermission("user:write")` is the only gate on that verb, and permissions are independent strings. A principal with `user:write` and not `user:read` gets, from the 404-vs-403 split, an assignment-existence oracle they cannot otherwise obtain.

**Required.** One sentence in §6.2: the ordering is retained on compatibility and tripwire-test grounds (both sufficient on their own); the "already readable" argument holds only for callers who also hold `user:read`, which is not enforced. No behaviour change.

**Residual: Low, accepted.**

---

### T-I12 — 409 `RBAC_002` leaked the tenant's admin-roster state to unauthorized callers · **Low** · ✅ **closed by this story**

Recorded because it is a genuine security improvement the design makes and does not claim loudly enough. Today a non-admin `user:write` holder revoking a `TENANT_ADMIN` assignment receives **409 `RBAC_002`** if the target is the tenant's last active admin and **204** otherwise — a direct, unauthenticated-by-privilege read of tenant admin-roster state, and one that also tells the caller when a strip will succeed. D1's 403-before-409 ordering removes it: a non-admin now receives 403 in both cases and learns nothing. D1 reason 2 states this; it is correct, and it is the strongest of D1's four arguments.

**I looked for the mirror-image oracle D1 might have created and did not find one.** 403-before-409 on `revoke()` gives every unauthorized caller a uniform 403 regardless of business state — strictly less information than before. On `assign()` the gate already preceded the 409 (`RBAC_004`), so a non-admin cannot distinguish "already assigned" from "not assigned" for a privileged role either — also strictly less. The only new distinguishable outcome anywhere is T-I10's, which is on a different axis (the target *role*, not the tenant's state).

**Required.** None.

---

### T-E24 — AC5's narrowing proof · **Low** · ✅ valid, with one dependency to state

**I verified §6.4's proof independently and it holds.** Restating the chain in my own terms:

1. The AC5 branch is inside `nameMatch`, so `privileged` is true, so `requireActiveTenantAdmin` ran and did not throw ⇒ M5 returned true ⇒ the caller holds an active assignment of `adminRoleId` in `actor.tenantId()`.
2. On the `nameMatch` path `adminRoleId == role.getId()`, by `uq_roles_tenant_name UNIQUE (tenant_id, name)` under a case-insensitive collation (verified in V5:30-40).
3. M1's predicate is M5's minus the `userId` restriction, over the same `(roleId, tenantId, revokedAt IS NULL)` ⇒ the caller's own row is an element of `lockedActiveAdminIds` ⇒ the set is non-empty.
4. `size() <= 1` + non-empty ⇒ the set is exactly `{caller's own row}`.
5. `contains(ref.id())` ⇒ `ref` is the caller's own row ⇒ `targetUserId == actor.userId()`. ∎

**A consequence the design does not state, and should, because it is favourable.** After US-016 the ≥1-active-admin invariant is enforced *more* strongly than before, and by a different mechanism: since the caller must be an active admin to reach the AC5 branch, and the caller's own row is always in M1's set, no sequence of revocations can take a tenant below one admin — the last remaining admin is always the actor, and the actor cannot self-revoke. AC5 is no longer the *only* thing standing between a tenant and lockout; the gate is. §6.4 currently reads as a narrowing (a loss); it is also a strengthening, and saying so protects the guard from a future reader concluding it is now dead code and deleting it. The design's decision to **keep** the unit test as a synthetic-state guard-shape proof (§11.1, renamed with a §6.4 citation) is exactly right for that reason.

**The one dependency.** Step 3 assumes no admin assignment can be *created* between M1 and M5. That is guaranteed by M1's next-key/gap lock over the `role_id = adminRoleId` range under REPEATABLE READ, and by nothing else. Under READ COMMITTED the proof fails in a narrow corner (M5 true for a caller whose row was not in M1's set ⇒ the actor-agnostic scenario is reachable again). The outcome would still be a 409, so the security posture is unaffected — but the word "structurally" in "structurally unreachable" would be wrong, and it is about to be written into an amendment to a shipped Gate 1 resolution.

**Required.** Covered by **RC-9 part 2** (state and assert the isolation-level dependency). No behaviour change.

**Residual: Low.**

---

### T-E25 — D5's TOCTOU ruling is correct; one of its three reasons is factually wrong · **Low** · ⚠️ wording change required

**I stress-tested the "self-defeating race" argument in both directions and on both verbs, and the ruling survives.**

- **Assign, attach direction.** For a non-admin to benefit, a dangerous permission must be attached between M7 and the insert. Attach is AC11-gated to active admins ⇒ the attacker must already hold the authority the gate protects. Holds.
- **Assign, detach direction.** Detaching before M7 lets a benign-looking role through — but the role then confers nothing dangerous, and re-attaching is admin-gated. Holds.
- **Revoke, either direction.** The design does not analyse the revoke side of the race, and it should, because the attacker's goal there is *removal*, not acquisition — so the "the assignment confers nothing" argument does not transfer. Working it through: if M7 reads dangerous and the permission is then detached, the gate still fires (fail-closed, harmless). If M7 reads benign and the permission is then attached, the non-admin strips a role that has just become dangerous — **but they could have stripped that same role a microsecond earlier with full authorization**, because revoking a non-dangerous role is a legitimate `user:write` operation. The race grants no capability the attacker did not already have. **The ruling holds on revoke too, for a different reason than on assign, and §6.5 should say so** — a reader checking the symmetric verb currently finds only the assign-side argument.
- **Interaction with D2's lock-order change.** M7 executes *before* M1 on `revoke()`, so the permission-set read is taken outside the locked region on every path. That is the correct order (locking earlier would extend the X-lock hold that T-D11 is already about) and it introduces no new window, because M7's result only ever *enables* the gate — a stale "not dangerous" is the case analysed above, and a stale "dangerous" fails closed.

**The factual error.** §6.5 reason 1 states: *"The direction an attacker can drive without admin rights is detach"* — and RES-2 then characterises the full detach → assign → re-attach sequence as *"requires admin authority at both ends, so it is a self-collusion path, not a privilege escalation."* **Detach is not admin-gated.** Verified: `RoleManagementService.detachPermission`'s own Javadoc says *"No AC11 gate — detaching a permission reduces privilege, a deliberate asymmetry with `attachPermission`."* Detach requires `role:write` only.

**Does the correction change the rating? No — for a reason worth writing down.** `role:write` is itself a member of `RbacDangerousPermissions.NAMES`. An actor who can detach already holds admin-equivalent authority by this story's own definition, so the sequence is still not an escalation. The rating stands at **Low**; only the reason is wrong, and a wrong reason in a threat model is how the next story inherits a false premise.

**Required.** Correct §6.5 reason 1 and RES-2's description: the detach leg needs `role:write` (not admin), and the sequence is non-escalating because `role:write` is itself in the dangerous set — not because both ends are admin-gated. Add the revoke-side race analysis above to §6.5.

**Residual: Low, accepted** (as RES-2, rating unchanged).

---

### T-E26 — Admin-equivalent custom-role holders cannot administer privileged roles · **Low** · ✅ accepted, record it

The gate requires an active assignment of the **literally-named** `TENANT_ADMIN`. A user holding a custom role that carries all three dangerous permissions — a legitimate, US-015-sanctioned configuration — is therefore *subject to* the gate but can never *pass* it. Consequences: (a) an operational dead end that pressures tenants toward granting literal `TENANT_ADMIN`, which is broader than the custom role and worse for least privilege; (b) a tenant whose only privileged principals hold custom admin-equivalent roles cannot administer privileged role assignments at all.

This is **consistent with US-015 AC11**, which gates the mint side on the same literal role, so US-016 introduces no new inconsistency — it inherits one. It is also the same asymmetry RES-3 records from the lockout angle. Recording it as a distinct residual matters because RES-3 is framed as "custom roles get less protection"; T-E26 is the mirror: "custom roles get less *authority*". Both point at the same follow-on decision (should "admin" be a privilege test rather than a name test, on the *caller* side too?), which ADR-0017's own follow-on rule — *"any future 'is this role special?' decision in `rbac` must be expressed as a test over the role's permissions, not its name"* — arguably already commits the platform to, for the target role but not the caller. Worth one line in the ADR so the inconsistency is deliberate.

**Required.** Add as RES-9; add one sentence to ADR-0017's follow-on rules noting the caller-side test remains name-based by decision.

**Residual: Low, accepted.**

---

### T-S7 — Admin status spoofed via a stale JWT on the new privilege path · **Low** · ✅ closed

The attack (a caller whose admin assignment was revoked out of band but who holds an unexpired JWT still claiming it) is US-012 T-E7, and it is closed on the new path by construction: the gate's only admin determination is M5, a `PESSIMISTIC_READ` DB read on the caller's own row, and `RoleChangeActor` carries no permission or role data at all, so there is nothing stale to read. `callerHoldsActiveTenantAdmin` — the non-locking, name-based helper three methods away — is explicitly excluded (§4.1) and mechanically excluded by **MC-2**. The design mandates extending `RoleAssignmentSecurityIT`'s out-of-band-revocation IT to a dangerous custom role (§11.3), which is the right proof at the right level.

One note for `/breakdown`: MC-2's `verify(port, never()).findActiveAssignmentViews(any(), any())` must be asserted on the **privilege** path specifically, not on the service as a whole — `listActive` legitimately calls it, so a class-level assertion would be wrong and a test that accidentally exercises `listActive` would produce a confusing failure.

**Required.** None.

---

### T-T12 — Reserved-name squat / collation bypass of the name-match half · **Low** · ✅ closed, inherited

A tenant-created role named `tenant_admin` or `Tenant_Admin` would, if it could exist, either satisfy `isNamedTenantAdmin` spuriously or shadow M8's lookup. It cannot: `uq_roles_tenant_name` is `UNIQUE (tenant_id, name)` under `utf8mb4_0900_ai_ci`, so all case and accent variants collide with the seeded role; and US-015 **RC-1** reserved `RbacRoleNames.RESERVED = {TENANT_ADMIN, MEMBER}` at creation time (verified in `RbacRoleNames.java:22`). D3's insistence on a bare `r.name = :name` predicate (never `UPPER()`) keeps M8 both sargable and collation-consistent with the Java-side `equalsIgnoreCase`. The existing unit test `should_throwNotTenantAdmin_when_roleNameIsDifferentCaseVariantOfTenantAdmin` is the R-9 regression proof and §11.1 correctly refuses to weaken it.

**Required.** None.

---

## 4. Verdict on each of the design's claimed-closed items

Requested explicitly by the task; each is CONFIRMED or DISPUTED, with the finding that carries the disagreement.

| # | Design claim | Verdict | Basis |
|---|---|---|---|
| **1** | **D1** — gate (403) before AC5 lockout (409); no oracle created | **CONFIRMED** | All four arguments hold. The 409 leak is real and D1 removes it (**T-I12**). I searched the other side and found no mirror oracle from the ordering itself. Two qualifications, neither affecting the decision: a **new** oracle exists on a different axis (**T-I10**, 403-vs-201 discloses target-role privilege), and §6.2's "already readable via `user:read`" premise is unenforced (**T-I11**) |
| **2** | **D2** — X-first lock order fixes the deadlock; option (b) does not | **CONFIRMED as a decision; the proof is incomplete** | X-before-S is correct; §7.3's rejection of option (b) is sound (mode ≠ order, and the A/B cross-revocation counterexample is valid); the lock partition is clean on every path I could enumerate, and I could construct no new cycle. But step 1's containment is argued at logical-row granularity while InnoDB locks **index records**, and both D2 and §6.4 silently assume **REPEATABLE READ**. Harness A is homogeneous and cannot test property 3's cross-method claim. **Not a Blocker** — **RC-9** |
| **3** | **D3** — two narrow reads on `UserRoleAssignmentPort`, no capability leak | **CONFIRMED at the application layer · DISPUTED at the adapter layer** | The service gains no write capability and its constructor is unchanged; the names-not-boolean shape is a genuine strengthening. But `JpaRolePermissionRepository` is a full `JpaRepository`, and `role_permissions` is the one RBAC table with `INSERT`+`DELETE` grants, no trigger and no DB backstop. **T-T13 / RC-12** (fix: host M7's query on the already-injected `JpaRoleRepository` — zero new adapter dependencies) |
| **4** | **D4** — unified gate, one call site, correct `roleId` from M8 | **CONFIRMED** | The pseudocode passes `findRoleIdByName(actor.tenantId(), TENANT_ADMIN)`, not `role.getId()`; the containment argument is proved by `uq_roles_tenant_name`; fail-closed-on-empty precedes M5; the short-circuit cannot skip the read while clearing `privileged`; MC-3 pins the argument. One symmetric axis is unpinned: `targetUserId` instead of `actor.userId()` fails open identically — **T-E22 / RC-14** |
| **5** | **D5** — non-locking permission-set read; the exploitable race is self-defeating | **CONFIRMED as the ruling; one stated reason is factually wrong; the real gap is elsewhere** | The ruling survives stress-testing on both verbs and in both directions, including the interaction with D2 (M7 sits outside the locked region on every path — correct). But §6.5 reason 1 and RES-2 assert detach is admin-gated; **it is not** (`detachPermission` has no AC11 gate, by deliberate US-015 asymmetry). Rating unchanged (`role:write` is itself in the dangerous set), reason must be corrected — **T-E25**. The genuinely exploitable window is not the race at all: it is **T-E21**, which requires no race |
| **6** | **D6** — reuse `NOT_TENANT_ADMIN`; closes R5 "by construction" | **CONFIRMED on the false-negative axis · DISPUTED on the false-positive axis** | R5 as written (a forgotten PromQL edit silently blinds a page alert) is genuinely closed by construction, and that is the better engineering. But the same choice widens a `> 0` **page** alert's population from a near-zero-base-rate attack to include routine denied offboarding by non-admin operators, on two un-rate-limited verbs. §8.3 costs this as "the metric is coarser than the log"; a log field cannot re-tier a pager. §8.3's own escape hatch ("the right instrument is a new counter") is needed now — **RC-11** |
| **7** | **D7 / FR-6** — `privileged` tag makes the canary actionable and unambiguous | **DISPUTED** | The tag is genuinely free (the value is computed on every assign) and the reinterpretation is right. But the composed page alert fires on the **normal Epic-3 bootstrap sequence** (admin creates role → attaches `user:write` → self-assigns to verify), and the counter carries **no field** distinguishing that from a bypass — even though the gate computed exactly that boolean microseconds earlier. Structurally, the canary can only detect a bypass *inside* the gate (T-E22's fail-open axes), which is valuable and should be stated. Alert fatigue on the happy path is exactly what R8 warned against — **RC-11 part 2** |
| **8** | **Forward-only, no backfill; runbook pointer is sound** | **PARTIALLY CONFIRMED** | The decision is Gate 1's and correct; the release-note sentences in §10.4 are well-drafted and necessary. But the residual is **mis-scoped** — framed as a historical exposure window discharged by a one-off audit, when it is a permanent, repeatable, race-free primitive (**T-E21**, High) — and §12.2 item 6's instruction to flip RES-1/T-E16 to "closed" would delete the register's only record of the surviving path. The runbook pointer is **not** sound: step 2 names a Java port method no operator can invoke (US-015 RC-6 already solved this with DBA SQL), and step 3's current-admin comparison produces **false negatives on exactly the escalation case** — **RC-8, RC-13** |
| **9** | **§6.4 — AC5's actor-agnostic scenario is structurally unreachable** | **CONFIRMED** | Proof verified step by step; valid. Nothing depends on the scenario remaining reachable: the health indicator is name-based and unaffected, the unit test is correctly retained as a synthetic guard-shape proof, and the IT correctly flips to 403. Two additions required: state the **REPEATABLE READ** dependency (**RC-9**), and state that the ≥1-admin invariant is now enforced *more* strongly — by the gate — so a future reader does not delete AC5 as dead code (**T-E24**) |

---

## 5. Residual risk register

Continues the design's §12.3 numbering where entries correspond; ratings are mine and override the design's where they differ.

| # | Residual | Severity (design → mine) | Why accepted | Compensating control | Owner / review |
|---|---|---|---|---|---|
| **RES-1** | **Forward-only enforcement, in two components.** (a) *Historical:* pre-existing non-admin-granted assignments of roles that are already dangerous survive deployment. (b) **Standing primitive (T-E21):** any `user:write` holder may self-assign a benign custom role and be silently escalated whenever an administrator later attaches a dangerous permission to it. No race, no collusion, no gate evaluation, no signal at either end | Med → **High** | (a) is genuinely discharged by the §10.4 audit. (b) is **not** discharged by anything currently proposed, and is not a Gate 1 decision — Gate 1 decided against *backfill*, not against *forward detection* | (a) §10.4 exposure audit (as corrected by RC-13) + release-note sentences. (b) **RC-8**: mint-side holder-count signal at `attachPermission`, or a named successor story with an id before US-016 merges | **Md Nisar Ahmed (accountable, inherited from US-015 §4.5).** Review **2026-11-27**; **hard expiry Epic 3 kickoff** — inherited unchanged, and attaching to component (b) |
| **RES-2** | **Non-locking permission-set read (D5).** detach → assign → re-attach propagates privilege without the gate firing | Low → **Low** (unchanged) | The ruling is right and the sequence is non-escalating. **But the stated reason is wrong** — detach needs `role:write`, not admin. Non-escalating because `role:write` is itself in the dangerous set | Fully audited (`ROLE_PERMISSION_REVOKED` → `ROLE_ASSIGNED` → `ROLE_PERMISSION_GRANTED`, all correlatable by `tenantId` + `roleId`); MC-1 keeps the read non-locking. **Reason corrected per T-E25** | Architect (wording); Security (accepted) |
| **RES-3** | AC5 lockout and `RbacZeroActiveAdminsHealthIndicator` cover only the literally-named `TENANT_ADMIN`; a tenant can be zeroed out of an admin-equivalent custom role invisibly | Med → **Medium** (unchanged) | Out of scope by Gate 1 #8. Agreed — it is a different mechanism | This design strengthens the case (§6.4 corollary). Backlog story required | Architect; backlog entry is a **merge checklist item**, per the US-015 §4.5 precedent for exactly this pattern |
| **RES-4 + RES-5** | **Composed:** the X lock over every admin row in the tenant is acquired before the authorization decision and held across M8 + M5 + a `REQUIRES_NEW` audit write on a second connection, on a path any `user:write` holder can drive | Low + Low → **Medium (composed)** | Individually defensible; composed they change lock-hold duration *and* the contention graph, on an un-rate-limited path | **RC-9 part 5** (bound or relocate the audit write; publish the composed hold time) + **RC-10** (throttle). Never-throw audit contract; HikariCP pool alert; PRIORITY-lane exclusion | Architect |
| **RES-6** | Assign-side and revoke-side denials are indistinguishable in `auth_events`; discriminated only by a log field | Low → **Medium** | Adding `operation` to the audit event touches `identity` code the impact analysis verified needs no change — a real cost | **RC-13**: persist `operation`, **or** mandate WARN retention ≥ `auth_events` retention, in writing, with a figure. US-015 RES-10 precedent | Architect + Ops (retention is not an Architect-only decision) |
| **RES-7** | `permission_denied` cannot distinguish name-match from privilege-match, nor assign from revoke | Low → **Low** (unchanged, but see RC-11) | Correct as a metric-cardinality trade | The new `privileged_role_change_blocked{operation, matchedOn}` counter (RC-11) supersedes this residual rather than mitigating it | Architect |
| **RES-8** *(new)* | **Privilege oracle on the target role (T-I10).** A `user:write` holder without `role:read` can enumerate which roles carry dangerous permissions, and detect when one becomes dangerous, from 403-vs-201 | — → **Low** | Inherent to any gate that fails visibly; the alternative (uniform responses) would break the API contract and the 404 ordering | Probing is loud (WARN + counter + **durable audit row** per probe) and, after RC-10, rate-bounded. Note the linkage: this is T-E21's target-selection step | Security; accepted |
| **RES-9** *(new)* | **Admin-equivalent custom-role holders are gated but can never pass the gate (T-E26)** — the caller-side test remains name-based while the target-side test becomes privilege-based | — → **Low** | Consistent with US-015 AC11; making the caller-side test privilege-based is a materially larger decision | One sentence in ADR-0017's follow-on rules recording that the asymmetry is deliberate; pairs with RES-3 as the same follow-on question | Architect; Epic 3 |
| **RES-10** *(new)* | **Pre-existing cross-method deadlock (T-D12):** `assign(TENANT_ADMIN)` (S on caller's row → insert-intention in the `role_id` gap) versus `revoke(TENANT_ADMIN)` (M1 next-key range lock) can cycle. Real today; unchanged by this story | — → **Low (inherited)** | Genuinely pre-existing; §7.2 property 3 is correct that US-016 does not alter it | **RC-9 part 4**: name it, so harness C's findings are not misattributed to US-016. File as a separate backlog observation | Architect; backlog |
| **RES-11** *(carried from `03-design.md` §12.3; two sub-findings added by `07-security-review.md`)* | **Throttle (D14) side effects, three parts.** (a) *Benign-role collateral:* because the throttle check precedes M7, a throttled actor is also denied `assign()`/`revoke()` of **benign** roles for the rest of the window. (b) **M-1 — attacker-controlled detection blind spot:** a suppressed request emits no WARN, no `privileged_role_change_blocked` increment and no durable audit row; because the throttle key `(tenantId, actorUserId)` is the attacker's own identity, they can order cheap `ROLE_NAME` denials first to choose when suppression begins, hiding subsequent `DANGEROUS_PERMISSION` attempts from the page-severity `nexus_rbac_privileged_role_change_blocked_dangerous` alert. (c) **M-3 — per-replica bound:** under the default `InMemoryRateLimitStore`, the denial count itself is per-JVM, so an N-replica deployment's effective bound is `max-denials × N` fully processed denials per window, not the documented single-replica figure; the throttled-until transition map stays per-replica even under `store-type=redis` | Low → **Low (unchanged; detection-quality and DoS-bound gaps, not authorization gaps)** | (a) Accepted, bounded at W seconds (default 60), self-clearing, the price of not evaluating the gate just to find out whether a request would have been denied anyway. (b)/(c) Not exploitable for access — the gate still denies every request — but adversarially reachable and worth naming explicitly rather than leaving §4.8's "D14 bounds them" reasoning unqualified | (b) **Mitigated:** `nexus_rbac_denial_throttle_engaged` promoted ticket → page (`docs/features/US-012/monitoring.md` §2), so entering suppression always pages regardless of the attacker's chosen ordering — the suppressed attempts' own `matchedOn` shape must still be reconstructed by hand from the preceding durable rows. (c) **Documented, not code-mitigated:** `03-design.md` §4.8 and `monitoring.md` §3 state the per-replica caveat; `runbook.md` §3 tells operators to set `store-type=redis` or divide `max-denials` by replica count in any multi-replica deployment | Security (alerting); Architect/Ops (multi-replica deployment guidance) |

---

## 6. Cross-references to prior threat models

| Prior threat | Status after US-016 |
|---|---|
| **T-E16** (US-015) — propagate-side self-escalation via `assign()` | **Closed for the direct path.** A non-admin can no longer assign a role that carries a dangerous permission at assign time. **Not closed** for the attach-after-assign path — carried forward as **T-E21 / RES-1** |
| **T-E17** (US-015) — revoke-side administrator stripping (N→1) | **Closed.** The symmetric gate denies any non-admin revocation of a privileged role. I could construct no surviving variant. §12.2 item 6 may flip this one unconditionally |
| **T-E9** (US-012) — `revoke()` has no symmetric admin check | **Closed.** This is the story. The Javadoc replacement in §4.2 is correct and correctly refuses to delete the note |
| **T-E7** (US-012) — admin status must be a live locking read, never a JWT claim | **Preserved on the new path** (T-S7). M5 reused verbatim; MC-2 is the mechanical control; the stale-JWT IT is extended |
| **T-E14** (US-015) — the non-locking-read trap on an admin gate | **Correctly distinguished, not copied.** D5 reasons the *permission-set* read to the opposite conclusion from the *admin-status* read, with three sound reasons and one wrong one (T-E25). Impact §6.4's warning that "T-E14 was High, so lock everything" is the wrong inference is upheld |
| **T-E18 / R-10** (US-015) — fail closed when the tenant has no `TENANT_ADMIN` role | **Precedent followed exactly.** M8 empty ⇒ deny, before M5 is reached; the name-match-path asymmetry is correctly identified as a data bug rather than a legitimate state |
| **T-E15 / RES-5** (US-015) — `role_permissions` has no DB backstop; MEMBER amplification | **MEMBER path verified closed** by RC-5b (reserved system role, AC7 before AC11). **The no-backstop property becomes newly load-bearing** for T-T13 |
| **T-E20 / RES-9** (US-015) — flag-off is not a privilege rollback | **Inherited and correctly restated** in §10.3. D10's refusal to add a story-specific flag whose "off" position is the vulnerability is the right conclusion from the same premise |
| **T-D6** (US-015) — unthrottled writes on the RBAC surface | **Extended to the denial path** as T-D10. US-015's finding was about resource growth; this one is about a page alert and an audit row |
| **T-R7 / RES-10** (US-015) — denials not durably audited / the log-retention question | **Inverted and re-encountered.** US-016's denials *are* durably audited (US-014 AC4), but the field that discriminates them is log-only — the same retention question, on the other side (T-R8) |
| **T-R6 / RC-6** (US-015) — no reverse lookup for "who holds role X"; DBA SQL written into the runbook | **Precedent cited but not followed.** §10.4 points at the Java port method rather than RC-6's executable SQL (RC-13) |
| **T-I8** (US-015) — ~30-minute permission staleness | **Unchanged, and in the safe direction for denials.** A denial has no privilege effect to propagate; a successful privileged assignment takes up to ~30 min to become effective, which is a detection window |
| **T-D3** (US-012) — M1's lock scope is confined to one tenant's rows | **Still true, and now more consequential** (T-D11): the same confined lock now conflicts with far more concurrent operations |
| **T-I5** (US-012) — `assignedBy` redaction in `listActive` | **Untouched.** `callerHoldsActiveTenantAdmin` remains the non-locking, name-based redaction helper and is explicitly excluded from the gate (§4.1, MC-2) |

---

## 7. Threats requiring design changes

**These must go back to the architect before Gate 2 can close.** Each becomes one `/breakdown` task unless noted. **RC-8 part 3 is the only one requiring a decision rather than an edit** — flag it first.

---

### RC-8 — Re-scope RES-1 and decide the mint-side holder signal *(T-E21, **High**)* — **the most important change in this list, and the one that goes back to the Architect**

1. Re-rate RES-1 to **High** in §12.3 and split it into (a) the historical exposure window and (b) the standing pre-positioning primitive (T-E21), with the description in §3.
2. Correct §12.2 item 6: **T-E17 → closed**; **T-E16 → closed for the direct propagate path, with the attach-after-assign path carried forward as US-016 T-E21 / RES-1.** RES-1's owner, 2026-11-27 review and Epic-3 hard expiry transfer to the surviving component. Update the §4.2 Javadoc replacement text accordingly — it currently claims RES-1/T-E16 are closed outright.
3. **Architect decision:** ship the mint-side signal in US-016, or name a successor story with an id before US-016 merges. The signal: at `RoleManagementService.attachPermission`, when `dangerous == true`, call the existing `UserRoleAssignmentPort.findActiveUserIdsForRole(roleId)` and emit the holder count on the `ROLE_PERMISSION_GRANTED` audit event / WARN and as a bounded bucket tag (`0`, `1`, `2-10`, `>10`) on `nexus.rbac.dangerous_permission_granted`. One bounded query on a rare admin-only path; no schema change; no new port method. This is the same shape and the same justification as US-015's RC-7, which was accepted.

### RC-9 — Complete D2's proof, state the isolation dependency, and add a mixed-workload harness *(T-E23 / T-D11 / T-D12 / T-E24, Medium)*

1. Restate §7.2 step 1 at **index-record** granularity; pin M1's and M5's access paths with an `EXPLAIN`-asserting IT. If M5 does not use `fk_user_roles_role`, write down the resulting non-contained acquisition and analyse it.
2. State the **REPEATABLE READ** dependency explicitly in both §7.2 and §6.4, and assert it (`SELECT @@transaction_isolation`) in the concurrency IT.
3. Add **harness C — mixed workload**: 8 threads across `revoke(TENANT_ADMIN)`, `assign(TENANT_ADMIN)`, `revoke(dangerousCustomRole)`, `assign(dangerousCustomRole)` and a **denied** non-admin `revoke(TENANT_ADMIN)`. Same `CyclicBarrier` shape, same "unexpected exception type fails loudly" rule.
4. Name the pre-existing `assign` × `revoke` cycle (T-D12 / RES-10) in property 3, so harness C's findings are attributed correctly.
5. Bound or relocate the denial-path audit write, and publish the **composed** X-lock hold time in §7.5 rather than the two halves separately.

### RC-10 — Bound the denial path *(T-D10 / T-R9 / T-D11, Medium)*

1. Add a per-`(tenantId, actorUserId)` denial throttle: after N denials in a window, return 403 **before** M7/M8/M5, the audit write and the metric increment. Fails safe; no new dependency; directly bounds T-D10, T-R9 and T-D11. A filter-layer equivalent reusing `LoginRateLimitFilter`'s mechanism is equally acceptable.
2. Record the value of N and the window in `docs/features/US-016/monitoring.md`, and alert on the throttle firing.
3. State the `ROLE_ASSIGNMENT_DENIED` **PRIORITY-lane exclusion** in §9.1 as a load-bearing mitigation.

### RC-11 — Restore alert precision and give the canary a discriminator *(D6/D7 consequences, Medium)*

1. Add `nexus.rbac.privileged_role_change_blocked{operation, matchedOn}` at the WARN's throw site — zero new queries, cardinality 2×2. Leave `nexus_rbac_self_escalation_attempt` **exactly as written** (preserving D6's zero-edit floor) and retarget the **page** to the high-signal shape, demoting the rest to ticket. This is §8.3's own stated "correct instrument", brought forward.
2. Ensure the `privileged="true"` canary cannot page on the Epic-3 bootstrap sequence: either carry the gate's admin determination as a bounded tag, or reduce the page condition to the anomalous shape and leave admin self-assignment as a ticket. Record in the runbook that the canary detects a bypass **inside** the gate (T-E22's axes), not around it.
3. Rename or re-caption `nexus_rbac_self_escalation_attempt` in `docs/features/US-012/monitoring.md` — after this story the name no longer describes what it matches.

### RC-12 — Do not give the assignment adapter write capability over `role_permissions` *(T-T13, Medium)*

1. **Preferred:** declare M7's JPQL on the already-injected `JpaRoleRepository`. `JpaUserRoleAssignmentAdapter`'s constructor then gains **zero** dependencies, §4.5's new repository method disappears, and §11.3's adapter-test setup change is unnecessary.
2. **Fallback:** inject a narrow `RolePermissionNameReader` interface that `JpaRolePermissionRepository` also extends, never the `JpaRepository` itself.
3. Extend §4.4's Javadoc edit to state that the adapter holds no write capability over `role_permissions`.
4. Add the tenant-scoping precondition to M7's port Javadoc (T-I13): *"`roleId` MUST already have been tenant-verified by the caller; this method performs no tenant check."*

### RC-13 — Fix the audit record and the exposure-audit runbook *(T-R8, Medium)*

1. Re-rate RES-6 to Medium; resolve as US-015 RES-10 was resolved — persist `operation` in the denial metadata, **or** mandate in writing that the WARN be retained at least as long as `auth_events`, **with the figure named**.
2. Replace §10.4 step 3's current-admin comparison with a point-in-time check against `ROLE_ASSIGNED` audit history, and state that the current-set comparison yields false negatives on exactly the escalation case.
3. Replace §10.4 step 2's port-method pointer with executable DBA SQL, per US-015 RC-6.
4. State the audit's two blind spots: revoked escalations and roles that have since been detached are invisible to a `user_roles` query.

### RC-14 — Extend MC-3 to the `userId` axis *(T-E22, Medium)*

1. Every privilege-path unit test that is not a deliberate FR-4 self-assignment case must use `targetUserId != actor.userId()`.
2. Add `verify(port, never()).hasActiveAdminAssignment(eq(targetUserId), any(), any())` alongside the existing MC-3 assertion.
3. State in MC-3's row that it covers **both** arguments.

### Editorial corrections (not tasks; fold into `03-design.md` at Gate 2)

- §6.5 reason 1 and RES-2: detach is **not** admin-gated; the sequence is non-escalating because `role:write` is itself in the dangerous set (T-E25). Add the revoke-side race analysis.
- §6.2: qualify "No new oracle" — true for the ordering analysed, not for the story (T-I10); and the "already readable via `user:read`" premise is unenforced (T-I11).
- §6.4: add that the ≥1-admin invariant is now enforced *more* strongly, by the gate, so AC5 is not mistaken for dead code (T-E24).
- ADR-0017 follow-on rules: one sentence recording that the **caller**-side admin test remains name-based by decision, while the **target**-side test becomes privilege-based (T-E26 / RES-9).

---

## 8. Gate 2 recommendation

**Conditional pass.** No Blocker. The design closes T-E9 and T-E17 outright and closes the direct path of T-E16; on every path I could construct, US-016 is strictly stronger than the status quo, and I found no way for the fix to be turned against itself — no ordering trick, no short-circuit exploit, no fail-open in the interaction between D1's decision order and D2's lock order.

**Gate 2 may close once RC-8…RC-14 are folded into `03-design.md`.** Six of the seven are editorial or test-shaped and none reopens Gate 1 or requires a new ADR beyond the two sentences named above.

**Send back to the Architect before Gate 2: RC-8 part 3.** It is a scope decision, not an edit — ship the mint-side holder signal in US-016, or file the named successor story with an id before merge. Either answer is acceptable; silence is not, because §12.2 item 6 as currently written would flip US-015's RES-1 to "closed" and delete the only record of the path that survives. That is the specific outcome US-015's Gate 2 built the closure-reference discipline to prevent, and this story is where the discipline gets tested.

**Merge checklist items (non-code), following the US-015 §4.5 precedent:**
- RES-1's surviving component has a named owner, the inherited 2026-11-27 review date, and the Epic-3 hard expiry, recorded before merge.
- RES-3's backlog story exists with an id before merge.
- RC-8 part 3's outcome (shipped, or successor story id) is recorded in §12.3 before merge.
- `./mvnw dependency:tree` and `npm audit` run at **Phase 7**, not skipped — no manifest delta exists today (verified §0.1), so there is nothing to scan at Gate 2.

### Cross-references

- `docs/features/US-016/03-design.md` — the artifact under review (§14 lists the inputs this document discharges)
- `docs/features/US-016/01-requirements.md` — Gate 1 decisions (binding)
- `docs/features/US-016/02-impact.md` — Phase 2; R1–R9 are the risks this document rates
- `docs/features/US-015/03b-threat-model.md` §4.5, §5, §7 — RES-1 / T-E16 / T-E17 / RC-6 / RC-7 / RES-10, the precedents this document applies
- `docs/features/US-012/03b-threat-model.md` — T-E7, T-E9, T-D3, T-R4; `monitoring.md` §1/§2/§5
- `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` D1/D3 — anchors for ADR-0017
