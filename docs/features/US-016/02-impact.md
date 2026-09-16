# US-016 — Impact Analysis (Phase 2)

**Story:** Gate role assignment/revocation by actual privileges, not role name
**Epic:** EPIC-002 — RBAC Foundation
**Gate 1 basis:** `docs/features/US-016/01-requirements.md` — the "Gate 1 Decisions (recorded 2026-09-09)" section is treated as settled and is not re-litigated here. FR-1…FR-6 are inputs, not questions.
**Method:** every claim below was verified by reading the current code on branch `feature/US-016`. Line ranges are from the files as they stand at commit `76470e2`.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Modules affected | Backend only — `rbac.application`, `rbac.application.port.out`, `rbac.infrastructure.persistence`, `common.security` (one enum value), plus tests and docs |
| Frontend affected | **No** — confirmed by exploration, not assumed (§4) |
| DB schema changes | **None.** No migration, no new index, no grant change — **conditional** on the new privilege read being non-locking on `permissions` (§2) |
| REST contract changes | **No new endpoint, no DTO change.** But there *is* a behavioural authorization change on two shipped verbs, and one additive field-value change in the 403 body (§3) |
| Breaking changes | **Yes, deliberately** — two behavioural breaks, one of which (`revoke()`) makes an existing, documented AC5 test scenario structurally unreachable (§9) |
| New dependencies | **None** (§8) |
| Data migration | **None** — forward-only by Gate 1 decision #7 (§10) |
| ADR | Required. Recommend a **new ADR (next free number: 0017)** that extends ADR-0013, appended-to-not-edited per ADR-0001 (§11) |

---

## 1. Modules, classes, and call sites affected

### 1.1 Primary — `rbac.application`

**`nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`** (451 lines)

| Region | Lines | What changes |
|---|---|---|
| Constructor + fields | 61–78 | Gains at least one collaborator capability. Today the class depends on exactly five: `UserRoleAssignmentPort`, `UserDirectoryPort`, `RbacAuditPort`, `PermissionCachePort`, `MeterRegistry`. **`RoleManagementPort` is not among them** (verified) |
| `assign()` M-3 Javadoc | 80–110 | Must be **replaced with a closure reference, never deleted** — this is a binding instruction from US-015 design §10.3 and repeated verbatim in the code at line 108–109 |
| `assign()` name-match gate | 126–143 | The privilege test composes here. Per Gate 1 decision #5's recommended default, this becomes one condition, not two sequential gates |
| `assign()` admin read | 134–136 | `hasActiveAdminAssignment(actor.userId(), role.getId(), actor.tenantId())` — **`role.getId()` is the third argument**. See §1.5: this call site cannot be reused verbatim for the privilege path |
| `revoke()` T-E9 Javadoc | 215–233 | Same replace-not-delete treatment |
| `revoke()` — new gate | between 250 and 252 | `revoke()` has **no admin gate at all today**. The new gate is inserted; its exact position relative to `findAssignmentRefOrThrow` (250) and the AC5 lockout block (252–269) is a design decision with direct test consequences (§9.3, §12) |
| `recordDenial` | 405–427 | Reused unchanged for the new denial (FR-5). No signature change needed — it already takes a `DenialReason` |
| `listActive` / `callerHoldsActiveTenantAdmin` | 314–347 | **No change.** The non-locking helper at 342–347 must not be reused for the new gate (it is documented as redaction-only, and US-015's RC-5a made the mirror-image mistake a build failure — §1.6) |

### 1.2 Reuse candidates — verified still correct

| Candidate | Location | Verdict |
|---|---|---|
| `RbacDangerousPermissions` | `rbac/domain/RbacDangerousPermissions.java:11–27` — `NAMES` at 13, case-insensitive `contains` at 19–24 | **Reusable as-is, no change.** Already unit-tested (`rbac/domain/RbacDangerousPermissionsTest.java`). Its `contains()` deliberately mirrors `utf8mb4_0900_ai_ci`, which matters if the design compares names in Java rather than SQL |
| `RoleManagementService.verifyCallerIsActiveTenantAdmin` | `rbac/application/RoleManagementService.java:280–312` | **Mechanism reusable, code not.** It is `private`, takes `RoleView`/`PermissionView` (types `RoleAssignmentService` never handles), and logs a US-015-specific marker. The reusable part is the two-step shape: Q3 `findRoleIdByName` (292–293) → `hasActiveAdminAssignment` (296–299), **fail-closed when Q3 is empty** (295) |
| `RoleManagementPort.findPermissionsForRole` (Q7) | `rbac/application/port/out/RoleManagementPort.java:74–78`; adapter at `JpaRoleManagementAdapter.java:108–111`; query at `JpaRolePermissionRepository.java:21–28` | **Right mechanism, wrong port.** See §1.4 |
| `UserRoleAssignmentPort.hasActiveAdminAssignment` | `port/out/UserRoleAssignmentPort.java:35–42`; adapter 49–52; query `JpaUserRoleRepository.java:152–160` (`@Lock(PESSIMISTIC_READ)`) | **Reusable unchanged** — but see §1.5 (argument) and §6.3 (lock interaction) |
| `DenialReason` | `common/security/DenialReason.java:8–16` — 5 values, `NOT_TENANT_ADMIN` at 15 | Zero or one new value. No test asserts the enum's cardinality (checked `common/security/*Test.java`), so adding a value breaks **no** test — only docs (§3.3) |

### 1.3 What the new gate actually needs (two distinct capabilities)

The gate needs **two** reads that `RoleAssignmentService` cannot perform today:

1. **"Does the target role carry any `RbacDangerousPermissions` member?"** — no port reachable from this service can answer this.
2. **"What is this tenant's `TENANT_ADMIN` role id?"** — also unavailable. This is explicitly documented at `RoleAssignmentService.java:334–336`: *"the port exposes no 'find role by (tenant, name)' lookup."* The existing name-match path sidesteps it because the role being assigned **is** the admin role, so `role.getId()` is already the admin role id.

Capability 2 is easy to miss when scoping this story. It is not optional: on the privilege path the target role is a *custom* role, so `role.getId()` is the wrong argument for `hasActiveAdminAssignment` — passing it would silently check whether the caller holds *the custom role*, which is both wrong and would fail-open in the common case. This is the single most likely silent-failure mode in the implementation.

### 1.4 Port choice — the two options, assessed

**Option A — inject `RoleManagementPort` into `RoleAssignmentService`** (uses Q7 + Q3 as-is, no new port method).

- Pro: zero new persistence code; both queries already exist, are tested (`JpaRoleManagementAdapterTest`), and Q3's index discipline is already documented.
- Con 1 — **it hands this service write capability it must not have.** `RoleManagementPort` exposes `createRole` (34), `attachPermission` (90), `detachPermission` (98). This codebase has already rejected exactly this trade twice, in writing: `UserRoleAssignmentPort.java:11–20` ("*widening it would leak a write capability to a read-only collaborator*") and `RoleManagementPort.java:10–22` ("*One port, not a split, and not a widening of `UserRoleAssignmentPort`*").
- Con 2 — it **falsifies `RoleManagementPort`'s own Javadoc** at line 15–16: *"There is exactly one consumer (`RoleManagementService`)."* That statement is load-bearing for the port's "no split" rationale; a second consumer means the Javadoc must be amended and the no-split argument re-made.
- Con 3 — first-of-its-kind coupling. No ArchUnit rule forbids it (checked `HexagonalArchitectureTest.java` in full: `rbac_must_not_depend_on_identity` at 113–125 governs cross-*context*, not intra-context, direction), so this would pass the build while introducing an undiscussed dependency edge inside `rbac.application`.

**Option B — add narrow read capability to `UserRoleAssignmentPort`** (one boolean-shaped "does this role carry any of these permission names" read, plus a role-id-by-name read).

- Pro: keeps `RoleAssignmentService` on exactly one persistence port, matching its current shape; no write capability leaks; the answer can be a `boolean`, which is unignorable and carries no `PermissionView` payload this service has no use for.
- Pro: the adapter cost is near-zero. `JpaUserRoleAssignmentAdapter` (`infrastructure/persistence/JpaUserRoleAssignmentAdapter.java:24–37`) already injects two repositories; it would add `JpaRolePermissionRepository` (which already holds the Q7-shaped query, 21–28) and `JpaRoleRepository` already has `findIdByTenantIdAndName` (used by `JpaRoleManagementAdapter.java:85–87`).
- Con: two new port methods and their adapter tests; a second query doing morally the same job as Q7 (mitigated if the new one returns a boolean rather than duplicating the projection).
- **Discipline note:** `JpaUserRoleAssignmentAdapter`'s Javadoc (17–22) states the adapter *"does not resolve `TENANT_ADMIN` by any hardcoded literal — that resolution happens in the service layer, per 03-design.md §5.2's R-9 discipline."* By symmetry the *dangerous permission names* must also not be hardcoded in the adapter or repository; they should arrive as a parameter from the service so `RbacDangerousPermissions` stays the single source of truth. This is a constraint on Option B's shape, not an argument against it.

**Recommendation: Option B**, on the strength of Con 1 and Con 2 above — this repository has already paid for the "don't widen a port to leak write capability into a read-only collaborator" principle twice and written the reasoning down both times. Deviating from it here would need the ADR to argue against the project's own precedent, which is a worse trade than two narrow port methods. **Design phase owns the final call and the exact signatures.**

### 1.5 Can the existing `hasActiveAdminAssignment` call site be reused?

Partially, and only if it is *generalised*:

- Today (`RoleAssignmentService.java:134–136`) the third argument is `role.getId()`, correct **only** because the name match guarantees `role` *is* the tenant's `TENANT_ADMIN`.
- Under Gate 1 decision #5's unified condition, the gate must resolve the admin role id independently (capability 2, §1.3) and pass *that*. For the name-matched case the two are provably equal — `uq_roles_tenant_name` is unique per `(tenant_id, name)` and case-insensitive by collation, so `findRoleIdByName(tenant, "TENANT_ADMIN")` can only return `role.getId()` when `role.getName()` matches case-insensitively.
- Therefore **one generalised call site is correct and safe**, and is preferable to two (it cannot drift). Cost: one extra Q3 read on the name-match path, which previously needed none. Benefit: one gate, one denial, one audit row (Edge Case 3 resolved structurally rather than by ordering rules).
- **Fail-closed obligation:** generalising imports US-015's R-10/T-E18 obligation — Q3 empty ⇒ deny. Note the resulting asymmetry worth stating in the design: on the name-match path Q3 *cannot* be empty (the role we just resolved is named `TENANT_ADMIN` in this tenant), so an empty Q3 there indicates a collation/consistency bug, not a legitimate un-seeded tenant. Fail closed regardless.

### 1.6 Mechanical-control gap this story should close

US-015 converted the mirror-image mistake into a build failure: `HexagonalArchitectureTest.role_management_service_must_not_call_the_non_locking_admin_read` (`HexagonalArchitectureTest.java:174–197`) forbids `RoleManagementService` from calling `UserRoleAssignmentPort#findActiveAssignmentViews`.

`RoleAssignmentService` has **no equivalent protection** and is now the more dangerous case: it legitimately calls `findActiveAssignmentViews` at line 343–346 for `listActive`'s redaction, so the wrong (non-locking, name-based) helper is *already in the file*, three methods away from the new gate. The realistic failure is not calling a private helper on another class — it is copying the shape that is already local. Design should specify a mechanical control (a targeted collaborator test asserting the new gate path invokes the locking read, since a blanket ArchUnit ban is impossible here — `listActive` needs the method).

### 1.7 `common.security`

`nexus-backend/src/main/java/com/example/nexus/common/security/DenialReason.java` — zero or one new value (Gate 1 deferred, recommended default: add one).

Note this file lives in `common`, shared with `identity`/US-011's `TenantAwarePermissionEvaluator`. Adding a value is additive and touches no `switch` (verified: no exhaustive switch over `DenialReason` exists anywhere in `src/main`; the only consumers stringify it — `GlobalExceptionHandler.java:162,169` and `RbacAuthEventAdapter.java:87`).

### 1.8 Not affected — verified, not assumed

| Component | Why unaffected |
|---|---|
| `rbac/interfaces/rest/UserRoleController.java` | Calls `assign` (104) / `revoke` (162) with unchanged signatures; the new denial is an `InsufficientPermissionException`, already mapped |
| `common/web/GlobalExceptionHandler.java:159–176` | Already handles `InsufficientPermissionException` generically — no new handler, no new error code (still `RBAC_001`/403) |
| `rbac/application/RoleResolutionService`, `UserRoleQueryPort`, `PermissionCachePort` | The gate denies before any write; nothing is assigned, so nothing to evict. No cache-key or TTL change |
| `identity` context | `RbacAuthEventAdapter` needs no code change — `recordRoleAssignmentDenied` (79–88) already threads an arbitrary `DenialReason.name()` into `metadata.reason` (239–241). **Its Javadoc does need updating** (§3.3) |
| `AuthEventType` | `ROLE_ASSIGNMENT_DENIED` already exists (`identity/domain/AuthEventType.java:49`) and is deliberately non-priority-lane (63). No new event type, so no audit-lane or threshold change |
| Flyway migrations | §2 |

---

## 2. Database changes

**None required.** Verified in detail:

| Concern | Finding |
|---|---|
| New table/column | None. The gate is a pure read over `roles`, `role_permissions`, `permissions`, `user_roles` |
| New index | **Not needed.** `pk_role_permissions PRIMARY KEY (role_id, permission_id)` (`db/migration/V5__rbac_schema.sql:49`) makes the dangerous-permission lookup a leftmost-prefix PK range scan bounded at 7 rows, followed by PK lookups on `permissions`. The admin-role-id lookup is served by `uq_roles_tenant_name` (V5:39), exactly as Q3 already is |
| `ddl-auto=validate` / ADR-0003 | No entity mapping changes ⇒ nothing for `validate` to reject. No migration file added |
| Expand/contract | Not applicable — zero non-additive changes |
| Seed data relevance | `V5:130–136`: the seeded `TENANT_ADMIN` carries **all 7** permissions (including all three dangerous ones); the seeded `MEMBER` carries **only `user:read`**. Consequence: the privilege test fires on the seeded admin role (both conditions true — Edge Case 3, hence §1.5's one-gate recommendation), and never on `MEMBER`. There is **no** seeded role whose assignment becomes admin-gated by accident |

### 2.1 Grant constraint — a production-only failure mode the design must respect

`nexus-database/mysql/init/02-grants-post-schema.sql:31–35`:

```
GRANT SELECT                 ON nexus.permissions      -- SELECT ONLY
GRANT SELECT, INSERT         ON nexus.roles
GRANT SELECT, INSERT, DELETE ON nexus.role_permissions
GRANT SELECT, INSERT         ON nexus.user_roles
GRANT UPDATE (revoked_at)    ON nexus.user_roles
```

MySQL requires `SELECT` **plus at least one of `DELETE`, `LOCK TABLES`, or `UPDATE`** to execute a locking read (`FOR SHARE` / `FOR UPDATE`) against a table. `nexus_app` holds **only `SELECT` on `permissions`**.

⇒ **A locking read that touches `permissions` will be rejected in production and will pass every single test**, because every `*IT` connects as the Testcontainers superuser. This is the identical shape as US-015's R-6 dirty-flush trap and US-012's T-R4/O-1 `FOR UPDATE`-privilege question (settled for `user_roles`, which has the column-scoped `UPDATE`). `role_permissions` *does* hold `DELETE`, so a locking read confined to that table alone would be permitted.

This is a hard constraint on the design's TOCTOU answer (§6.3), and it needs a privilege-level test analogous to `RolePermissionsPrivilegeIT` / `UserRolesPrivilegeIT` if any locking is proposed.

---

## 3. API / contract changes

### 3.1 Wire contract — unchanged

No new endpoint. No new/changed request or response DTO. No path, method, status-code-set, or error-code change. `POST /api/v1/users/{userId}/roles` and `DELETE /api/v1/users/{userId}/roles/{roleId}` keep their shapes. Assumption 3 from the requirements doc (§5.3) is **confirmed**. No versioning strategy needed.

### 3.2 Behavioural contract — changed, deliberately (this is the story)

| Verb | Before | After |
|---|---|---|
| `assign()` of a non-`TENANT_ADMIN`-named role carrying a dangerous permission | **201**, by any `user:write` holder, including self-grant | **403 `RBAC_001`** unless the caller holds an active `TENANT_ADMIN` assignment |
| `revoke()` of the literally-named `TENANT_ADMIN` role | **204** (or 409 `RBAC_002` on the last-admin guard) by any `user:write` holder | **403 `RBAC_001`** unless the caller holds an active `TENANT_ADMIN` assignment |
| `revoke()` of a dangerous-permission-carrying custom role | **204** by any `user:write` holder | **403 `RBAC_001`** unless caller is an active admin |
| Everything else (`MEMBER`, permission-less custom roles, cross-tenant, 404s, 409s, `listActive`) | — | **Unchanged** |

US-015's own design (§10.2 item 2) and threat model (§4.2 item 2) both classify this as *"a breaking behavioural change to US-012's live endpoint."* It is in-scope and intended here; it is recorded in §9 as a breaking change so the rollout plan owns it.

Mitigating context: both endpoint families are behind default-off kill switches — `feature.nexus-us012-rbac-role-assignment.enabled` and `feature.nexus-us015-rbac-role-management.enabled`, both `false` in `application.yml:205–219`. The exposure this story closes is only reachable where the US-015 flag has been on.

### 3.3 Additive, client-visible field-value change (if a new `DenialReason` is added)

`GlobalExceptionHandler.java:162` puts `reason` into the 403 `ProblemDetail` **body**. A sixth `DenialReason` therefore becomes a new client-visible string value. Additive (no existing value changes meaning), but three consequences:

1. **Information disclosure to consider.** A reason literally naming "target role carries a dangerous permission" tells an unauthorised caller something about a role's permission set that they may not be entitled to read (`role:read` gates `GET /roles/{id}/permissions`). US-015 accepted a comparable 403-vs-404 oracle as RES-4; the design/threat-model phase should make this an explicit choice, and can keep the wire value coarse while keeping the *audit* and *log* values precise.
2. **Metric cardinality +1** on `nexus.rbac.permission_denied{permission, reason}` (`GlobalExceptionHandler.java:167–171`).
3. **Doc/Javadoc updates are mandatory, not cosmetic:**
   - `rbac/application/port/out/RbacAuditPort.java:37–40` currently states the denial audit is *"Scoped to the two 403 authorization denials (`CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`)"* — becomes false.
   - `docs/features/US-012/monitoring.md:14` enumerates the reason values.
   - `docs/features/US-012/monitoring.md:29` — alert `nexus_rbac_self_escalation_attempt` is `increase(nexus_rbac_permission_denied_total{reason="NOT_TENANT_ADMIN"}[5m]) > 0`, **page**, unfiltered by permission. If a new reason is introduced and this expression is not updated, **the new gate's denials page nobody** — a detection regression created by the fix itself. If `NOT_TENANT_ADMIN` is reused instead, this alert fires on the new gate for free but the two failure modes become indistinguishable in the metric.

**This alert-expression coupling is the concrete cost of the new-`DenialReason` decision Gate 1 deferred.** Impact analysis's contribution: the decision is not free either way, and whichever way it goes, `docs/features/US-012/monitoring.md` must be edited in the same PR.

---

## 4. UI / frontend impact — none (verified)

Requirements Assumption 4 (`§5.4`) is **confirmed by exploration**:

- `nexus-frontend/src/app/**` contains features `auth`, `dashboard`, `design-system` only — no role or role-assignment feature directory.
- A repo-wide search of `nexus-frontend` for `TENANT_ADMIN`, `role-assignment`, `roleAssignment` returns **zero matches**. Nothing in the frontend special-cases `TENANT_ADMIN` by name.
- `nexus-frontend/src/app/core/guards/permission.guard.ts` and `shared/directives/has-permission.directive.ts` operate on flat permission strings from `/users/me`, not on role names, so they are indifferent to this change.
- Consistent with EPIC-002: role-management UI is Epic 3 scope.

⇒ No Angular component, route, guard, service, or state change. No i18n/copy change (requirements §3 i18n row resolved: **not applicable**). **Forward note for Epic 3:** its role-assignment UI must expect a 403 on assigning/revoking admin-equivalent roles as a *normal* outcome for non-admin operators, and should not present such roles as assignable to them.

---

## 5. Security impact

| Dimension | Impact |
|---|---|
| Attack surface | **Reduced, not widened.** No new endpoint, no new input, no new parser. The change is a deny-side gate |
| Closes | RES-1 / T-E16 (propagate-side self-escalation) and T-E17 (N→1 administrator stripping) from `docs/features/US-015/03b-threat-model.md` §4.5, §5 |
| authn | Unchanged |
| authz | **Two shipped verbs get a stricter gate** (§3.2). This is the story |
| Freshness discipline | The new admin check inherits T-E7's rule: live, transactional, locking read on the caller; never JWT-derived. `RoleAssignmentService.java:127–133` already states this at the existing call site, and `RoleAssignmentSecurityIT.should_return403WithNotTenantAdmin_when_staleJwtStillClaimsAdminAfterOutOfBandRevocation` (267–305) is the end-to-end proof that must keep passing |
| Fail-closed | Two new fail-closed obligations: Q3-empty ⇒ deny (§1.5), and lookup-error ⇒ deny (requirements §3 Security row) |
| Audit | New denial path must emit `ROLE_ASSIGNMENT_DENIED` via `recordDenial` (405–427) — FR-5. Note `revoke()` gains its **first** 403-authorization denial audit row ever, widening US-014 AC4's documented population from "assign-side + cross-tenant" to include revoke-side admin denials |
| New residual | The gate evaluates at the moment of assign/revoke only. A role that *becomes* dangerous after an assignment already exists is not re-validated (requirements Edge Case 7). Forward-only is a Gate 1 decision; the design/threat-model must record it as a named residual rather than leave it implicit |
| Explicitly out of scope | AC5-style lockout protection for custom admin-equivalent roles (Gate 1 #8) — but see §9.2, which shows this story *narrows* AC5's reachable population as a side effect, which strengthens the case for the follow-on backlog entry |
| PII | None. Every new log/metric/audit field is a UUID, a role name, or a permission name |

---

## 6. Performance impact

### 6.1 Added query count (worst case, per call)

| Path | Today | After |
|---|---|---|
| `assign()`, non-dangerous role | 5 statements (`findTenantId`, `findRole`, `hasActiveAssignment`, insert+flush, `findActiveAssignmentView`) | **+1** (dangerous-permission test) |
| `assign()`, dangerous or admin-named role | 4 (denial short-circuits) | **+2** (dangerous test, admin-role-id Q3) — the locking admin read already exists on the name-match path |
| `revoke()`, non-dangerous role | 3–4 | **+1** |
| `revoke()`, dangerous or admin-named role | 3–4 | **+3** (dangerous test, Q3, and the locking admin read which `revoke()` never performed before) |

### 6.2 Query cost and N+1 risk

- **No N+1.** The added reads are a fixed, small constant per request — they do not iterate roles, permissions, or assignments.
- Dangerous-permission test: PK-prefix range scan on `role_permissions` (`PRIMARY KEY (role_id, permission_id)`, V5:49), bounded at 7 rows by the fixed permission catalogue (V5:107–114), plus ≤7 PK lookups on `permissions`. Sub-millisecond.
- Q3: `uq_roles_tenant_name` equality lookup. `RoleManagementPort.java:49–55` already mandates a bare `r.name = :name` predicate (never `UPPER(name)`) to keep it sargable — the same rule applies verbatim to any new equivalent.
- Hot-path status: **not a hot path.** `docs/features/US-012/03b-threat-model.md` records these endpoints as intentionally un-rate-limited because they are reachable only by the tenant's most privileged principals. No documented p95/RPS budget exists for `assign`/`revoke` (requirements §3, still a `[CONFIRM]`); the epic-level bar is p95 < 300 ms at 200 RPS for the roles API. +1 to +3 indexed point lookups cannot plausibly threaten that.
- Cache: `PermissionCachePort` untouched — no new key, no new eviction, no TTL change. ADR-0013 D4 unaffected. Nexus does not use a Redis-backed cache on this path for the gate, and this story proposes none.

### 6.3 The real performance/correctness risk is locking, not cost

`revoke()` currently takes exactly one lock: `lockActiveAssignmentIds` → `PESSIMISTIC_WRITE` (`X`) over **all** active assignments of `(tenant, role)` (`JpaUserRoleRepository.java:68–77`).

Adding the admin check to `revoke()` introduces a **second** lock in the same transaction: `lockActiveAdminAssignment` → `PESSIMISTIC_READ` (`FOR SHARE`, `S`) on the caller's own `user_roles` row (`JpaUserRoleRepository.java:152–160`).

For a `TENANT_ADMIN` revocation these two row sets **necessarily overlap**: the caller must be an active admin to pass the gate, so the caller's own assignment row is inside `lockActiveAssignmentIds(tenant, adminRoleId)`. That is the *legitimate, expected* path, not an edge case.

Consequence: two concurrent admin revocations in the same tenant can each take `S` on a shared row and then each request `X` on it — the classic InnoDB `S`→`X` upgrade deadlock, surfacing as a rolled-back transaction (500 or a lock-wait timeout) rather than a clean 403/409/204. Today this cannot happen because no transaction takes both locks.

Mitigation is a design decision (candidates: take the `X` lock first and let the subsequent `S` be a same-transaction no-op; or make the gate's admin read `PESSIMISTIC_WRITE` on this path). What impact analysis establishes is that **`LastAdminLockoutIT`'s 8-thread concurrency test (189–255) is precisely the harness that will expose it**, and that this must be designed, not discovered.

### 6.4 TOCTOU — reason it through, do not assume symmetry with T-E14

Two distinct races, with different answers:

1. **Caller's admin status revoked concurrently** — identical to T-E7/T-E14. Must be a fresh locking read. Already satisfied by reusing `hasActiveAdminAssignment` unchanged. No new analysis needed.
2. **Target role's permission set changes concurrently** (a `role_permissions` row attached/detached between the check and the write) — **not** symmetric with #1, for three reasons:
   - The dangerous direction is *attach*, and attach is itself AC11-gated to active admins (`RoleManagementService.java:160–163`). To win this race an attacker must already hold the authority the gate protects. The exploitable direction (*detach* to slip past the gate) **reduces** the role's privilege, so the assignment that then succeeds confers nothing dangerous. The race is self-defeating.
   - `role_permissions` has no soft-delete and no `@Version` (US-015 RES-5): a locking read here would need to lock a row that may not exist yet (attach is an INSERT), which a row lock cannot prevent without gap/next-key locking — materially more invasive than the S-lock in #1.
   - §2.1's grant constraint bars any locking read that touches `permissions`.
   ⇒ **Provisional recommendation: lock the admin-status check (as today), leave the permission-set read non-locking**, and record the residual explicitly. The design/threat-model phase owns the final ruling; the point here is that "T-E14 was High, so lock everything" is the wrong inference, and the reasoning above is what a design must engage with.

---

## 7. Integration / cross-context impact

| Direction | Impact |
|---|---|
| `rbac` → `identity` | None. The `rbac_must_not_depend_on_identity` ArchUnit rule (`HexagonalArchitectureTest.java:113–125`) stays green — the gate touches no `identity` type |
| `identity` → `rbac` | `RbacAuthEventAdapter` (implementor of `RbacAuditPort`) needs **no code change**; it already passes any `DenialReason` through as `metadata.reason` (239–241). Javadoc-only (§3.3) |
| `rbac` ↔ `common` | One additive enum value in `common.security` (§1.7) |
| Intra-`rbac.application` | **The one genuinely new edge**, if Option A is chosen (§1.4). Option B avoids it |
| Audit pipeline | No new `AuthEventType`; `ROLE_ASSIGNMENT_DENIED` is already STANDARD-lane by US-014 decision 5 (`AuthEventType.java:63`). Denial volume increase is expected to be negligible, so no `nexus_audit_priority_lane_depth` threshold review is needed |
| Health indicators | `RbacZeroActiveAdminsHealthIndicator` unaffected in code. **Semantic note:** its zero-active-admins detection covers only the literally-named `TENANT_ADMIN` (`JpaUserRoleRepository.java:208–217`), so it still cannot see a tenant that has zeroed out its custom admin-equivalent role — consistent with, and further evidence for, the Gate-1-#8 follow-on risk |
| Upstream/downstream services | None. Nexus has no external consumer of these verbs |

---

## 8. Dependency changes

**None.** No new Maven artifact, no version bump, no license review. Everything needed (`RbacDangerousPermissions`, `hasActiveAdminAssignment`, the Q7-shaped query, Micrometer, the audit port) already exists in the repository. No frontend `package.json` change — which also means the npm-Windows-lockfile-prune hazard is not in play for this story.

---

## 9. Backward-compatibility analysis

### 9.1 Compatible (no change)

Wire format, status-code vocabulary, error codes (`RBAC_001`/`RBAC_002`/`RBAC_004`), the 404-before-403 ordering for cross-tenant and not-found paths, `listActive` semantics and its `assignedBy` redaction, FR-3's name-match behaviour for the literal `TENANT_ADMIN` on `assign()`, all `MEMBER`/permission-less-role flows, `nexus.rbac.self_role_assignment` emission (FR-6: retained).

### 9.2 Incompatible — and one consequence nobody has written down yet

Beyond the two intended behavioural breaks in §3.2, there is a **derived** break:

> After FR-2, the AC5 scenario *"a caller who is not an active `TENANT_ADMIN` revokes the tenant's last active admin assignment"* becomes **structurally unreachable**.

Proof: to reach the AC5 guard on the `TENANT_ADMIN` role, the caller must now pass the admin gate, i.e. hold an active assignment of that same role. If the caller holds one and the target's assignment is the tenant's *last* active one, then caller's assignment == target's assignment, so target == caller. Hence AC5's actor-agnostic branch collapses to **self-revocation only** for the name-matched admin role.

This matters concretely:
- `LastAdminLockoutIT.should_blockRevocation_when_differentAdminAttemptsTheRevocation` (136–163) seeds a caller *"Deliberately NOT itself an active TENANT_ADMIN"* (comment at 141–143) and asserts 409 `RBAC_002`. After this story it must assert **403**, and the scenario it was written to defend (US-012 Gate 1 Resolution 5, AC5's actor-agnostic reading) can no longer be expressed for the admin role.
- AC5 is not being removed or weakened — but its *reachable population* narrows, and a documented US-012 Gate 1 resolution silently changes meaning. **This needs an explicit sentence in the design and, per the requirements doc's own standard, an update to US-012's AC5 documentation** — not a quietly rewritten test.

### 9.3 Callers/tests that will break (see §12 for the full matrix)

Anything asserting (a) that a non-admin can successfully assign a dangerous-permission-carrying role, or (b) that a non-admin can revoke a `TENANT_ADMIN` assignment. Both exist today and both are load-bearing tests written on purpose.

---

## 10. Data migration strategy

**None.** No shape change ⇒ nothing to migrate. Gate 1 decision #7 makes the fix forward-only: no backfill, no remediation of assignments created during the US-015→US-016 exposure window.

Two carry-forward notes for the design/release phase (both explicitly *not* story scope):
1. The recommended one-off exposure audit (Gate 1 #7) can be served by existing mechanisms with **no new code** — `UserRoleAssignmentPort.findActiveUserIdsForRole` (`port/out/UserRoleAssignmentPort.java:82–92`) already exists for exactly this RC-6 remediation-runbook purpose, and US-015's runbook already carries the reverse-lookup SQL. The design should point the runbook at it rather than inventing a query.
2. Pre-existing non-admin-granted assignments of now-dangerous roles will **survive** deployment and keep conferring their permissions. Operators must be told this in the release notes/runbook, because "the escalation gap is closed" will otherwise be read as "existing escalated assignments are revoked."

---

## 11. ADR impact

An ADR is required (Gate 1 decision #6). Recommendation for the design phase:

- **Write a new ADR, numbered 0017** (next free slot — `docs/adr/` currently holds 0001–0016), titled around *privilege-based (not name-based) authorization for role assignment and revocation*.
- **It extends and supersedes-in-part `docs/adr/0013-rbac-data-model-and-enforcement-contract.md`**, which is the correct anchor: ADR-0013 owns the permission naming convention (D1), the `active_key` uniqueness mechanism (D2), and the `403 + RBAC_001` enforcement contract (D3) — the three decisions this gate is built on top of. Its "Follow-on rules for future work" section is where a reader would go looking for this rule.
- **Do not edit ADR-0013's body.** ADR-0001's append-only rule is enforced in practice here — ADR-0013 already carries an in-place *"Amendment (2026-07-22) — US-011 threat-model hardening"* section (lines 106–164) that explicitly states *"nothing above this line is edited."* Either follow that precedent with a new appended amendment section, or (preferred, given this is a new decision rather than a correction to an old one) a standalone ADR-0017 that cross-references D1/D3. The design phase should pick one and say why.
- The ADR must also record the two decisions Gate 1 deferred (new `DenialReason` yes/no; single-vs-composed gate) and the port-choice decision from §1.4, since the latter is the "first-of-its-kind dependency" question risk R6 raised.
- Also update: `docs/features/US-015/03b-threat-model.md` §4.5 and §5 RES-1 (status → closed, citing US-016), and the `RoleAssignmentService` Javadoc notes (replace, never delete — §1.1).

---

## 12. Test impact

### 12.1 Existing tests that will FAIL and must be rewritten (not merely extended)

| Test | Location | Why it breaks |
|---|---|---|
| `should_incrementBothCountersAndSucceed_when_adminAttachesDangerousPermissionAndNonAdminSelfAssigns` | `rbac/RoleAssignmentEscalationIT.java:76–112` | **This test asserts the vulnerability.** Its comment at 95–97 and closing assertion at 110–111 explicitly require that the non-admin self-assignment of a now-dangerous role **succeeds**. It must be inverted to assert a 403 + a `ROLE_ASSIGNMENT_DENIED` audit row, while preserving its `dangerous_permission_granted` counter assertion. **This is the single highest-signal test change in the story** |
| `should_blockRevocation_when_differentAdminAttemptsTheRevocation` | `rbac/LastAdminLockoutIT.java:136–163` | Caller is deliberately not an admin; now denied 403 before reaching AC5. See §9.2 — the scenario becomes unreachable, so this is a semantic rewrite, not a stub fix |
| `should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins` | `rbac/LastAdminLockoutIT.java:189–255` | The `caller` (194, 200) holds no admin assignment ⇒ all 8 threads would 403. Making the caller an active admin **also changes the lockout arithmetic** (its own row joins `lockActiveAssignmentIds`, so 2 admins become 3) and is the harness most likely to expose §6.3's deadlock |
| `should_revokeSuccessfully_when_lockedSetSizeTwoOrMore` | `rbac/application/RoleAssignmentServiceTest.java:716–736` | `TENANT_ADMIN` revoke by an actor whose `hasActiveAdminAssignment` is unstubbed (⇒ `false`) |
| `should_invokeLockoutGuard_when_revokeRoleNameIsDifferentCaseVariantOfTenantAdmin` | `…:744–760` | Same |
| `should_throwLastAdminRoleException_…_selfRevoke` | `…:672–689` | Same — needs the admin stub to reach AC5 |
| `should_throwLastAdminRoleException_…_differentAdminRevoking` | `…:698–714` | Same, plus the §9.2 semantic issue |
| `should_neverCallLockActiveAssignmentIds_when_adminRoleAssignmentNotFound` | `…:652–666` | **Only if** the new gate is placed *before* `findAssignmentRefOrThrow`: its `verifyNoInteractions(rbacAuditPort)` would then fail because a denial row is written. This test is an exact tripwire on the gate's placement decision — useful, keep it |

### 12.2 Existing tests that must keep passing unmodified (regression contract, FR-3)

- `RoleAssignmentServiceTest` assign-side name-match tests (264–285, 295–315 — the `equalsIgnoreCase`/R-9 proof, 322–349 — the AC8 positive path).
- `RoleAssignmentSecurityIT.should_return403WithNotTenantAdmin_when_nonAdminHoldingUserWriteAttemptsToGrantTenantAdmin` (234–251) and `…staleJwtStillClaimsAdminAfterOutOfBandRevocation` (267–305) — the latter is the load-bearing proof that the admin check is a live DB read, and the new gate must not weaken it.
- `LastAdminLockoutIT` scenarios 1 (109–132), 4 (267–289), 5 (303–339) — in all three the actor *is* the admin being revoked, so the new gate passes and behaviour is unchanged.
- All permission-less-role paths across `RoleAssignmentIT`, `RoleAssignmentAuditIT`, `RoleAssignmentCacheIT`, `ActiveAssignmentIT`, `UserRolesAppendOnlyIT`, `CrossTenantPermissionIT` — verified: their `seedRole` helpers create roles with **no** attached permissions (e.g. `RoleAssignmentIT.java:84–88`, `RoleAssignmentAuditIT.java:631–635`, `RoleAssignmentCacheIT.java:311–315`), so the new gate never fires. **Mockito note:** default mock returns (`false`/empty) mean "not dangerous", so unit tests that do not care need no new stubs and strict-stubs will not complain.
- `RoleManagementServiceTest` / `RoleManagementAdminGateIT` — US-015's mint side is untouched.

### 12.3 New tests implied

| Level | Coverage needed |
|---|---|
| Unit (`RoleAssignmentServiceTest`) | assign+revoke × {role carries one dangerous permission / all three / none / empty permission set} × {caller is active admin / is not} × {target == actor / target != actor (FR-4)}; Q3-empty ⇒ fail-closed; lookup throws ⇒ fail-closed; exactly **one** denial + **one** audit row when both name-match and privilege-match hold (Edge Case 3); correct `DenialReason`; correct WARN marker; gate ordering vs. 404/409 branches |
| Unit (domain) | None new — `RbacDangerousPermissionsTest` already covers the set. If a new `DenialReason` lands, check whether the `common.security` coverage gate needs a companion test (cf. the known JaCoCo `toString()` gap pattern on security records) |
| Adapter (`JpaUserRoleAssignmentAdapterTest` or `JpaRoleManagementAdapterTest`) | Whichever port option is chosen: delegation test for the new read(s) |
| IT — escalation | `RoleAssignmentEscalationIT` extended into the closure proof: admin attaches `role:write` to a custom role → non-admin self-assign **denied** → audit row present → counters behave per FR-6's reinterpretation |
| IT — revoke symmetry | New: non-admin cannot strip a dangerous/admin role (T-E17 closure), and an admin still can |
| IT — freshness | Out-of-band admin revocation + stale JWT on the **new** path (extends `RoleAssignmentSecurityIT`'s 267–305 pattern to the privilege gate) |
| IT — concurrency | §6.3's lock interaction, under `LastAdminLockoutIT`'s existing 8-thread harness |
| IT — DB privilege | **Only if** the design proposes any locking read on the new path: a `nexus_app`-as-`nexus_app` test in the `RolePermissionsPrivilegeIT` / `UserRolesPrivilegeIT` family, because §2.1's failure is production-only and invisible to every superuser-connected IT |
| Architecture | A mechanical control that the gate uses the locking admin read, not `listActive`'s non-locking helper (§1.6) |

### 12.4 Gates

Standard: `./mvnw verify -DskipITs` per task; full `./mvnw verify` with Docker up once in Phase 8, since this story touches persistence-adjacent code and several `*IT`s. No frontend gate runs are needed (§4).

---

## 13. Top risks

| # | Risk | Sev | Note for design |
|---|---|---|---|
| **R1** | **`revoke()`'s new admin gate collides with AC5's last-admin lockout** — it makes AC5's actor-agnostic scenario structurally unreachable (§9.2), breaks two ITs and four unit tests, and silently changes the meaning of a documented US-012 Gate 1 resolution. US-015's threat model (§4.2 item 3) named this as the question Gate 2 could not answer; it is now unavoidable | **High** | Design must state the gate/lockout ordering, the resulting 403-vs-409 precedence, and update US-012's AC5 documentation explicitly |
| **R2** | **New lock pair in `revoke()` (`S` on the caller's row + `X` over the tenant's admin rows) can deadlock on the legitimate path** (§6.3) — today no transaction takes both | **High** | Pick and justify a lock order (or promote the gate's read to `PESSIMISTIC_WRITE` on that path); prove it under `LastAdminLockoutIT`'s 8-thread harness |
| **R3** | **A locking read touching `permissions` is rejected in production and passes every test** (`GRANT SELECT` only, §2.1) — same production-only shape as US-015's R-6 and US-012's T-R4 | **High** | Keep the permission-set read non-locking (§6.4 argues this is also the correct security answer), or confine locking to `role_permissions`; add a privilege-level IT if any locking is proposed |
| R4 | Wrong `roleId` passed to `hasActiveAdminAssignment` on the privilege path (§1.3/§1.5) — fails **open** for the exact scenario the story exists to close, and passes any test that does not assert the argument | Med-High | Generalise to a single call site fed by Q3; assert the argument in a unit test, as `RoleAssignmentServiceTest:343` already does for the existing path |
| R5 | `DenialReason` decision leaves a detection hole: a new value silently stops matching `docs/features/US-012/monitoring.md:29`'s **page** alert; reusing `NOT_TENANT_ADMIN` blurs two distinct failure modes (§3.3) | Med | Whichever way, edit the alert expression in the same PR and record the choice in the ADR + a US-016 monitoring note |
| R6 | Port-choice precedent: injecting `RoleManagementPort` leaks write capability into `RoleAssignmentService` and falsifies that port's "exactly one consumer" Javadoc (§1.4) | Med | Prefer narrow reads on `UserRoleAssignmentPort`; whichever is chosen, the ADR must argue it against the project's two written precedents |
| R7 | `RoleAssignmentEscalationIT`'s "assignment still succeeds" assertion (§12.1) is deleted rather than inverted, losing the closure proof for RES-1 | Med | Require the inverted test to be named as the RES-1 closure evidence |
| R8 | FR-6's counter reinterpretation ships as code without the alert semantics being written down, so operators keep treating a now-blocked scenario as a live exploit page (US-015 R8) | Med | `docs/features/US-016/monitoring.md` (or an amendment to US-015's) is a **design-phase deliverable**, not optional |
| R9 | Operators/readers infer that pre-existing escalated assignments were remediated (§10) | Low-Med | One explicit sentence in the release notes and runbook |

---

## 14. Confirmations of the requirements doc's open `[CONFIRM]` items

| Requirements item | Status after this analysis |
|---|---|
| §5.3 — no REST/DTO/API contract change | **Confirmed** (§3.1) |
| §5.4 — no frontend change | **Confirmed by exploration** (§4) |
| §5.5 — no DB migration | **Confirmed**, with the §2.1 grant caveat attached |
| §5.6 — `DenialReason` gains at most one value | **Confirmed as feasible**; no test blocks it, only docs/alerts (§3.3) |
| §3 Performance — latency budget | **Still open**, but de-risked: +1…+3 bounded indexed point lookups on a non-hot admin path (§6.1–§6.2). Recommend accepting the epic-level p95 < 300 ms bar rather than inventing a story-specific budget |
| §3 Availability — SLO | **Still open**; recommend inheriting US-012's posture. No new external dependency is introduced, so this story adds no new availability risk |
| §3 i18n | **Resolved: not applicable** (§4) |
| §8 Gap 7 — backward compatibility of existing tests | **Resolved**: §12.1 lists exactly which tests break and why; §12.2 lists the regression contract |
