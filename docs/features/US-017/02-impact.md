# US-017 — Impact Analysis (Phase 2)

**Story:** Extend last-admin lockout protection to admin-equivalent custom roles (closes US-016 RES-3 and RES-9)
**Epic:** EPIC-002 — RBAC Foundation
**Gate 1 basis:** `docs/features/US-017/01-requirements.md`, including its **"Gate 1 Resolution (approved 2026-09-17)"** section. Resolutions 1–3 are settled inputs and are **not** re-litigated here: the admin-equivalent definition is `nameMatch || carriesDangerousPermission`; RES-9 is **in scope**; this story gets its own ADR and its own `03b-threat-model.md`.
**Method:** every claim below was verified by reading the code on branch `QA-002` at commit `5f74ac7`. Line ranges are from the files as they stand at that commit. Where this document contradicts an assumption in the requirements doc, it says so explicitly and shows the code.
**Precedent followed:** `docs/features/US-016/02-impact.md` (structure, depth, and the convention of separating "verified" from "assumed").

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Modules affected | Backend only — `rbac.application` (2 services), `rbac.application.port.out`, `rbac.infrastructure.persistence` (adapter + 2 repositories), `rbac.infrastructure.health`, plus tests and docs. `rbac.domain` **unchanged** (§1.7) |
| Frontend affected | **No** — re-verified (§4) |
| DB schema changes | **FR-1/FR-3: none.** **FR-2: TBD at design** — no migration if the live-query option is chosen; an **additive index** is a plausible optimisation and a **new table + a grant change** if a materialised signal is chosen (§2). Assumption 6 of the requirements doc holds for FR-1 and is **not** extended to FR-2, as Gate 1 already warned |
| REST contract changes | **None.** No endpoint, DTO, status code, or error code changes (§3.1) |
| Health endpoint contract | **Keys unchanged** (`affectedTenantCount`, `issue`); the `issue` **string text** and the DOWN **population** change (§3.3) |
| Breaking changes | **No external/API break.** Three *behavioural* breaks, all internal authorization/business-rule widening — and one of them is an authorization **loosening** (§9.2), which is the security-critical half of this story |
| New dependencies | **None** (§8) |
| Data migration | **None.** Forward-only, same posture as US-016 (§10). One **detection** gap the story should own is called out (§10.2) |
| ADR | Required by Gate 1 Resolution 3. Next free number is **0018** (`docs/adr/` holds 0001–0017). It must **supersede-in-part ADR-0017's second follow-on rule**, which explicitly forbids what this story does (§11) |
| **Single largest finding** | **A literally symmetric FR-3 makes the US-016 gate vacuous and reopens T-E16/T-E17.** Every caller who can reach `assign()`/`revoke()` holds `user:write`, and `user:write` ∈ `RbacDangerousPermissions.NAMES`, so "the caller holds *any* admin-equivalent role" is **true for every possible caller**. See §1.4 — this is a Critical, must-decide-at-Gate-2 finding, not a style point |

---

## 1. Modules, classes, and call sites affected

### 1.1 Primary — `rbac.application.RoleAssignmentService` (700 lines)

`nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`

| Region | Lines | What changes | Driven by |
|---|---|---|---|
| `assign()` Javadoc | 116–142 | The "Also surviving: AC5's last-admin lockout still protects only the literally-named `TENANT_ADMIN` (RES-3), and the **caller**-side admin test remains name-based (RES-9)" sentence (138–140) becomes **false**. Per US-015 D13 / US-016 §12.2 item 7 discipline, this is **replaced with a closure reference, never deleted** | FR-1, FR-3 |
| `assign()` gate | 160–167 | `privileged` computation unchanged; the **call into `requireActiveTenantAdmin`** now resolves a different caller-side question (§1.4) | FR-3 |
| `revoke()` Javadoc | 254–280 | Same replace-not-delete treatment (276–278) | FR-1, FR-3 |
| `revoke()` — `nameMatch`/`privileged` | 304–305 | Unchanged as a computation. **Its consumers change**: today `nameMatch` alone drives M1, the timer and AC5; after this story `privileged` must drive all three (§1.2) | FR-1 |
| `revoke()` — M1 lock acquisition | 310–313 | `nameMatch ? lockActiveAssignmentIds(tenantId, role.getId()) : List.of()` becomes a **tenant-wide union lock across N admin-equivalent role ids**, acquired whenever `privileged`. This is the R1 concurrency change; the locking protocol is **deferred to Gate 2** | FR-1 |
| `revoke()` — lock-hold timer | 317, 403–411 | `Timer.Sample` starts only on `nameMatch` today; it must start whenever the union lock is taken. **D18's documented property — "a dangerous-custom-role revocation never participates in this timer" (401–402, and `US-016/monitoring.md` §1) — becomes false** and both must be corrected | FR-1 |
| `revoke()` — AC5 guard | 328–339 | `nameMatch && lockedActiveAdminIds.size() <= 1 && lockedActiveAdminIds.contains(ref.id())` becomes a **tenant-wide, distinct-holder** test (§1.3). The WARN message literal "last active TENANT_ADMIN assignment" (337) becomes inaccurate | FR-1 |
| `requireActiveTenantAdmin` | 537–575 | **The RES-9 change.** M8+M5 (545–550) resolve the literal `TENANT_ADMIN` role id and test one `(userId, roleId)` pair. A privilege-based caller test needs a different port capability and a different lock footprint (§1.4, §6.3). Shared by **both** `assign()` and `revoke()` — the R3 size warning Gate 1 carried forward | FR-3 |
| `callerHoldsActiveTenantAdmin` | 588–593 | **Do not change blindly.** This is deliberately a *second, independent* name-based mechanism feeding the `callerIsAdmin` canary tag (US-016 07-security-review M-2, comments at 224–235). If it stays name-based while M5 goes privilege-based, the two legitimately disagree and the **page-severity** `nexus_rbac_gate_bypass_canary` alert false-fires (§5.4, R2) | FR-3 (consequence) |
| `listActive` | 421–436 | Uses `callerHoldsActiveTenantAdmin` for the `assignedBy` redaction (O-10/T-I5). Whether an admin-equivalent custom-role holder should now see `assignedBy` is a **new, unasked question** this story creates. Scoped here, decided at Gate 2 | FR-3 (consequence) |
| `recordDenial`, `requireNotThrottled`, `recordThrottleDenialAndMaybeWarn` | 464–519, 653–677 | **No change.** Reused as-is | — |
| Constructor / collaborators | 88–114 | **No new collaborator expected** if the new reads land on `UserRoleAssignmentPort` (§1.5). Confirm at design | — |

### 1.2 The lockout's trigger condition: `nameMatch` → `privileged`

Today three things key off `nameMatch` (304): the M1 lock (311), the timer (317), and the AC5 guard (328). This is sound today because a tenant's admin-equivalent access is, by definition, the literal role.

After FR-1, all three must key off `privileged` instead — and that is **exactly the right set**, provably: a revocation can only reduce the tenant's admin-equivalent holder set if the revoked role is itself admin-equivalent. Revoking a benign role cannot zero a tenant out. So the gate condition, the lock condition, and the lockout condition remain **one condition** — preserving D4's "one condition, one call site" property rather than forking it. Worth stating in the design, because it is the one part of this story that gets *simpler*, not harder.

### 1.3 The lockout predicate itself changes shape, not just scope — rows → distinct holders

This is the most easily-missed correctness change in FR-1, and the requirements doc's Edge Case 1 is its symptom.

Today's predicate counts **assignment rows** of one role (`lockedActiveAdminIds.size() <= 1`). That is equivalent to counting **distinct holders** only because `uq_user_role_active (active_key)` (`V5__rbac_schema.sql:71–89`) guarantees at most one active row per `(user_id, role_id)` — so within a single `role_id`, rows and holders are the same thing.

Across a **union of role ids that is not true**. A single user holding both the literal `TENANT_ADMIN` and a dangerous custom role contributes **two rows and one holder**. A row-count union check would therefore compute `size() == 2`, conclude "not the last holder", and let the tenant be zeroed — the exact failure FR-1 exists to prevent, arrived at by a "straightforward per-role extension" (requirements R1's own words).

⇒ The widened invariant must be expressed over **`DISTINCT user_id`**, and the guard must additionally account for the fact that revoking one of a user's two admin-equivalent assignments leaves them a holder. The shape that satisfies both:

> Block iff the set of distinct users holding an active assignment of **any** admin-equivalent role in the tenant, **excluding the assignment row `ref.id()` being revoked**, is empty.

This is one predicate covering requirements Edge Cases 1, 2 and 3 structurally, rather than three ordering rules. The **locking protocol** that makes it race-free is deferred to Gate 2 (R1) — but the *predicate* is an impact-analysis finding and must not be discovered at implementation time.

### 1.4 FR-3 (RES-9): the caller-side test **cannot** reuse the target-side predicate — Critical

Gate 1 Resolution 2 settles that `requireActiveTenantAdmin`'s caller test becomes privilege-based, "symmetric with FR-1/FR-2's target/detection-side treatment." Impact analysis's contribution is to show that the *literal* reading of "symmetric" — caller holds any role satisfying `nameMatch || carriesDangerousPermission` — is **vacuously true for every caller who can reach this code**, and therefore silently reopens everything US-016 closed.

**Proof, from shipped code:**

1. Both verbs are gated by `@RequiresPermission("user:write")` at `rbac/interfaces/rest/UserRoleController.java`; `RoleAssignmentService` re-asserts `USER_WRITE` as the required permission on every denial (58, 148, 287, 485, 574).
2. A caller therefore reaches `requireActiveTenantAdmin` only if they hold `user:write`, which they can only hold via an active assignment of some role R that carries `user:write` (`JpaUserRoleRepository.findActivePermissionNames`, 46–58).
3. `user:write` ∈ `RbacDangerousPermissions.NAMES` (`RbacDangerousPermissions.java:13`).
4. ⇒ R satisfies `carriesDangerousPermission` ⇒ R is admin-equivalent ⇒ the caller holds an admin-equivalent role.
5. ⇒ "caller holds an admin-equivalent role" is **true for 100 % of callers**, including the exact non-admin attacker US-016's T-E16/T-E17 were written about.

The same argument applies one context over: `RoleManagementService.attachPermission`'s AC11 gate (`RoleManagementService.java:176–179`) sits behind `role:write`, which is also in the dangerous set.

**Mechanical tripwires that would catch this — they already exist and must not be weakened:**

- `RoleAssignmentSecurityIT.should_return403WithNotTenantAdmin_when_nonAdminHoldingUserWriteAttemptsToGrantTenantAdmin`
- `RoleRevocationSymmetryIT.should_throwNotTenantAdmin_when_nonAdminAttemptsToRevokeDangerousCustomRole` (87) and `…RevokeTenantAdminAssignment` (115)
- `LastAdminLockoutIT.should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin` (181–210) and harness C's denied thread (547–559)

All of these seed a caller holding exactly `user:write` and assert 403. Under a literally-symmetric FR-3 they would all flip to success. **If an implementer "fixes" them, US-016 is silently undone.** Flag this in the design as a hard non-regression contract.

**What Gate 2 must therefore decide (scoped here, not decided):** the caller-side predicate is a *different, strictly narrower* predicate than the target-side one. Candidate shapes, each with a cost:

| Option | Shape | Note |
|---|---|---|
| A | Caller holds a role carrying **all three** dangerous permissions (ALL, not ANY) | This is what US-016 §12.3 RES-9 literally describes ("a user holding a custom role that carries **all three** dangerous permissions … can never pass it"). Narrow, no schema, but a role carrying `role:write` + `user:write` and not `tenant:write` is arguably admin-equivalent and still cannot administer |
| B | Caller holds the literal `TENANT_ADMIN` **or** a role carrying all three | Additive over today's behaviour; preserves the name path exactly (FR-4 shape) |
| C | An explicit admin-equivalence marker on the role (new column/flag) | Removes the definitional guesswork entirely; costs a migration, a management API surface, and is materially larger than this story |
| D | Descope FR-3 after all | **Contradicts Gate 1 Resolution 2** — only reachable by escalating back to PM/Security with this finding, not by architect fiat |

**Recommendation for Gate 2:** treat "admin-equivalent **target**" and "admin-equivalent **caller**" as two named, separately-defined predicates with a written justification for why they differ — and make `RbacDangerousPermissions` host both, so FR-7's single-source-of-truth property is preserved even though the predicates are not identical. Requirements R4 (definitional drift) was written about the target side; this is its mirror image on the caller side, and it is more dangerous because drift here **fails open**.

### 1.5 Port impact — `UserRoleAssignmentPort`

`nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`

| Existing method | Verdict |
|---|---|
| M1 `lockActiveAssignmentIds(tenantId, roleId)` (44–52) | **Insufficient as-is.** Single `roleId`, returns row ids not holders. Either gains a sibling that takes a *collection* of role ids and returns **distinct holder ids**, or is left untouched and a new method is added. Its Javadoc's "drive off `role_id`, never `tenant_id`" rule (48–51) carries over verbatim and constrains any IN-list variant |
| M5 `hasActiveAdminAssignment(userId, roleId, tenantId)` (35–42) | **Insufficient for FR-3** — one role id. Its "MUST be a fresh, locking (`PESSIMISTIC_READ`) read, never a JWT claim, never a plain non-locking read" contract (37–41) is non-negotiable and must survive whatever replaces it |
| M7 `findPermissionNamesForRole(roleId)` (82–100) | **Reusable, but N+1-prone at this scale.** Answering "which roles in this tenant are admin-equivalent?" via M7 means one call per role in the tenant. A tenant-scoped variant is almost certainly needed (§6.2) |
| M8 `findRoleIdByName(tenantId, name)` (102–109) | Retained for the name half of the union; still fail-closed-on-empty (R-10/T-E18) |
| M9 `findActiveUserIdsForRole(roleId)` (111–122) | Right shape, wrong arity — single role. Its "no locking, not a hot path" contract (120–121) would be **violated** if it were reused for FR-1's locked union; add a method, do not re-annotate this one |

**Expected new capability (exact signatures are Gate 2's):** (1) resolve the tenant's admin-equivalent role ids, and (2) lock + count the distinct active holders across that set. Both must respect two shipped rules:

- **R-9 / D3 discipline:** the dangerous-permission *names* must not cross this port in either direction, and must not be hardcoded in the adapter (`UserRoleAssignmentPort.java:91–94`; `JpaUserRoleAssignmentAdapter.java:18–26`). A port method that takes `Set<String> dangerousNames` **violates the letter of ADR-0017 D2** ("not hardcoded in the adapter … and not passed in as a parameter either"). The shape that preserves it: the port returns `(roleId → permission names)` for the tenant and the *service* applies `RbacDangerousPermissions.contains`, then passes back a set of **role ids** for the locked count. That costs one extra round trip and is the boring, precedent-consistent answer. **Flag for the ADR:** if Gate 2 instead pushes the name filter into SQL, the new ADR must argue against ADR-0017 D2 explicitly, not silently.
- **No write capability leak:** ADR-0017 D2's second half (the adapter must not gain `JpaRolePermissionRepository`). The tenant-scoped permission query should therefore be hosted on the already-injected `JpaRoleRepository`, exactly as M7 is (`JpaRoleRepository.java:57–71`).

### 1.6 Persistence impact

| File | Change |
|---|---|
| `infrastructure/persistence/JpaUserRoleRepository.java` | New locked union query (sibling of `lockActiveAssignmentsByRole`, 60–77) returning **distinct `user_id`**; widened health query replacing/augmenting `findTenantsWithZeroActiveAssignmentsForRole` (208–234). Both must carry the `ur.tenantId = r.tenantId` cross-check every other query here carries (17–29, 106–112) — it is the T-S1 defense against a drifted `user_roles.tenant_id` leaking a role across tenants, and it is **more** load-bearing here because the new query joins more tables |
| `infrastructure/persistence/JpaRoleRepository.java` | Likely one new tenant-scoped "roles and their permission names in this tenant" query, hosted here for the D16/T-T13 reason (57–71) |
| `infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` | Delegations only (44–133). **Constructor should remain unchanged** — both repositories are already injected (35–42). If a design forces a third repository in, that is an ADR-0017 D2 deviation and must be argued |

### 1.7 Domain — unchanged (verified)

`RbacDangerousPermissions` (`rbac/domain/RbacDangerousPermissions.java:11–27`) and `RbacRoleNames` (`rbac/domain/RbacRoleNames.java:11–34`) are reused **as-is**. No new domain type, no new exception (`LastAdminRoleException` is reused — FR-5). Consequence: the `*.domain.*` 0.90 JaCoCo gate is untouched, and the known `common.security` `toString()` coverage trap is not in play. **Unless** §1.4's option A/B introduces a new predicate helper — if it lands in `rbac.domain` it needs its own unit test to hold the gate.

### 1.8 Health indicator

`nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java` (32–84)

| Region | Lines | Change |
|---|---|---|
| Class Javadoc | 14–31 | States the control watches "a seeded `TENANT_ADMIN`-named role with zero active assignments" — must be rewritten for the widened semantics |
| Query call | 47–49 | Passes `RbacRoleNames.TENANT_ADMIN` from `rbac.domain` into the repository. **This is the precedent that makes FR-2 tractable:** the indicator is infrastructure and may legally read `rbac.domain`, so it can pass `RbacDangerousPermissions.NAMES` the same way without violating layering. Note the tension with §1.5 — the *port* may not take the names, but this indicator does not go through the port at all (it injects `JpaUserRoleRepository` directly, 38–42). The design must state that asymmetry deliberately rather than let a reviewer find it |
| DOWN detail | 63–72 | `affectedTenantCount` key unchanged (FR-6 preserved); the `issue` **string** must be rewritten (it names "seeded TENANT_ADMIN role" and "AC5 bypass") |
| WARN log | 52–55 | Message text references `TENANT_ADMIN` by name; full tenant id list stays here, per 07-security-review M-1 (FR-6) |
| `catch (DataAccessException)` → UNKNOWN | 75–82 | **Unchanged and important.** A widened, more expensive query is *more* likely to time out; UNKNOWN-not-DOWN remains the right posture. Note this is the one place the story's otherwise-fail-closed posture (requirements §3 Security) is deliberately fail-*neutral*, because this is a detection control, not a gate — say so explicitly rather than letting the two rules appear to conflict |

**The unasked FR-2 question this analysis surfaces: what is the driving set of tenants?** Today the query drives off `Role WHERE UPPER(r.name) = UPPER(:roleName)` (225–234), so a tenant with **no** `TENANT_ADMIN`-named role is structurally invisible — it can never be reported. Widening "admin-equivalent" forces a choice: drive off *all* tenants present in `roles` (or `users`), or keep driving off roles that match. These produce **different DOWN populations**: the former newly reports every tenant that has roles but no admin-equivalent role at all (requirements Edge Case 6 — a mis-seeded or mid-provisioning tenant), which could turn a rare page into a routine one. This is a **design decision with an on-call cost**, it is not implied by the story text, and it must not fall out of query syntax by accident.

### 1.9 Not affected — verified, not assumed

| Component | Why |
|---|---|
| `rbac/interfaces/rest/UserRoleController.java` | Method signatures unchanged; `LastAdminRoleException` and `InsufficientPermissionException` already mapped |
| `common/web/GlobalExceptionHandler.java` | `RBAC_002`/`RBAC_001` handling unchanged; `nexus.domain.conflict{code}` is generic and needs no edit |
| `common/security/DenialReason` | No new value (D6/ADR-0017 D3 stands; reusing `NOT_TENANT_ADMIN` keeps US-012's alert expression edit-free) |
| `identity` context, `RbacAuthEventAdapter`, `AuthEventType` | No new event type, no audit-lane change — **unless** requirements Open Question 9 (durable audit row for a lockout block) is adopted at Gate 2, which would add a `RoleAuditEvent`/metadata change. Scoped, not decided |
| `PermissionCachePort`, `RoleResolutionService` | The lockout denies before any write; nothing to evict. No cache key, TTL, or invalidation change. **Nexus adds no Redis here** |
| `RbacDbPrivilegeHealthIndicator` | Untouched |
| `HexagonalArchitectureTest` rules | All stay green: no `rbac → identity` edge, no `Principal`/`Map` in application signatures, no field injection. `role_management_service_must_not_call_the_non_locking_admin_read` (181–197) is unaffected — but see §12.4 for the **new** mechanical control this story needs |
| Flyway migrations | For FR-1/FR-3. See §2 for FR-2 |

---

## 2. Database changes

### 2.1 FR-1 and FR-3 — no migration (confirmed)

| Concern | Finding |
|---|---|
| New table/column | None. The union check reads `roles`, `role_permissions`, `permissions`, `user_roles` — all shipped |
| New index | **Not required.** The reverse lookup "which roles carry permission X" is already indexed: `V5__rbac_schema.sql:53–57` records that InnoDB auto-creates an index on `role_permissions.permission_id` for `fk_role_permissions_permission`, because the composite PK's leftmost column is `role_id`. `uq_permissions_name` (24) resolves the three dangerous names to ids. `fk_user_roles_role` serves the locked union. `uq_roles_tenant_name` (39) serves the name half |
| `ddl-auto=validate` / ADR-0003 | No entity or mapping change ⇒ nothing for `validate` to reject; no migration file, so ADR-0003's append-only rule is not engaged |
| Expand/contract | Not applicable |
| Seed data | `TENANT_ADMIN` carries all 7 permissions, `MEMBER` carries only `user:read`, and `RbacRoleNames.RESERVED` prevents `MEMBER` from ever becoming dangerous. **No seeded role becomes lockout-protected by accident**, and the bootstrap tenant's existing behaviour is unchanged |

### 2.2 FR-2 — **TBD at design**, and the reason the answer is not "no"

Three mechanisms are live (Gate 1 deferred the choice to Gate 2):

| Mechanism | Migration? | Grant change? | Notes |
|---|---|---|---|
| Live widened query per health check | **No** | No | Cheapest to ship. Cost profile is genuinely different from today's (§6.4) and is unmeasured |
| Live query **+ an additive index** (e.g. on `roles(name)` to make the name half sargable — today's query wraps the column in `UPPER()` at `JpaUserRoleRepository.java:228`, which already de-sargonises it into a `roles` scan) | **Yes — one additive `CREATE INDEX`** | No | Additive and ADR-0003-safe. Should be *measured*, not assumed: `roles` is small, and the pre-existing scan may be irrelevant |
| Materialised per-tenant "has ≥1 active admin-equivalent holder" flag (requirements Open Question 2's simpler alternative) | **Yes — new table** | **Yes** — `nexus-database/mysql/init/02-grants-post-schema.sql:30–35` grants nothing on a table that does not exist; a new table needs an explicit `GRANT`, and grants are **not** Flyway-managed | Biggest blast radius: a schema object, a grant, a write on every relevant path, and a whole new consistency problem. Gate 1 floated it as *simpler for locking*; it is **not** simpler for deployment |

⇒ **Answer for the Gate 3 sizing:** plan for "no migration" and hold one contingency task for "one additive index"; treat the materialised-flag option as a scope change that must come back through Gate 2 with its grant and consistency story attached.

### 2.3 The grant constraint is a harder input here than it was in US-016

`nexus-database/mysql/init/02-grants-post-schema.sql:31–35`:

```
GRANT SELECT                 ON nexus.permissions       -- SELECT ONLY
GRANT SELECT, INSERT         ON nexus.roles             -- no UPDATE, no DELETE
GRANT SELECT, INSERT, DELETE ON nexus.role_permissions
GRANT SELECT, INSERT         ON nexus.user_roles
GRANT UPDATE (revoked_at)    ON nexus.user_roles
```

Two consequences specific to this story:

1. **A locking read that touches `permissions` is rejected in production and passes every Testcontainers IT** (every IT connects as the container superuser). This is the same shape as US-015's R-6 and US-012's T-R4, is already mechanically guarded by `LastAdminLockoutIT.should_neverEmitForShareOrForUpdate_when_capturingM7M8AndM9sSql` (787–830, MC-1), and now applies to **every new query this story adds**. MC-1's coverage must be **extended**, not merely kept.
2. **Role names are immutable at runtime; role *permissions* are not.** `roles` has no `UPDATE`/`DELETE` grant, so `roles.name` cannot change once written. `role_permissions` has `INSERT` **and** `DELETE`. ⇒ **This story changes the lockout guard's input from immutable data to mutable data.** Today "is this the admin role?" is a stable fact; after US-017 "is this role admin-equivalent?" can be flipped by any `role:write` holder via `RoleManagementService.detachPermission` — which, by its own Javadoc (`RoleManagementService.java:245–248`), has **no AC11 admin gate**. That is the structural basis of requirements Edge Cases 4 and 5, and it is the single thing the forthcoming `03b-threat-model.md` should focus hardest on (§5.5).

---

## 3. API / contract changes

### 3.1 Wire contract — unchanged (requirements Assumption 4 confirmed)

No new endpoint, no path change, no request/response DTO change, no new error code, no versioning need. `POST /api/v1/users/{userId}/roles`, `DELETE /api/v1/users/{userId}/roles/{roleId}` and `GET …/roles` keep their exact shapes. `LastAdminRoleException` → 409 `RBAC_002` and `InsufficientPermissionException` → 403 `RBAC_001` are reused verbatim (FR-5).

### 3.2 Behavioural contract — three changes, in two directions

| Verb / caller | Before | After | Direction |
|---|---|---|---|
| `revoke()` of a dangerous custom role that is the tenant's **last** admin-equivalent access, by an authorised caller | **204** — tenant silently zeroed | **409 `RBAC_002`** | Tightening (the story's point) |
| `revoke()` of the literally-named `TENANT_ADMIN` when the target still holds *another* admin-equivalent role | **409** (today's per-role check fires) | **204** — correctly permitted, because the tenant retains a holder | **Loosening** — a *false-positive* removal, requirements Edge Case 1 |
| `assign()`/`revoke()` of any privileged role by a caller holding an admin-equivalent custom role but not literal `TENANT_ADMIN` | **403 `RBAC_001`** | **Permitted** (subject to §1.4's predicate choice) | **Loosening — the security-critical one** |

Row 2 is worth flagging to QA explicitly: FR-1 is usually described as "more blocking", but it also **unblocks** a revocation that is blocked today. A test asserting today's 409 in that fixture is asserting a bug.

### 3.3 Health endpoint shape — keys unchanged, meaning and text changed

`/actuator/health` → `rbacZeroActiveAdmins` keeps `status`, `affectedTenantCount`, `issue`. The `issue` free-text value changes; nothing in `src/main` parses it, and the only assertions on it are in `RbacZeroActiveAdminsHealthIndicatorTest` (49–76), which asserts the **count key** and the **absence** of tenant ids, not the text. ⇒ **Not a breaking contract change**, but any external dashboard that string-matches `issue` would drift. Worth one line in the runbook.

---

## 4. UI / frontend impact — none (re-verified)

Requirements Assumption 5 is **confirmed**. Re-checked against US-016's own exploration finding (§4 of `US-016/02-impact.md`, itself verified by repo-wide search): `nexus-frontend/src/app/**` contains `auth`, `dashboard`, `design-system` only; nothing references `TENANT_ADMIN`, role assignment, or the health endpoint; `permission.guard.ts` and `has-permission.directive.ts` operate on flat permission strings from `/users/me`, not role names. This story adds no endpoint and changes no response body, so there is nothing new for a frontend to consume.

No i18n impact: the only user-visible string is `RBAC_002`'s pre-existing English message, unchanged (FR-5). Requirements §3's i18n `[CONFIRM]` resolves to **not applicable**.

**Forward note for Epic 3:** its role-management UI must expect 409 `RBAC_002` on revoking a custom role as a *normal* outcome, not only on `TENANT_ADMIN`.

---

## 5. Security impact

| Dimension | Impact |
|---|---|
| Attack surface | No new endpoint, no new input, no new parser. Two of the three behavioural changes are deny-side |
| Closes | **RES-3** (US-016 §12.3) end-to-end — both the preventive guard (FR-1) and the detective control (FR-2) — and **RES-9 / T-E26** (US-016 §12.3), together with requirements Edge Case 8's asymmetric state |
| authn | Unchanged |
| authz | **Loosened, deliberately, for the first time in this epic.** Every prior RBAC story in EPIC-002 tightened authorization. FR-3 *grants* administrative capability to a population that does not have it today. §1.4 is the reason this must be designed with a narrower predicate and threat-modelled before it ships |
| Freshness discipline | T-E7's rule survives intact: the caller-side check must remain a **live, transactional, locking** read, never JWT-derived. Whatever replaces M5 inherits `UserRoleAssignmentPort.java:35–42` verbatim, and `RoleAssignmentSecurityIT`'s stale-JWT out-of-band-revocation proof must keep passing against the **new** predicate |
| Fail-closed | Requirements §3 Security row stands: an empty/unresolvable/erroring admin-equivalence lookup must block the revocation (409) and deny the caller (403) — never silently permit. The existing M8-empty ⇒ deny precedent (R-10/T-E18, `RoleAssignmentService.java:545–553`) is the pattern to extend |
| Fail-*neutral*, deliberately | The health indicator's UNKNOWN-on-error posture (75–82) is the documented exception and must be restated so the two rules don't read as a contradiction |
| Audit | No change by default. Open Question 9 (should a lockout block emit a durable `ROLE_ASSIGNMENT_DENIED`-class row?) stays open for Gate 2; note today a 409 lockout writes **no** durable audit row, only the WARN |
| PII | **None.** Every new/changed log, metric and health field is a UUID, an integer, a role name, or a permission name |

### 5.4 The detection regression this story can create (new, not in the requirements doc)

`nexus.rbac.self_role_assignment{privileged, callerIsAdmin}` feeds the **page**-severity `nexus_rbac_gate_bypass_canary` alert (`increase(…{privileged="true", callerIsAdmin="false"}[5m]) > 0`, `US-016/monitoring.md` §2). Its whole design (07-security-review M-2, code comments at `RoleAssignmentService.java:224–241`) is that `callerIsAdmin` is derived from a **second, independent, name-based** mechanism (`callerHoldsActiveTenantAdmin`, 588–593) so that it can *disagree* with M5 and surface a gate bug.

After FR-3, an admin-equivalent custom-role holder legitimately passes the gate (`privileged="true"`) while `callerHoldsActiveTenantAdmin` returns `false` → **`callerIsAdmin="false"` → the page fires on a now-legitimate operation.** The canary must be re-derived in the same change, and doing so must not collapse the two mechanisms into one (which would return `"false"` to being unreachable — the exact defect M-2 fixed). This is a design-phase deliverable, not a doc footnote.

### 5.5 Where the threat model should focus (input to `03b-threat-model.md`, not its conclusions)

1. **Mutable admin-equivalence (§2.3 item 2)** — `detachPermission` is un-gated and can flip a role out of admin-equivalence concurrently with the lockout check. Requirements Edge Case 5 asks which side of the commit wins; T-E14's precedent rated the analogous mint-side non-locking read **High**.
2. **FR-3's predicate (§1.4)** — the vacuity proof, and whichever narrower predicate is chosen, must be attacked directly: which caller populations gain capability, and can a role be crafted to reach the chosen predicate?
3. **The union lock's new deadlock surface** — multi-role-id locking on the exact method carrying the accepted RES-10 cycle.
4. **Cross-tenant containment of the new queries** — more tables joined means more places for a missing `r.tenantId = ur.tenantId` predicate (T-S1).
5. **Health-indicator disclosure under a widened query** — FR-6 must hold; the count must not become derivable-per-tenant.

---

## 6. Performance and concurrency impact

### 6.1 Added query count per call (worst case)

| Path | Today | After (indicative — final shape is Gate 2's) |
|---|---|---|
| `assign()` / `revoke()`, non-privileged role | 5 / 4–5 statements | **+0** — the gate short-circuits before any new read (§1.2) |
| `assign()`, privileged role | +M7/M8/M5 | **+1…2**: resolving the caller's admin-equivalence costs more than one `(userId, roleId)` probe |
| `revoke()`, privileged role | M7 + M8 + M5 + M1 + M6 | **+2…3**: admin-equivalent role-id resolution for the tenant, the locked distinct-holder union, and the widened caller check |

No N+1 **if** the tenant-scoped role/permission resolution is a single query. There **is** an N+1 if implemented as "list the tenant's roles, then call M7 per role" (§1.5) — the most likely naive implementation, and worth naming in the design as a rejected shape.

### 6.2 Cost shape

- The dangerous-permission → role-ids direction is indexed end-to-end (`uq_permissions_name` → auto-index on `role_permissions.permission_id` → PK). The union lock drives off `fk_user_roles_role` as an IN-list range, the same access path M1 uses today.
- Not a hot path: `docs/features/US-012/03b-threat-model.md` records these endpoints as intentionally un-rate-limited because only privileged principals reach them; D14's denial throttle bounds the denial path. Inherit the epic-level p95 < 300 ms bar rather than inventing a story-specific one (requirements Gap 1 stays open, de-risked).
- **Cache:** none touched. No new key, TTL, or eviction. No Redis proposed.

### 6.3 The real risk is locking, and it now has a second dimension

`revoke()` today takes exactly one lock (M1, X over one role's rows), then the gate's S read, in a pinned order that ADR-0017 D4 proves deadlock-free. That proof has two stated dependencies, both mechanically asserted today:

- **MC-5** (`LastAdminLockoutIT.should_driveBothM1AndM5OffTheRoleIndex_when_explainingCapturedLockingReads`, 701–740) asserts **both** M1 and M5 use `fk_user_roles_role`, because InnoDB locks index records, not logical rows — containment is a property of the *plan*.
- **MC-6** (`…:261–263`) asserts `REPEATABLE-READ`, because the serialization claim needs gap locks.

US-017 changes **both** statements in that proof:

1. **M1 becomes an IN-list over N role ids.** Two concurrent revocations in the same tenant execute the *same* statement over the same index in the same direction, so they cannot cycle *with each other* — provided the IN-lists are identical, which they may not be if a concurrent `attach`/`detach` changes the admin-equivalent set between them (§2.3 item 2). Lock-acquisition ordering must be deterministic (requirements NFR "Scalability / concurrency"). **Decision deferred to Gate 2; what impact analysis establishes is that this is a new acquisition pattern, not a parameter widening.**
2. **The caller-side read becomes multi-role too (FR-3).** Today M5's single index record is provably inside M1's X region. If the caller check spans role ids *outside* the locked union, those are **genuinely new acquisitions** and D4's containment proof no longer holds. Conversely, if FR-1's union lock covers every admin-equivalent role id in the tenant, the caller's rows are inside it again and containment is *restored*. ⇒ **FR-1's lock scope and FR-3's read scope are coupled and must be designed together, not as two tasks.** This is the concrete, code-level form of requirements R1+R3.
3. **MC-5 must be re-derived, not merely re-run.** An IN-list plan may report `range` rather than `ref` on `fk_user_roles_role`; the assertion asserts `key` only (`explainKey`, 1047–1051), so it may survive — but that is a hypothesis to verify at Gate 2, and the test's own Javadoc (694–699) says a mismatch is an **Architect-level escalation, not a test to relax**.
4. **RES-10 is now directly in the blast radius.** `LastAdminLockoutIT` harness C's Javadoc (463–478) records that a concurrent `assign(TENANT_ADMIN)` thread reproduced a genuine InnoDB deadlock **5 of 5 runs** against real MySQL, attributed to the pre-existing RES-10 cycle, and was therefore removed from the harness. Widening M1's range from one role id to N makes that gap-lock range wider. **Requirements Gap 3 asked whether RES-10's risk acceptance needs revisiting: the answer from the code is yes** — this story must re-examine it rather than inherit it unchanged.

### 6.4 The health indicator's cost profile changes category

Today: one query joining `roles` + `user_roles`, driven by a `roles` scan (`UPPER(r.name)` at line 228 is already non-sargable), independent of tenant count in shape.

After: the same per-tenant `NOT EXISTS` but over a role set derived from `role_permissions` + `permissions`, i.e. two more tables and a set whose size grows with (tenants × custom roles carrying a dangerous permission). Requirements R2/R6 rate this High/Medium; nothing in the codebase measures it, and the actuator poll cadence is not pinned anywhere. **Impact analysis's contribution:** the mechanism choice (§2.2) should be made against a *measured* baseline of the widened live query at realistic tenant/role counts, not argued. Cheapest path to a decision: build the live query first, measure it, and only then decide whether caching/materialisation is warranted — the materialised option carries a migration, a grant change and a new consistency problem (§2.2), and buying that before measuring would be the opposite of boring.

---

## 7. Integration / cross-context impact

| Direction | Impact |
|---|---|
| `rbac` → `identity` | **None.** `rbac_must_not_depend_on_identity` (`HexagonalArchitectureTest.java:114–125`) stays green |
| `identity` → `rbac` | None in code. `RbacAuthEventAdapter` unchanged unless Open Question 9 lands |
| Intra-`rbac.application` | `RoleManagementService` is touched only if Gate 2 decides AC11's mint-side caller test must move in step with FR-3 (§11). **D13's holder-count signal (`RoleManagementService.java:186–191`) is not reusable for FR-2** — Gate 1 R2 settled this, and the code confirms it: it is computed once, at attach time, and never maintained |
| `rbac.infrastructure.health` → `rbac.infrastructure.persistence` | Existing direct-repository coupling (no port), retained (§1.8) |
| Audit pipeline | No new `AuthEventType`; no lane change; `ROLE_ASSIGNMENT_DENIED`'s PRIORITY-lane exclusion note (`US-016/monitoring.md` §2) stays true |
| Ops docs / runbooks — **must change** | See below |
| Upstream/downstream services | None. Nexus has no external consumer of these verbs |

### 7.1 Documents that currently describe literal-`TENANT_ADMIN`-only behaviour and become wrong

| Document | What breaks |
|---|---|
| `docs/features/US-012/monitoring.md` §3 (`rbacZeroActiveAdmins` row) | Says the indicator fires on "a seeded `TENANT_ADMIN`-named role with zero active assignments" and that the details "include the list of affected `tenantIds`". The first becomes false with FR-2; **the second is already stale today** (07-security-review M-1 replaced ids with a count) — pre-existing drift this story should fix while it is in there |
| `docs/features/US-012/monitoring.md` §2 (`nexus_rbac_tenant_lockout_blocked`) | Its meaning was updated by US-016 to "the tenant's **sole admin** tried to remove their own admin role". After US-017 it becomes "the tenant's sole **admin-equivalent holder**…" — see §7.2 for why the self-revocation narrowing *survives* |
| `docs/features/US-012/monitoring.md` §5 (log rows) | `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`'s field list and "Zero active admins" row both need the widened fields/semantics |
| `docs/features/US-012/runbook.md` §2 (`rbacZeroActiveAdmins` DOWN procedure) | **Three separate breaks:** step 1 tells the operator to read `tenantIds` from the health detail (already impossible since M-1); step 2's confirmation SQL is `WHERE r.name = 'TENANT_ADMIN'` (name-only, now wrong); step 6 speculates about the O-5 residual "if a tenant has custom roles with `user:write`" — which is precisely the case this story makes first-class |
| `docs/features/US-016/monitoring.md` §1 (`privileged_revoke_lock_hold`) | Its "verified emission caveat" — a non-name-match revocation never participates in this timer — becomes **false** (§1.1). Its §4 lock-hold baseline (already flagged **MEASURED FIGURE — PENDING**) must be re-derived for the widened locked region |
| `docs/features/US-016/runbook.md` §1 | The gate-bypass canary procedure, for the §5.4 false-positive |
| `docs/features/US-016/03-design.md` §6.4, §9.6, §12.3 (RES-3, RES-9) | Status flips from accepted-residual to closed, citing US-017 — following US-016's own RC-8.2 discipline: **record what is closed and what survives; do not flip an entry wholesale** |
| `docs/adr/0017-…md` | See §11 |

### 7.2 One thing that does **not** break: §6.4's self-revocation narrowing generalises

US-016 §6.4 proves the AC5 branch is reachable only for self-revocation. That proof survives and widens, and stating it here saves Gate 2 the re-derivation:

> To reach the widened lockout, the caller must have passed the privilege gate, so the caller holds an active assignment of an admin-equivalent role in the tenant (under **any** of §1.4's candidate predicates, since all of them are subsets of "admin-equivalent"). The caller is therefore an element of the tenant's distinct admin-equivalent holder set. The guard fires only when removing `ref` empties that set, which requires the set to be exactly `{caller}` and `ref` to be the caller's own assignment. Hence `targetUserId == actor.userId()`. ∎

⇒ `RBAC_002` continues to mean "the tenant's sole admin-equivalent holder tried to remove their own last admin-equivalent role" — a self-service offboarding mistake, not a third-party attack. The monitoring meaning widens; the severity tier does not need to move. Its two stated dependencies (index-record containment, REPEATABLE READ) carry over and stay asserted by MC-5/MC-6.

---

## 8. Dependency changes

**None.** No new Maven artifact, no version bump, no license review. Everything needed already exists. No `package.json` change — the npm-Windows-lockfile-prune hazard is not in play.

---

## 9. Backward-compatibility analysis

### 9.1 Compatible (unchanged)

Wire format; status-code vocabulary; error codes `RBAC_001`/`RBAC_002`/`RBAC_004`; the 404-before-403 ordering; the 403-before-409 ordering (requirements Edge Case 9 — **must be explicitly preserved**, per Gate 1 Resolution 2); `findAssignmentRefOrThrow` running before any lockout evaluation (requirements Edge Case 11); `listActive` semantics; `DenialReason`; `AuthEventType`; `GlobalExceptionHandler`; `UserRoleController`; `RbacDangerousPermissions`; `RbacRoleNames`; all Flyway migrations; all DB grants (for FR-1/FR-3); everything under `nexus-frontend/`.

### 9.2 Incompatible (intended)

The three behavioural changes in §3.2. Two deserve explicit callouts:

- **The loosening is the risk, not the tightening.** FR-3 widens who may perform privileged role changes. Every other change in this story removes capability; this one adds it. It is the reason this story needs its own threat model even though it is framed as a lockout fix.
- **Requirements FR-4's "purely additive" framing is not quite right for FR-1.** Widening from a per-role row count to a tenant-wide distinct-holder count **removes** a 409 in the Edge Case 1 fixture (§3.2 row 2). The pre-existing literal-`TENANT_ADMIN` behaviour is preserved *for tenants whose only admin-equivalent role is `TENANT_ADMIN`* — which is every tenant today that has not created a dangerous custom role, and is why the existing `LastAdminLockoutIT` scenarios still pass. Say it precisely in the design rather than claiming pure additivity.

### 9.3 Feature flags

No new flag. This rides the two shipped default-off kill switches (`feature.nexus-us012-rbac-role-assignment.enabled`, `feature.nexus-us015-rbac-role-management.enabled`), both `false` outside `dev`/`test` — so production blast radius at deploy time is zero, and the D10 argument ("a dedicated flag's off position would *be* the vulnerability") applies verbatim to FR-1/FR-2. **But note the asymmetry FR-3 introduces:** for FR-1/FR-2 the "off" state is the vulnerability; for FR-3 the "off" state is the *safe* state. If Gate 2 wants a rollback lever for the loosening specifically, that is a genuinely new flag-shape question the D10 precedent does not settle. The health indicator is **not** behind either flag — FR-2 takes effect in every environment on deploy.

---

## 10. Data migration strategy

### 10.1 None required

No shape change ⇒ nothing to migrate. Forward-only, consistent with US-016 Gate 1 decision #7.

### 10.2 …but this story owns a detection question US-016's did not

Requirements Gap 2: RES-3 has been a live gap since US-016 merged, so **a tenant may already be sitting at zero admin-equivalent holders today**, and no control would have noticed. Unlike US-016's exposure audit (a historical window needing a one-off query), this one **discharges itself**: the moment FR-2 ships, the widened health indicator reports exactly this population on its first run. Two consequences for the rollout plan:

1. **Expect a DOWN on first deploy** in any environment that has such a tenant. The runbook must say so, or the first firing will be triaged as a regression in the new code.
2. Remediation is **DBA-level** — `nexus_app` cannot `INSERT` an admin without one (the indicator's own Javadoc, 22–25), and that remains true for admin-equivalent custom roles. The existing US-012 runbook §2 remediation path must be widened, not re-invented.

No new code is needed for either: `UserRoleAssignmentPort.findActiveUserIdsForRole` (111–122) already exists for the RC-6 remediation path.

---

## 11. ADR impact

Gate 1 Resolution 3 requires a new ADR. **Next free number: 0018** (`docs/adr/` holds 0001–0017).

It must be a **standalone ADR that supersedes-in-part ADR-0017**, because ADR-0017 does not merely omit this story's decisions — it **forbids them in writing**:

> *"That rule is applied to the **target** role only. The **caller**-side admin test deliberately remains name-based … This asymmetry is a decision, not an oversight … Making the caller-side test privilege-based is a separate, larger decision that belongs with RES-3; **do not assume this ADR made it.**"* — ADR-0017, follow-on rule 2

> *"Last-admin-style lockout protection still covers only the literally-named `TENANT_ADMIN`. Extending it to admin-equivalent custom roles is tracked separately (US-016 RES-3); **do not assume this ADR covers it.**"* — ADR-0017, follow-on rule 6

ADR-0018 is the answer to both. Per ADR-0001's append-only rule and ADR-0017's own §13.1 reasoning, **ADR-0017's body is not edited**; ADR-0018 cites both follow-on rules and records that it supersedes them. It must also record:

- The two-predicate decision from §1.4 (target-side ANY vs. a narrower caller-side predicate) **with its justification**, because it is the exact point where a future reader would otherwise assume symmetry and reintroduce the vacuity bug.
- Whether the dangerous-permission name set may cross `UserRoleAssignmentPort` (ADR-0017 D2's "not passed in as a parameter either") — §1.5.
- The union-locking protocol and its containment/isolation dependencies (ADR-0017 D4's successor).
- The FR-2 mechanism and, if a migration or grant is involved, why (§2.2).
- The new residual replacing RES-9: the mint-side AC11 caller test (`RoleManagementService.verifyCallerIsActiveTenantAdmin`) remains name-based unless Gate 2 moves it, so this story **relocates** the asymmetry rather than eliminating it. Record it explicitly — that is ADR-0017 follow-on rule 5's own discipline ("a control that closes an escalation path must record, in the same change, what it does not close").

---

## 12. Test impact

### 12.1 Existing tests that must keep passing **unmodified** — the non-regression contract

| Test | Why it is load-bearing |
|---|---|
| `RoleAssignmentSecurityIT.should_return403WithNotTenantAdmin_when_nonAdminHoldingUserWriteAttemptsToGrantTenantAdmin` | **§1.4's tripwire.** A caller holding only `user:write` must still be denied. If this goes green-by-inversion, US-016 is undone |
| `RoleRevocationSymmetryIT` 87, 115 | Same tripwire on the revoke side (T-E17 closure evidence) |
| `LastAdminLockoutIT.should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin` (181–210) | Same, plus §7.2's ordering proof |
| `LastAdminLockoutIT` scenarios 1 (144–167) and 4 (605–627) | FR-4 non-regression: a tenant whose only admin-equivalent role **is** `TENANT_ADMIN` behaves exactly as today. Scenario 4 also catches hardcoded-bootstrap-role-id bugs, which the widened resolution makes *more* likely |
| `LastAdminLockoutIT` harness B (350–414) | AC5 under a real 8-way self-revocation race |
| `RbacZeroActiveAdminsHealthIndicatorTest` (33–88) | FR-6's disclosure discipline: count-only, no tenant ids, UNKNOWN-not-DOWN on query failure |
| `RoleAssignmentServiceTest` name-match paths (276, 312, 342, 1241, 1336) | FR-4 at unit level |
| All permission-less-role flows (`RoleAssignmentIT`, `RoleAssignmentAuditIT`, `RoleAssignmentCacheIT`, `ActiveAssignmentIT`, `UserRolesAppendOnlyIT`, `CrossTenantPermissionIT`) | Their `seedRole` helpers attach no permissions, so no new path fires. **Mockito note:** default empty returns still mean "not admin-equivalent", so strict-stubs stays quiet |

### 12.2 Existing tests that will need **fixture or semantic** changes

| Test | Change |
|---|---|
| `LastAdminLockoutIT` harness A (236–331) | Its timer-delta assertion (`revoked` count, 328–330) assumes the timer participates only on the name-match path; still true for its fixture, but the assertion's *rationale comment* must be updated once the timer's population widens |
| `LastAdminLockoutIT` harness C (480–593) | Directly exercises a dangerous custom role with name-match false, asserting `verify … never lockActiveAssignmentIds`-style behaviour implicitly via its comments (522–525: "M1 is never invoked on this path at all"). **That becomes false** — the union lock now runs on the dangerous path. Its outcome assertions should survive; its Javadoc and its RES-10 caveat (463–478) must be revisited against the widened lock range (§6.3 item 4) |
| `LastAdminLockoutIT` scenario 6 / MC-5 (701–740) | Must be re-derived for the IN-list plan (§6.3 item 3) |
| `LastAdminLockoutIT` scenario 7 / MC-1 (787–830) | Must be **extended** to cover every new query, especially any that touches `permissions` (§2.3 item 1) |
| `RoleAssignmentServiceTest` revoke-side dangerous-role tests (1456, 1500, 1535, 1564, 1605, 1627, 1661–1676) | Several assert `verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any())` on the dangerous path (1488, 1578, 1627, 1676). **These assertions encode today's "no lock on the non-name-match path" behaviour and are exactly what FR-1 changes.** They are the best inventory of the blast radius at unit level — count ~6 |
| `RoleAssignmentServiceTest` lockout tests (1241, 1282, 1305, 1336) | New stubs for the union resolution; `…_differentAdminRevoking_syntheticStateSeeDesign64` (1282) keeps its guard-shape role but its §6.4 citation must point at §7.2's generalised proof |
| `RbacZeroActiveAdminsHealthIndicatorTest` | Extended, not rewritten — new stubs for the widened repository method |

### 12.3 New coverage implied

| Level | Coverage |
|---|---|
| Unit (`RoleAssignmentServiceTest`) | Union semantics: one user holding two admin-equivalent roles (Edge Case 1 — **the distinct-holder proof**, §1.3); two users each holding a different admin-equivalent role (Edge Case 2); tenant with no admin-equivalent role at all (Edge Case 6); lookup empty/throws ⇒ fail closed (Edge Case 12); 403-before-409 ordering preserved (Edge Case 9); 404 still precedes everything (Edge Case 11); the non-admin-equivalent negative baseline (Edge Case 10) |
| Unit (FR-3) | The caller-side predicate, **with a `user:write`-only caller as an explicit denied case** — the §1.4 vacuity regression test, named as such in its Javadoc |
| Adapter | Delegation tests for each new port method |
| **New IT — concurrent multi-role revocation (Edge Case 3 / R1 / R5)** | **A dedicated class, not an extension of `LastAdminLockoutIT`.** Rationale: `LastAdminLockoutIT` is already 1059 lines with 7 scenarios and 3 harnesses, carries a shared bootstrap-tenant fixture with `@AfterEach` cleanup, and pins `max-denials=100` class-wide (101). The new scenario needs a different fixture (two distinct admin-equivalent roles, distinct holders, no bootstrap-tenant coupling) and is the story's central risk. Suggested: `AdminEquivalentLockoutIT`, reusing `LastAdminLockoutIT`'s `CyclicBarrier`/`Future` shape and its "any unexpected exception type fails loudly" rule verbatim |
| New IT — health indicator | Widened DOWN population against a real DB, including the "tenant has a dangerous custom role with holders ⇒ UP" positive case and the "custom role zeroed ⇒ DOWN" negative case. Note the existing unit test is Mockito-only; there is **no** IT for this indicator today (`RbacDbPrivilegeHealthIndicatorIT` exists; the zero-admins one does not). One is warranted now that the query is non-trivial |
| IT — freshness | Extend `RoleAssignmentSecurityIT`'s stale-JWT + out-of-band-revocation pattern to the **new caller-side predicate** |
| IT — canary | §5.4: an admin-equivalent custom-role holder performing a privileged self-assignment must **not** page |
| IT — DB privilege | **Only if** any new locking read is proposed that touches `permissions` — which it must not (§2.3). MC-1's extension is the cheaper guard |
| Cross-tenant | `CrossTenantPermissionIT` is relevant: the new queries join more tables, so a fixture proving the union never crosses a tenant boundary is warranted |

### 12.4 Mechanical controls this story needs

| # | Control | Prevents |
|---|---|---|
| **MC-A** | Extend MC-1's SQL capture to every new query: no `for share` / `for update` on anything touching `permissions` | §2.3 item 1 — a production-only failure that passes every IT |
| **MC-B** | A unit assertion that the caller-side predicate **denies** a caller whose only role carries exactly `user:write` | §1.4 — the vacuity regression, which compiles, reads as "symmetric", and fails open |
| **MC-C** | Re-derived MC-5 (`EXPLAIN` on the widened lock statement) | §6.3 item 3 — containment silently becoming false |
| **MC-D** | A distinct-holder assertion in the unit matrix (one user, two admin-equivalent roles ⇒ counted once) | §1.3 — the row-vs-holder confusion, which produces a guard that looks right and does not protect |

### 12.5 Gates

`./mvnw verify -DskipITs` per task (per the project's per-task DoD); one full `./mvnw verify` with Docker up in Phase 8, since this story touches persistence, locking and several `*IT`s. No frontend gate (§4). Watch the `rbac.application` JaCoCo gate; `rbac.domain` is untouched unless §1.4 adds a predicate helper there.

---

## 13. Top risks

| # | Risk | Sev | Note for design |
|---|---|---|---|
| **R1** | **A literally-symmetric FR-3 predicate is vacuous and silently reopens T-E16/T-E17** (§1.4): every caller who can reach the gate holds `user:write`, which is itself in the dangerous set. Fails **open**, compiles cleanly, reads as "doing what Gate 1 asked", and is only caught by tests an implementer would be tempted to "fix" | **Critical** | Define caller-side and target-side as two named predicates with written justification; ship MC-B; name the four existing 403 tests as an untouchable non-regression contract. If Security intended the identical ANY predicate, escalate before designing |
| **R2** | **The union check counts rows, not distinct holders** (§1.3) — a user holding two admin-equivalent roles reads as two holders, so the tenant can still be zeroed. This is the naive extension requirements R1 predicted, expressed at predicate level rather than lock level | **Critical** | Express the invariant over `DISTINCT user_id` excluding `ref.id()`; ship MC-D |
| **R3** | **Admin-equivalence becomes mutable input to a security guard** (§2.3 item 2). `roles.name` cannot change (no `UPDATE`/`DELETE` grant); `role_permissions` can, via `detachPermission`, which has **no** admin gate. The lockout's premise can be flipped concurrently by a `role:write` holder | **High** | The threat model's primary focus (§5.5). Requirements Edge Cases 4/5 need an explicit ruling on which side of the commit wins, and the answer must respect §2.3's "no locking read on `permissions`" constraint |
| R4 | **The union lock widens M1's gap-lock range on the exact method carrying the accepted RES-10 cycle** (§6.3 item 4), which reproduced a real deadlock 5/5 runs and forced a thread out of harness C | High | Re-examine RES-10's acceptance rather than inheriting it (requirements Gap 3). Pin acquisition order; prove it with the new IT, not by reasoning |
| R5 | **FR-1's lock scope and FR-3's read scope are coupled** (§6.3 item 2) — ADR-0017 D4's containment proof breaks if the caller read spans role ids outside the locked union, and is restored if it does not | High | Design them as one decision; do not split them into independent Gate 3 tasks |
| R6 | **The page-severity gate-bypass canary false-fires on a now-legitimate operation** (§5.4) — a detection regression created by the fix, the same failure class US-016 R5/R8 were written about | Med-High | Re-derive `callerIsAdmin` in the same change, without collapsing the two mechanisms into one |
| R7 | **FR-2's driving-tenant-set choice silently changes the DOWN population** (§1.8) — a tenant with no admin-equivalent role at all is invisible today and may become a routine page tomorrow | Med | Decide explicitly (Edge Case 6); pair with §10.2's "expect a DOWN on first deploy" runbook note |
| R8 | **FR-2's cost profile is unmeasured**, and the materialised alternative carries a migration **and** a grant change that is not Flyway-managed (§2.2) | Med | Measure the live query before buying materialisation |
| R9 | **Stale runbooks/monitoring produce wrong operator actions** (§7.1) — US-012's runbook already contains one instruction that cannot work today (`tenantIds` in the health detail) and one SQL query that becomes wrong | Med | Doc edits are a design-phase deliverable in the same PR, per US-016 §9.3's precedent |
| R10 | **The asymmetry is relocated, not removed** — AC11's mint-side caller test stays name-based (§11) | Low-Med | Record as a named residual in ADR-0018, per ADR-0017 follow-on rule 5 |

---

## 14. Disposition of the requirements doc's `[CONFIRM]` items

| Requirements item | Status after this analysis |
|---|---|
| Assumption 2 — admin-equivalent = `nameMatch \|\| carriesDangerousPermission` | **Settled by Gate 1 Resolution 1** for the target/detection side. **Does not transfer to the caller side** — see §1.4 (R1) |
| Assumption 3 — tenant-wide union invariant | **Confirmed, and sharpened**: the union is over **distinct holders**, not rows (§1.3) |
| Assumption 4 — no REST/DTO/API change | **Confirmed** (§3.1) |
| Assumption 5 — no frontend change | **Confirmed by exploration** (§4) |
| Assumption 6 — no DB migration | **Confirmed for FR-1/FR-3** (§2.1). **Open for FR-2** (§2.2), exactly as the assumption itself warned |
| Assumption 7 — RES-9 disposition | **Settled by Gate 1 Resolution 2** (in scope). Its predicate is **not** settled (§1.4) |
| Assumption 8 — `RBAC_002` / WARN contract reused | **Confirmed**, with two text corrections required (the WARN's message literal, §1.1; the indicator's `issue` string, §3.3) |
| Assumption 9 — health-indicator disclosure posture preserved | **Confirmed** (§1.8); `RbacZeroActiveAdminsHealthIndicatorTest` is the standing proof |
| §3 Performance — lock-hold budget `[CONFIRM]` | **Still open, and now compulsory**: US-016's own baseline is marked *MEASURED FIGURE — PENDING* and its population widens (§1.1). Recommend inheriting the epic bar and re-deriving the lock-hold ceiling from the staging soak rather than inventing one now |
| §3 i18n `[CONFIRM]` | **Resolved: not applicable** (§4) |
| Gap 3 — relationship to RES-10 | **Resolved: RES-10 must be revisited**, not inherited (§6.3 item 4) |
| Gap 2 — already-zeroed tenants | **Resolved: self-discharging via FR-2**, with a rollout note required (§10.2) |
| Open Questions 2, 3, 8, 9 | Correctly deferred to Gate 2. §1.3, §1.8, §2.2 and §6.3 scope what each one touches |

---

## 15. Effort / complexity signal for Gate 3

Not a breakdown — a sizing shape. Expect **roughly 15–18 tasks**, dominated by the concurrency work and the doc/ADR tail:

| Cluster | Tasks | Notes |
|---|---|---|
| Port + persistence (admin-equivalent role resolution; locked distinct-holder union) | 2–3 | Includes adapter delegation + repository queries + their unit tests |
| FR-1 — `revoke()` lockout widening (predicate + lock + timer) | 2 | Must land with the port work; R2/R5 |
| FR-3 — `requireActiveTenantAdmin` caller-side predicate | 2 | **Touches `assign()` and `revoke()` equally**; carries R1; needs MC-B |
| FR-2 — health indicator + widened query | 2 | +1 contingency task if an index migration is adopted |
| Observability (WARN fields, `matchedOn`-style tag if adopted, timer population, canary re-derivation) | 2 | R6 lives here |
| New ITs (`AdminEquivalentLockoutIT`, health-indicator IT, freshness, canary) | 3 | The concurrency IT is the single largest task in the story |
| Mechanical controls MC-A…MC-D | 1 | Mostly extensions of shipped harnesses |
| ADR-0018 + `03b-threat-model.md` follow-through | 1 | ADR is Gate 2 output; the task is the commit + the RES-3/RES-9 status flips |
| Doc updates (US-012 monitoring + runbook, US-016 monitoring + runbook + design residuals, Javadoc replacements) | 2 | §7.1's table is the checklist |

**Sequencing constraint for `/breakdown`:** the port/persistence, FR-1 and FR-3 clusters cannot be independently ordered — §6.3 item 2 shows the lock scope and the caller-read scope are one decision. Treat them as a single ordered chain with the concurrency IT as its exit gate.

---

## Impact-Analysis Resolution (approved by Md Nisar Ahmed, 2026-09-17)

1. **FR-3 caller-side predicate (§1.4, Risk #1): RESOLVED — Option A, ALL three dangerous permissions.** The caller-side test for `requireActiveTenantAdmin` is: literal `TENANT_ADMIN`, **or** a role carrying **all three** of `role:write` AND `user:write` AND `tenant:write`. This is deliberately narrower than the target-side predicate (`nameMatch || carriesDangerousPermission`, ANY of the three) — §1.4's "two named, separately-defined predicates" recommendation is adopted; `RbacDangerousPermissions` (or a sibling in the same domain package) must host both, named distinctly (e.g. a target-side "is dangerous" check vs. a caller-side "is fully admin-equivalent" check), so FR-7's single-source-of-truth intent is preserved without collapsing two different security properties into one predicate. Gate 2 design must write the explicit justification for why they differ (§1.4's own instruction) and re-verify the three named tripwire tests (`RoleAssignmentSecurityIT…nonAdminHoldingUserWriteAttemptsToGrantTenantAdmin`, `RoleRevocationSymmetryIT:87,115`, `LastAdminLockoutIT:181–210`) still 403 under this predicate, not just under the vacuous one.
2. **`detachPermission` AC11-style gate (§5.5 item 1 / mutable admin-equivalence): RESOLVED — fold into US-017.** `RoleManagementService.detachPermission` gains the same admin-gated check `attachPermission` already has (AC11), closing the concrete mechanism behind Edge Case 5 (a `role:write` holder flipping a role out of admin-equivalence mid-lockout-check). This adds `RoleManagementService` to this story's blast radius, contrary to §1.9's "not affected... only if" caveat — Gate 2 design and Gate 3 breakdown must account for it as in-scope, not conditional. Threat-model focus item §5.5.1 is therefore addressed by a code change in this story, not left as a documented residual risk.

**Not decided here, confirmed still deferred to Gate 2 design (per §6.3, §2.2, §5.4):** the union-lock/caller-read coupling and its deterministic acquisition ordering, the RES-10 deadlock-risk re-examination the analysis found is now required (not optional), the FR-2 health-indicator data-source/caching mechanism, and the `nexus_rbac_gate_bypass_canary` re-derivation. These are architect/security design calls, not scope calls — no further stakeholder approval needed to let the architect propose them; they come back for review as part of Gate 2's design + threat model.

Proceeding to Phase 3 (design + threat model, Gate 2).

---

## Cross-references

- Gate 1: `docs/features/US-017/01-requirements.md` (incl. Gate 1 Resolution)
- Immediate precedent on this code path: `docs/features/US-016/02-impact.md`, `03-design.md` (§5.2, §6.4, §7.2–§7.5, §9.2–§9.3, §11.2, §12.2–§12.3), `03b-threat-model.md`, `monitoring.md`, `runbook.md`
- `docs/adr/0017-privilege-based-role-assignment-gate.md` — follow-on rules 2 and 6 are what this story supersedes
- `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` — D1/D2/D3, unedited
- `docs/adr/0003-flyway-schema-migrations.md` — relevant only if §2.2 adopts an index or a table
