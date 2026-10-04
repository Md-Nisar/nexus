# US-018 Milestone 2: Security Review (Phase 7, code audit)

**Scope:** `git diff origin/main...HEAD -- nexus-backend/src/main` for commits 9b823d5 (T-001), 9b2a7e9 (T-002), 489b0fb (T-003) and 5f39c76 (code-review fixes). Files: `RoleAssignmentService`, `RoleManagementService`, `RbacAdministrators`, `RolePermissionRef`, `UserRoleAssignmentPort`, `JpaUserRoleAssignmentAdapter`, `JpaUserRoleRepository`, `JpaRoleRepository`, `JpaPermissionRepository`, `UserRoleController`, `RbacAuditPort`, `RbacAuthEventAdapter`, `DenialReason`, `V6__rbac_user_role_assign_permission.sql`. I read tests only as evidence that mitigations exist.

**References:** `SECURITY.md`, OWASP Top 10 (2021), `03b-threat-model.md`, `06-code-review.md`.

**Verdict: APPROVED.** No Blocker or High findings. There is 1 Medium, which should be dispositioned before the parent flag is enabled in any shared environment (see M-1), plus 6 Low and 1 informational note.

---

## 1. Evidence gathered (gates actually run)

| Gate | Result |
|---|---|
| Targeted unit and ArchUnit tests: `RoleAssignmentServiceTest` (137), `RoleManagementServiceTest` (61), `RbacAdministratorsTest`, `RolePermissionRefTest`, `UserRoleControllerTest`, `RbacAuthEventAdapterTest`, `JpaUserRoleAssignmentAdapterTest`, `HexagonalArchitectureTest`, `TenantIsolationArchitectureTest` | 0 failures, 0 errors |
| Security ITs (Docker/Testcontainers): `GrantSubsetIT` (13), `RbacSchemaMigrationIT` (14), `RoleAssignmentSecurityIT` (28) | 55 run, 0 failures. **BUILD SUCCESS** |
| `./mvnw dependency:tree` | Ran. The branch changes no `pom.xml` and no dependency. I did not run OWASP dependency-check locally because it needs an NVD download; the CI profile covers it |
| `npm audit` (frontend not touched by this branch) | Pre-existing: prod 7 (6 moderate, 1 high: `@angular/router`, an SSR DoS); full tree 37 (3 critical, all in dev and build tooling). See I-1 |

`TenantIsolationArchitectureTest`: **`UNSCOPED_ALLOWLIST` is not modified** by this branch. M15 (`SELECT p.id FROM Permission p`) reads the global catalogue, which has no tenant column, so no exemption was needed.

---

## 2. Threat-model cross-reference

| Row / control | Status claimed for M2 | Visible mitigation in the diff | Verdict |
|---|---|---|---|
| **A1** `user:role:assign` endpoint gate | Mitigated | `UserRoleController.java:86,149` `@RequiresPermission(USER_ROLE_ASSIGN)` on assign and revoke. `resolveActor(..., USER_ROLE_ASSIGN)`. No `"user:write"` literal remains in `rbac.application` or `rbac.interfaces` | Present |
| **A2** grant-subset | Mitigated | `RoleAssignmentService.java:1070-1103` `requireGrantWithinCallerHoldings`: M14(target) ⊆ ∪M13(caller), using ids only from one live DB read, never M12 and never a JWT claim. A read failure propagates as a 500, never an allow | Present |
| **A3** attach-subset | Mitigated | `RoleManagementService.java:202, 432-451` `requireCallerHoldsPermission` runs on every attach, after AC11 and before the duplicate 409 | Present |
| **A4** self-assignment denial | Mitigated | `RoleAssignmentService.java:1022-1056`. `RbacAdministrators.isAdminDefining` is evaluated **per role** (groupingBy roleId), never over the union. An empty catalogue means no administrator. Tested: catalogue split across two roles is denied (`RoleAssignmentServiceTest`, `GrantSubsetIT.should_return403SelfAssignment_when_callerHoldsCatalogueOnlyAcrossTwoRoles`); legacy gate passes, then A4 denies (5f39c76) | Present |
| **T-E32** (High, ❌) RES-1(b) survives via a second account | M2 owns only RC-23.1 (restatement). RC-23.2/23.3 belong to M3 | The Javadoc on `assign()` and on `requireAdministratorForSelfAssignment` states "self path only; RES-26". It nowhere claims RES-1(b) is closed. RES-26 was accepted at Gate 2 (design §0) | **Correctly not claimed as mitigated.** Code has no preventive control, by design. The PR description and the EPIC-002 record must say "self path closed; transformed into RES-26" |
| **T-E35** catalogue coupling (first footer instance, RC-27.1) | Mitigated for V6 | V6 footer (a), lines 26-50: roles that held the whole pre-migration catalogue gain the new id. `RbacSchemaMigrationIT` covers the full-catalogue custom role, the one-permission-short role, and footer idempotence (run green) | Present |
| **T-E36** M13 as a shared input (M2 owns the input only; RC-28 is M3) | Input hardened | `JpaUserRoleRepository` M13 has `r.tenantId = ur.tenantId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL`, an inner join, ids only. `GrantSubsetIT.should_ignoreForeignTenantRole_when_userRoleRowPointsCrossTenant` passes. The US-017 M12-based canary is still live in M2 (`callerWasAdminBeforeThisAssignment`), so there is still an independent signal until M3 | Present (M2 part) |
| **T-E41** ✅ union-holder plus colluder | Accepted | Per-role A4 verified; the exemption is harmless to a holder of everything | Confirmed |
| **T-E42** ✅ A1 rolling overlap / V6 cache lag | Accepted | No fallback to `user:write` anywhere. V6 (b) re-syncs every system `TENANT_ADMIN` | Confirmed (operational; the runbook cache flush still applies) |
| **T-T21** (Low, ❌) footer checkability (RC-48) | Partially, for M2 | RC-48.1 template form is present (one placeholder instantiated with exactly the inserted id). RC-48.2 IT step is present. **The RC-48.1 scanner is deferred to T-021 (M8)** | Partial: see L-3 |
| **RES-27** snapshot TOCTOU on lock-free paths | Accepted (Low) | M13 is a non-locking snapshot, documented in code. On privileged targets the legacy M5b locked, contained gate still runs first, so T-E33 does not regress in M2 | Confirmed |
| **RES-13** mint side name-based | Closed by A3 (with role-subset in M3) | A3 applies to every permission, not only dangerous ones | Confirmed (M2 half) |

---

## 3. Ordering verification

**assign()** (`RoleAssignmentService.java:229-410`) runs in this order:
1. Tenant checks T1/T2 (404/403 `CROSS_TENANT_TARGET`).
2. Throttle.
3. Legacy gate (privileged only, under the M11 lock).
4. M13 (one read).
5. A4: M15 is read only when the target is the caller.
6. A2 (M14).
7. Duplicate 409.
8. Insert.

This matches Decision 6. Every 403 is raised before the 409, so a denied caller learns nothing about the target's assignment state. Each denial writes exactly one `ROLE_ASSIGNMENT_DENIED` row carrying the first reason (unit-tested pairwise). A4 and A2 both book against the throttle.

**attachPermission()** (`RoleManagementService.java:181-205`) runs in this order:
1. Tenant resolution.
2. AC7 409 (system role).
3. Permission 404.
4. AC11 (dangerous only).
5. A3.
6. Duplicate 409.
7. Insert.

A3 runs before the duplicate check (`should_denyGrantExceedsCallerAndNeverCheckDuplicate...`). The AC7 409 and the permission 404 leak nothing new: role kind and catalogue contents are already readable via `role:read` and `GET /permissions`.

**403 body** (`GlobalExceptionHandler.java:159-176`): `RBAC_001`, a generic message, and `requiredPermission` only. `reason` goes to the log and metric, never the body. For A2/A4 `requiredPermission` is the endpoint permission; for A3 it is `role:write`, never the permission being attached. **No oracle on role contents or on the caller's holdings.**

**Metrics:** `nexus.rbac.permission_denied{permission,reason}` gains two bounded enum values. The branch adds no new metric and no new tag. Cardinality is unchanged.

---

## 4. Findings

### [MEDIUM] M-1: In the M2 to M3 interim, revoke is gated by a delegable, non-dangerous permission and has no subset check
File: `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:469-532`; `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java:147-149`
OWASP: A01 Broken Access Control, A04 Insecure Design

**Issue:**
- Before M2, revoke required `user:write`. That permission is in `RbacDangerousPermissions`, so only an active `TENANT_ADMIN` could hand it out (legacy gate).
- After M2, revoke requires `user:role:assign`. That permission is deliberately **not** dangerous (design §4.2), and A2 lets any holder hand it on to others.
- A2 bounds what a delegate can **grant**. Nothing in M2 bounds what a delegate can **revoke**: revoke-subset lands in M3.
- Result: a delegated assigner can revoke any non-privileged role from any user in the tenant, including roles carrying permissions the delegate does not hold and could not grant. Peer delegates' `user:role:assign`-bearing roles are included.
- The threat model analyses the interim for A1/V6 (T-E42), but not this widening of the revoke population.

**Risk:**
- An insider (or a compromised delegate account) can strip other users' non-privileged access across the tenant, including other delegates' assignment rights. This is an integrity and availability attack.
- Each action is audited as `ROLE_REVOKED`. It is not an escalation: privileged roles still hit the legacy gate and the last-admin guard.
- Reachability: an administrator must first create a delegated role, since A3 means only holders can attach `user:role:assign`. The parent flag `feature.nexus-us012-rbac-role-assignment` is off in production.

**Fix (either one):**
- (a) Pull the revoke-side subset check into M2. Reuse M13 + M14 on revoke (`requireGrantWithinCallerHoldings` with `OPERATION_REVOKE`), placed after throttle and the legacy gate and before the last-admin 409.
- (b) Record this as a new residual in `03b-threat-model.md` (owner: Architect). Add a release gate: "M3 merged before the parent flag is enabled in any environment, and no role carrying `user:role:assign` other than admin-defining roles exists before M3."

### [LOW] L-1: Endpoint permission comes from the JWT; A2 and A3 do not re-verify that the caller still holds it
File: `RoleAssignmentService.java:1070-1103`; `RoleManagementService.java:432-451`
OWASP: A01, A07

**Issue:** `@RequiresPermission` reads the token's `permissions[]`. A2 and A3 use the fresh M13 read for the **target's** permissions, but never check that M13 still contains `user:role:assign` (or `role:write` for attach).

**Risk:** a delegate whose role was revoked for cause keeps, until token expiry (about 900 s), the ability to:
- assign roles within their remaining fresh holdings;
- revoke non-privileged roles (M-1).

This is the same class as the old `user:write` behaviour, and M7 (epoch freshness) is the planned systemic fix.

**Fix:** optional and zero extra reads. Assert that the seeded `user:role:assign` id (V6 literal, `019f6839-1807-7000-8000-000000000008`) is in M13's permission ids before A4/A2. Otherwise record this as covered by M7.

### [LOW] L-2: M14 returns an empty set on tenant mismatch, which A2 reads as "grants nothing"
File: `RoleAssignmentService.java:1077`; `JpaRoleRepository.findPermissionIdsByRoleAndTenantId`
OWASP: A01 (defense in depth)

**Issue:** this agrees with the code review's Low. It is safe today only because `resolveRoleInTenant` runs first in the same transaction, and a role's tenant is immutable. The Javadoc now states this correctly.

**Risk:** a future caller that skips `resolveRoleInTenant` would fail open.

**Fix:** return `Optional<Set<UUID>>` (empty = role not in tenant) and deny on empty, or keep the documented precondition plus an ArchUnit/grep check that M14 is called only after `resolveRoleInTenant`.

### [LOW] L-3: T-T21: the B7 footer scanner (RC-48.1) is not yet in place
File: `nexus-backend/src/main/resources/db/migration/V6__rbac_user_role_assign_permission.sql:26-50`
OWASP: A08 Software and Data Integrity Failures

**Issue:** V6 is correct, and its exclusion list equals exactly the id it inserts. The scanner that enforces this for future permission migrations is deferred to T-021 (M8).

**Risk:** a permission-adding migration merged before T-021 that copies V6's footer verbatim would silently demote every admin-defining role (T-E35 recurs).

**Fix:** until T-021 lands, block any new `INSERT INTO permissions` migration in review, or pull the scanner forward.

### [LOW] L-4: A3 denials leave no durable audit row
File: `RoleManagementService.java:432-451`
OWASP: A09 Security Logging and Monitoring Failures

**Issue:** this is by design (Decision 7, and it matches AC11). The trail is a WARN `RBAC_ATTACH_EXCEEDS_CALLER` (ids only) plus the `permission_denied` counter. No state changes, so this is not a repudiation gap for a mutation. The trade-off is that probing of attach is visible only in logs.

**Fix:** none required now. Revisit when B8's audit work lands in M8.

### [LOW] L-5: The assignment adapter injects a writable `JpaPermissionRepository` for a read-only need
File: `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java:47,57`
OWASP: A04 (least privilege, code hygiene)

**Issue:** `JpaRepository` exposes `save` and `delete` on `permissions`. Today only the DB grant (`nexus_app` has `SELECT` on `permissions`) stops a future misuse.

**Fix:** host M15 on a narrow `Repository<Permission, UUID>` interface that declares only `findCatalogueIds()`. The code review suggested the same.

### [LOW] L-6 (pre-existing, not introduced): revoke returns 404 before throttle and before the privilege gate, leaking assignment state
File: `RoleAssignmentService.java:485`
OWASP: A01

**Issue:** `findAssignmentRefOrThrow` (404 `ROLE_ASSIGNMENT_NOT_FOUND`) runs before `requireNotThrottled` and before the legacy gate. A `user:role:assign` holder without `user:read` can therefore probe whether user U holds role R. They get 404 versus 403 (privileged) or 204, and the probes are not throttled. This runs against the Decision 6 principle that US-018 applied to assign.

**Fix:** when M3 adds revoke-subset, order the revoke denials before the 404, or accept and record it.

### [INFO] I-1: Frontend dependency vulnerabilities (pre-existing, out of scope)
`npm audit --omit=dev` reports 6 moderate issues (Angular common/compiler/core/forms/platform-browser/animations) and 1 high (`@angular/router`, an SSR DoS, which matters only if SSR is enabled). The full tree has 3 critical issues (`@angular/build`, `piscina`, `tar`), all in dev and build tooling. This branch touches no frontend file. Raise a separate dependency-upgrade ticket.

---

## 5. Hostile-path checks with no finding

- **Cross-tenant / IDOR:**
  - Tenant always comes from `RoleChangeActor` (the token), never the request.
  - T1/T2 run before any new read.
  - M13 is double tenant-predicated and joins `Role` on `r.tenantId = ur.tenantId`, so a drifted `user_roles` row cannot widen holdings (IT-proven).
  - M14 is tenant-predicated. M15 is global by definition.
  - Denial rows are written under the actor's tenant, with `roleName = null` on cross-tenant denials.
- **Self-assignment through two partial roles:** denied (per-role evaluation; unit test and IT).
- **Self-assignment through a second account:** RES-26 (T-E32). Not prevented in M2, as designed and accepted.
- **Fail-open paths:**
  - M13, M14 and M15 failures propagate (500, rollback); tested for M13 and M15.
  - An empty M13 denies any target that carries permissions.
  - An empty catalogue means no administrator.
  - The only swallow is the pre-existing `isThrottled` (MC-7(i)), unchanged.
- **Last-admin interplay:**
  - Assign cannot reduce administrators.
  - Revoke keeps the last-holder guard after the privilege gate.
  - V6 grows the catalogue but preserves admin-defining status (footer (a)), so the lockout population does not shrink at V6.
- **TOCTOU:**
  - Non-privileged path: RES-27, a millisecond window.
  - Privileged path: still protected by the contained M5b locking read in M2.
  - A concurrent attach to the target role after M14 is the RES-26 class (attach-after-assign), not a new residual.
- **SQL/JPQL injection:** all new queries are static JPQL with bound `@Param`s. V6 contains only literals.
- **V6 safety and idempotence:**
  - Data only, no DDL and no grant.
  - The permission insert is protected by Flyway versioning and the unique name.
  - Footer statements (a) and (b) are idempotent `INSERT…SELECT…WHERE NOT EXISTS` (IT re-runs green).
- **Who gets `user:role:assign` from V6:**
  - Every system `TENANT_ADMIN` (`is_system_role = TRUE AND name = 'TENANT_ADMIN'`; a tenant cannot create a system role).
  - Every role that already held the whole pre-migration catalogue, which already included `user:write`.
  - `MEMBER` and partial custom roles get nothing.
  - So the population able to assign **shrinks** from all `user:write` holders to admin-defining holders. This fails closed; the runbook detection query handles the availability side.
- **PII and secrets:**
  - New WARN and audit fields are UUIDs, a reason enum and an integer `missingCount`.
  - No email, name, IP, token or permission names in denial metadata. CRLF injection is not possible because no free-text input is logged.
  - The branch adds no secret and no configuration.
- **Crypto:** none in scope. This branch adds or changes no cryptographic code.

## 6. Challenge to `06-code-review.md`

- Its Medium (A4 on a privileged target untested) is **closed** by 5f39c76: a unit test plus a `GrantSubsetIT` case, both run green here.
- Its "ITs have not run" Low is **closed** for the three security ITs, which I ran here (55/55).
- It missed **M-1**: the interim revoke widening caused by moving revoke to a delegable, non-dangerous permission without revoke-subset.
- It missed **L-1**: the endpoint permission is not re-verified from M13.
- I agree with its L-2 (M14 fail-open) and its L-5 suggestion (narrow repository interface).

## 7. Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 1 (M-1) |
| Low | 6 (L-1 to L-6; L-6 pre-existing) |
| Info | 1 (I-1, pre-existing frontend deps) |

**Verdict: APPROVED.** Condition: M-1 must be dispositioned before the parent flag is enabled in any shared environment, either by fix (a) or by the residual and release gate in (b). Ship M2 as is with the flag off.

**Concerns explicitly reviewed:**
- **Authorization:** endpoint gate, object-level and cross-tenant checks, A1 to A4 ordering, fail-closed behaviour, oracle and timing behaviour, TOCTOU and the last-admin guard.
- **Cryptography:** none present in the change set.
- **PII handling:** logs, audit metadata, 403/409 bodies and metric tags.

## 8. Fix status (post-review, branch `feature/US-018`, uncommitted)

| Finding | Status | Notes |
|---|---|---|
| M-1 | **Fixed (option a)** | Revoke-subset (M13 ⊇ M14) runs after the throttle and the legacy gate, before the last-admin 409. Denial: 403 `RBAC_001`, one `ROLE_ASSIGNMENT_DENIED` row (`GRANT_EXCEEDS_CALLER`, `operation=revoke`), and the metric from the central handler only. Unit tests are in `RoleAssignmentServiceTest`; `GrantSubsetIT` adds revoke-denied and revoke-allowed cases. |
| L-1 | **Fixed** | `user:role:assign` (on assign and revoke) and `role:write` (on attach) must be in the caller's fresh M13 rows, checked by seeded id with no extra read. Denial is 403 `PERMISSION_ABSENT`. On assign and revoke there is also a denial row; attach has none (Decision 7). M7 remains the systemic fix. |
| L-2 | **Fixed** | M14 returns `Optional<Set<UUID>>` from a single `LEFT JOIN` statement. Empty means "role not in tenant", and the service denies `CROSS_TENANT_TARGET`. |
| L-3 | Deferred | The B7 footer scanner is T-021 (M8). Until then, review blocks any new `INSERT INTO permissions` migration. |
| L-4 | Deferred (by design) | Decision 7 / AC11: A3 (and now L-1 on attach) denials are WARN plus counter only. Revisit with B8's audit work in M8. |
| L-5 | **Fixed** | M15 is hosted on `JpaPermissionCatalogueRepository` (`Repository<Permission, UUID>`, `findCatalogueIds()` only). `UNSCOPED_ALLOWLIST` is unchanged. |
| L-6 | Deferred | Pre-existing. It is ordered together with M3's revoke denials (move them before the 404) when M3 lands. |

ITs were compiled but not run for this fix. They run in the Phase 8 test-validate pass.
