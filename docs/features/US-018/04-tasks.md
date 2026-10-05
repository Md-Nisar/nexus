# US-018 — Task Breakdown: Harden RBAC for production readiness

**Phase:** 4 (Task Breakdown), Gate 3
**Status:** **Gate 3:** approved 2026-10-02 by the story owner. Decisions: ADRs renumbered to 0021–0025; `/docs` runs per milestone (before `/pre-pr-check`) for any milestone whose merge checklist gates on runbook or alert content, rather than all docs waiting for M11; no Jira sub-tasks.
**Decision 2026-10-05 (no staging, no deployment):** the app is not deployed and no environment exists, and work starts without one. Consequences, all recorded in `STATUS.md`:
- **M3's "M2 soaked in staging ≥ 1 sprint" gate is waived for starting M3.** The soak, the "no `RbacAdministrators` anomalies" check and the zero-admin sweep are not dropped: they become conditions on the **first staging deployment**, before any production traffic. M4 and M7 merged, and M3's own threat-model re-pass, still gate M3.
- **Rollout-order waits are vacuous until a deployment exists:** "M6 deployed on every instance before M7", "M7 on every instance ≥ 900 s before M7b" and "M9 live everywhere before M9-contract" reduce to "merged earlier". The PRs stay separate.
- **Environment-dependent checklist items** (staging drills, per-environment queries, cache flushes, Ops sign-offs, and the k6 gates that name "the staging topology") are **deferred to the first deployment** and remain required before production. Where such an item is marked merge-blocking (T-009's k6 hot-path run, T-023's B6 benchmark), the story owner decides before that PR whether to run it on a local topology or defer it; it is not silently waived.

**Epic:** EPIC-002 (RBAC Foundation)
**Inputs (all read, binding):**
- `docs/features/US-018/01-requirements.md`: the 30 ACs and §14 Gate 1 decisions (one story, delivered as milestones; each milestone is its own PR).
- `docs/features/US-018/02-impact.md`: file inventories and line citations (cited below as "impact §x").
- `docs/features/US-018/03-design.md`: **Revision 3, approved at Gate 2 on 2026-10-02**, with §0 decisions 1–30 and the R1-1..R1-5 rulings (cited as "design §x").
- `docs/features/US-018/03b-threat-model.md`: RC-23..RC-54, L-1..L-6 (§13.5), the §10 / §11.8 / §12.7 merge-checklist additions, and the §13.8 Gate 2 decision (cited as "TM §x").
- ADRs `0021-grant-subset-authorization-model`, `0022-permission-token-freshness`, `0023-object-level-authorization-deferred`, `0024-atomic-audit-for-rbac-mutations`, `0025-break-glass-admin-cli` (all Proposed).
- Format precedent: `docs/features/US-016/04-tasks.md` and `docs/features/US-017/04-tasks.md`.

**Verification basis.** Every path under "Files impacted" was confirmed to exist with Glob on `feature/US-018` this session. Paths under "Files created" do not exist yet. Line numbers are the design's and impact's citations at `3d8ec5f`; re-read them before editing, because M2 to M8 each shift `RoleAssignmentService.java` and `RoleManagementService.java`.

**Why there are 31 tasks rather than ≤ 8.** Gate 1 split US-018 into 10 independently merged milestone PRs plus a separate contract release (V10) and the M7b version cut. A task cannot span two PRs, so the floor is one task per PR (12), and the larger milestones (M7: six independent fail-open and availability controls; M9: soft-delete, PATCH, paging, access review, UI) need several vertical slices each to stay inside ~300–600 production lines.

**Per-task gate** (CLAUDE.md §4; project practice "skip ITs during implementation"): backend tasks run `./mvnw verify -DskipITs` from `nexus-backend/` (`mvnw.cmd` on Windows) and build only the touched module (`mvn -T 1C -pl nexus-backend install -DskipTests` when a build is needed). Frontend tasks run `npm run test:ci`, then `npm run lint && npm run format:check`, from `nexus-frontend/`. Each task still **writes** the `*IT` classes it owns. The full Testcontainers IT suite (Docker up, `./mvnw verify`) and any k6 runs execute once per milestone, in that milestone's `/test-validate`.

**Per-milestone exit** (Gate 1 delivery model): `/review` → `/security-review` → `/test-validate` → `/pre-pr-check` → PR. Every milestone's `/security-review` re-runs `./mvnw dependency:tree` and `npm audit` (TM §10, "all milestones"; baseline: no manifest delta, 27 pre-existing npm findings not attributable to this story).

**No PII.** People are referred to by role only.

---

## Gate 1 gaps (found while slicing; not invented here)

| # | Gap in `01-requirements.md` | How this breakdown handles it |
|---|---|---|
| G-1 | **Hot path, no updated budget.** §5 and R5 mark A9's per-request epoch lookup as threatening EPIC-002's existing **< 5 ms p95 permission-check budget at 200 RPS**, and state "no updated target". | The Gate 1-stated envelope (< 5 ms p95 at 200 RPS) is binding. Gate 2 approved a tighter **≤ 2 ms p95** for the epoch check itself (design §9.5, merge-blocking). T-009 carries a k6 load test against both numbers. No other budget is invented. |
| G-2 | **A2/A3 live read has no performance target** (§5, §8.1). §5 calls it "low-volume, admin-only", so it is **not** a hot path. | No load test added. The design's < 10 ms p95 added latency (design §4.6) has no stated verification method; listed as open item O-1, not tasked. |
| G-3 | **No availability SLO** for the RBAC API or the authorization path (§5, §8.1). | Unchanged. The A9 availability consequence is RES-30, accepted by the story owner at Gate 2 (TM §13.8), with SRE + PM confirmation on the M7 merge checklist. The SLO itself is still missing (open item O-2). |
| G-4 | **No tenant-size or session-concurrency figures** (§5, §8.1) to size A9/A10 fan-out. | The design's assumptions (10,000 holders, batch 500, 100,000-user replay queue; design §9.3, §9.4) are used as given. The k6 NAT gate uses the design's 200-holder case. No new sizing is invented. |
| G-5 | **FR-A5.c "shrinks materially" is untestable** (§8.2). | Uses the design's measurable proxy (design §5.1 footer): a grep-based ArchUnit test (T-019). |
| G-6 | **Revocation latency success metric** (§13: "measured p95/p99") has no target number. | TS-8 asserts "under 1 s" in `TokenFreshnessIT` (design §9.11). A production p95/p99 is a post-M7 measurement, not a task (open item O-3). |

---

## Ambiguities resolved by judgment (read before starting the named task)

| # | Where | Ambiguity | Resolution |
|---|---|---|---|
| **A-1** | design §4.3 (M13) vs code | The design names a **new** `rbac.domain` record `RolePermissionId`, but `rbac/domain/RolePermissionId.java` already exists as the `@EmbeddedId` of `RolePermission` (a JPA embeddable, not a record). | **New record `RolePermissionRef(UUID roleId, UUID permissionId)`** (mirrors `ActiveAssignmentRef`'s naming). The JPA key is not reused as an authorization projection. T-001. |
| **A-2** | `docs/adr/` | `0019-tenant-fairness-and-quotas.md` and `0020-tenant-data-lifecycle.md` already exist beside this story's staged `0021-grant-subset-…` and `0022-permission-token-freshness.md` (impact §0 said 0021 was free). | **Resolved at Gate 3 (2026-10-02):** this story's ADRs renumbered to 0021–0025 and every citation updated. |
| **A-3** | design §9.10, §9.12, §10.8 | `application-prod.yml` is named as the home of `require-auth=true` and `require-shared-store=true`, and impact §12.3 said no `prod` profile file exists. **Corrected at T-001 planning (2026-10-02):** `nexus-backend/src/main/resources/application-prod.yml` exists (since commit 0c2fed5). | T-014 **modifies** it (adds `require-auth=true`); T-024 extends it. M7 merge checklist: Ops confirms production activates the `prod` profile (otherwise the assertion is inert). |
| **A-4** | design §1.2 vs §9.6 | M7b "after at least 900 s once M7 is on every instance" can land while M3 is in flight. | M7b is numbered after M7 (T-015) but its PR may merge any time after the condition holds, independent of M3. |
| **A-5** | design §11.1 V10 | "The release after M9 is live everywhere" is a separate PR. | Own section "M9-contract" with T-031, last in the document. |
| **A-6** | design §5.1 row 15, §7.2 "Precondition" | The CLI's zero-administrator precondition uses the ADR-0018 population in M5 and the §2.1 definition from M3. | M5 (T-007) uses the shipped caller-qualifying population; T-019 switches it with the predicate deletion, and re-runs `BreakGlassAdminIT`. |
| **A-7** | design §10.6 (B6) | Scope of T-023 depends on the benchmark outcome. | T-023 always lands the bypass property, the k6 run and the ADR-0022 addendum; the deletion branch is conditional and sized L, the keep branch S. |
| **A-8** | design §2.3 vs user brief | RES-6 retention sign-off is listed on M2, M5 and M8 by TM §8, and also on **M3** by design §2.3 (two new M3 markers). | Included on all four checklists. |
| **A-9** | TM §10 M8 item | "V7 pre-flight = 0" predates the RC-40.4 split. | Read as the **V8** pre-flight (the composite FK is V8). |
| **A-10** | runbooks / monitoring | Many merge-gating items are runbook or alert definitions (A1 detection, cache flush, V8 pre-flight, `flyway repair`, break-glass procedure, rollback-pages-Security, alert rules in `monitoring.md`). Alert rules live only in docs in this repo. | They are **not tasks** (rule: no docs-only tasks). Each appears as a merge-checklist item of its milestone, authored in that milestone's docs pass; M11 covers the cross-cutting D-group docs. |
| **A-11** | B4 | ADR-only (Gate 1 OQ7); ADR-0023 is already drafted on this branch. | No task. AC table maps B4 to ADR-0023 plus the M8 merge checklist (accept the ADR). |
| **A-12** | C5 | "No code change; pin it" yields a test-only item, which may not be a task. | Folded into T-029 (C3), where "a newly registered user has zero effective permissions" is the natural companion assertion. |
| **A-13** | design §5.3 | The `DenialReason` for revoke-subset failures is not named (only `SELF_ASSIGNMENT` and `GRANT_EXCEEDS_CALLER` are new). | Subset failure → `GRANT_EXCEEDS_CALLER`; administrator-requirement failure → the existing `NOT_TENANT_ADMIN`, so the 403 tests kept verbatim stay byte-identical. T-016. |
| **A-14** | design §5.1 row 12, §11.1 | The role-subset denial WARN marker (detach, C1 PATCH/DELETE) is not named. | `RBAC_ROLE_SUBSET_DENIED {tenantId, actorUserId, roleId, operation}` with `operation ∈ {detach, update, delete}`; covered by the M3 RES-6 sign-off. Confirm at `/review` (O-5). |
| **A-15** | design §5.1 row 13 | The page condition (permission is `user:role:assign` / `role:write`, or the attach makes the role admin-defining) cannot be expressed from the `{holders}` tag alone. | Add one bounded tag `page ∈ {true, false}` computed by the RC-23.2 rule (2× series, no tenant tag). Confirm at `/review` (O-5). T-017. |
| **A-16** | impact §9 B3 vs M3 | Both `tenantId`-tagged meters (`RoleAssignmentService.java:354`, `RoleManagementService.java:254`) belong to signals M3 deletes or re-derives without tenant tags. | T-020 still lands MC-8 and removes any tag a repo-wide grep finds; B3 may then be a guard-only change. |

---

## Group map and delivery order

```
US-018 (one story, 12 PRs)
├─ PR 1  M2   A1–A4 grant-subset core ........ T-001 T-002 T-003      (V6)
├─ PR 2  M1   A8 deny-by-default ............. T-004
├─ PR 3  M6   A11 claim validation ........... T-005
├─ PR 4  M4   A6 atomic audit ................ T-006
├─ PR 5  M5   A7 break-glass CLI ............. T-007 T-008
├─ PR 6  M7   A9 epoch + A10 fan-out ......... T-009 … T-014
├─ PR 7  M7b  drop v2 tokens ................. T-015                 (≥ 900 s after M7 everywhere)
├─ PR 8  M3   A5 retirement + D3 ............. T-016 … T-019          (own threat-model re-pass)
├─ PR 9  M8   Group B ........................ T-020 … T-024          (V7, V8 + maintenance window)
├─ PR 10 M9   Group C ........................ T-025 … T-030          (V9 + maintenance window)
├─ PR 11 M9-contract ......................... T-031                 (V10, next release)
└─ PR 12 M11  Group D docs ................... no tasks (Phase 9 /docs)
   M10 / C4 ................................. out of scope (Gate 1 OQ5)
```

**Totals:** M2 3 · M1 1 · M6 1 · M4 1 · M5 2 · M7 6 · M7b 1 · M3 4 · M8 5 · M9 6 · M9-contract 1 · M11 0 = **31 tasks**.

**Feature flags:** no new flag in any task (design §13, Decision 29). Every task's DoD includes "no new flag".

---

# M2 — A1–A4 grant-subset core (PR 1, P0)

**Status (2026-10-05):** merged to `main` as PR #81 (2026-10-04). The ops/deploy items below are deferred to the first deployment (no environment exists, see the Decision at the top). See [STATUS.md](STATUS.md).

**PR boundary.** T-001 → T-002 → T-003 in one PR on `feature/US-018/M2`. Contains V6 and nothing from any other milestone. Ends with `/review`, `/security-review`, `/test-validate` (full IT suite, Docker up), `/pre-pr-check`, then the PR.

**Threats owned:** T-E32 (RC-23.1), T-E41 ✅, T-E42 ✅, T-E35 (RC-27.1 footer, first instance), T-T21 (RC-48 template, first instance), T-E36 (the M13 input; its fix lands in M3).

**Merge checklist (M2):**
- [ ] **RES-26 recorded before merge** per RC-23.1: design §4.9 and ADR-0021 "does not close" carry it; EPIC-002 reports RES-1(b) as **"self path closed; transformed into RES-26"**, never "fully closed" (TM §10).
- [ ] **RES-6:** Ops sign-off that `RBAC_ATTACH_EXCEEDS_CALLER` WARN logs are retained at least as long as `auth_events`, minimum 1 year (design §2.3).
- [ ] **Ops confirms production does not override the parent flags** `feature.nexus-us012-rbac-role-assignment.enabled` / `feature.nexus-us015-rbac-role-management.enabled` (impact §12.3: no prod file in the repo, so an env-var override cannot be ruled out from code; requirements §9).
- [ ] **A1 detection query** run in every environment where the US-012 flag was ever `true` (non-system roles carrying `user:write`, by tenant, ids only). A non-zero production count goes to PM and Security before deploy (design §4.8).
- [ ] **Custom-admin exposure check** run before and after deploy (design §4.8, RC-27.2(a) wording).
- [ ] **Permset cache flush** (`SCAN`/`DEL nexus:rbac:permset:*`) after V6 applies (design §4.8).
- [x] **ADR numbering collision resolved** (A-2): renumbered to 0021–0025 at Gate 3.
- [ ] V6 version number confirmed at merge (impact §12.1).
- [ ] Exit criterion: V6 applied; `GrantSubsetIT` green in staging; the staging soak that gates M3 (≥ 1 sprint) starts. *(2026-10-05: M2 merged as PR #81; no environment exists, so "applied", "in staging" and the soak move to the first deployment. `GrantSubsetIT` is part of the 353 ITs that pass in the local full `./mvnw verify`.)*
- [ ] Non-regression contract unmodified: `CrossTenantPermissionIT`, `UserRolesAppendOnlyIT`, `UserRolesPrivilegeIT`, `ActiveAssignmentIT`, `TenantAwarePermissionEvaluatorTest`, the four `permission.guard.spec.ts` fail-open tests, and the `LastAdminLockoutIT` outcome scenarios (design §15).

### T-001 — Role assignment requires `user:role:assign`, and assign grants only permissions the caller holds (A1, A2)

**Milestone:** M2

**Description.**
- **(a) V6.** `V6__rbac_user_role_assign_permission.sql` inserts permission `user:role:assign` (id `019f6839-1807-7000-8000-000000000008`, description "Assign and revoke roles for users in the tenant"), then the **first instance of the B7 footer**, pre-V9 template variant (design §4.7, RC-27.1, RC-48.1): statement (a) attaches the inserted ids to every role, system or custom, in any tenant, that carried every permission of the pre-migration catalogue, with the exclusion list bound to exactly this file's inserted ids (`{{INSERTED_PERMISSION_IDS}}` = the one id); statement (b) re-syncs every system `TENANT_ADMIN` with every missing permission. Both `INSERT … SELECT … WHERE NOT EXISTS`, idempotent, order-independent. No grant change, no index.
- **(b) A1 switch.** `UserRoleController` POST and DELETE and `RoleAssignmentService`'s `requiredPermission` move to `user:role:assign` through a local constant (B5 replaces it in M8); GET stays `user:read`; `@ApiResponse` text updated. `user:role:assign` is **not** added to `RbacDangerousPermissions` (design §4.2).
- **(c) M13 and M14 reads.** `UserRoleAssignmentPort` gains `List<RolePermissionRef> findHeldRolePermissionIdsForAuthorization(UUID userId, UUID tenantId)` (M13) and `Set<UUID> findPermissionIdsForRole(UUID roleId)` (M14), with JPQL in `JpaUserRoleRepository` / `JpaRoleRepository` and delegation in `JpaUserRoleAssignmentAdapter` (constructor unchanged). M13 joins `roles` with `r.tenantId = ur.tenantId` (T-S1), is driven off `fk_user_roles_user`, does not join `permissions`, and its Javadoc states it is **the** read for authorization decisions, non-locking, never `@Lock`. New record `RolePermissionRef` (A-1), no custom `toString()`.
- **(d) A2 in `assign()`.** After the throttle and the legacy US-016/017 gate (kept in M2), deny with 403 `RBAC_001`, `DenialReason.GRANT_EXCEEDS_CALLER`, unless M14(target) ⊆ the union of M13's permission ids. One `ROLE_ASSIGNMENT_DENIED` row via `recordDenial` (`REQUIRES_NEW`), metadata `operation`, `reason` and the **count** of missing ids, never the ids (design §4.4). The 403's `requiredPermission` stays `user:role:assign`. An empty target role passes (EC7). A throwing read propagates as 500 and never allows.

**ACs covered:** A1 (FR-A1.a–d), A2 (FR-A2.a, FR-A2.b); B7 first footer instance (B7 closes in T-021). Test scenario TS-1.

**Dependencies:** none (first task of the story).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/common/security/DenialReason.java`
- Tests: `rbac/RbacSchemaMigrationIT.java`, `rbac/application/RoleAssignmentServiceTest.java`, `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java`, `rbac/interfaces/rest/UserRoleControllerTest.java`, `rbac/LastAdminLockoutIT.java` (MC-A block), and fixture churn only in `rbac/RoleAssignmentIT.java`, `rbac/RoleAssignmentAuditIT.java`, `rbac/RoleAssignmentCacheIT.java`, `rbac/security/RoleAssignmentSecurityIT.java`, `rbac/RoleRevocationSymmetryIT.java`, `rbac/RoleAssignmentEscalationIT.java`, `rbac/AdminEquivalentLockoutIT.java` (all under `nexus-backend/src/test/java/com/example/nexus/`)

**Files created:**
- `nexus-backend/src/main/resources/db/migration/V6__rbac_user_role_assign_permission.sql`
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RolePermissionRef.java` + `…/test/…/rbac/domain/RolePermissionRefTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/GrantSubsetIT.java`

**Complexity:** L

**Risks:**
- **Authorization.** Mockito's unstubbed M13 returns empty, which now means **deny**. Every success-path test with a permissioned target needs stubs; never "fix" this by defaulting to allow (design §4.3).
- **Authorization.** Reusing M12 or reading the JWT `permissions[]` for A2 re-opens the decision to a non-authoritative input (FR-A2.b). MC-2 guards it.
- **Locking/concurrency.** M13 is a snapshot read inside the write transaction, deliberately not locking (RES-27, Low). Any `FOR SHARE`/`FOR UPDATE` touching `permissions` passes Testcontainers and fails in production (`nexus_app` has `SELECT` only there). MC-A extended.
- **Footer correctness.** Copying a footer without binding the exclusion list silently attaches nothing (T-T21); the second-tenant and one-short-role IT cases are the guard.
- **Rolling deploy.** Old instances gate on `user:write` for minutes (T-E42 ✅, flag off in production). V6 leaves `TENANT_ADMIN` holders without the new permission in cache for up to 900 s until the runbook flush.
- **Fixture churn.** No assertion in the eight churned ITs may be weakened; only the seeded permission changes.

**Tests (written first):**
- Unit `RoleAssignmentServiceTest`: (1) target role carries a permission the caller lacks → 403 `GRANT_EXCEEDS_CALLER`, no `user_roles` save; (2) target ⊆ caller union → 201; (3) zero-permission target → 201 (EC7); (4) M13 throws → exception propagates, no save; (5) denial metadata has `missingCount=2` and no id values; (6) 403 `requiredPermission` is `user:role:assign`; (7) `InOrder`: throttle check before M13/M14 (EC8); (8) legacy gate still fires first and every existing `NOT_TENANT_ADMIN` assertion is unchanged.
- Unit `UserRoleControllerTest`: POST and DELETE annotated `user:role:assign`, GET `user:read`.
- **MC-2:** an ArchUnit (or reflective unit) assertion that no method of `RoleAssignmentService` or `RoleManagementService` on a decision path calls `findPermissionNamesForActiveAssignmentsOfUser` (M12).
- **MC-A extended:** M13 and M14 repository methods carry no `@Lock` (same technique as `LastAdminLockoutIT` `:837`, `:873`, `:1010`).
- Unit `JpaUserRoleAssignmentAdapterTest`: M13/M14 delegation.
- IT `RbacSchemaMigrationIT`: counts 8→9 (`:182-190`) and 7→8 (`:193-206`); T-E6 generalized to "every system `TENANT_ADMIN` holds every permission" by seeding a second tenant's `TENANT_ADMIN` and re-executing the footer SQL; a custom role carrying the whole pre-migration catalogue **gains** `user:role:assign`; a custom role with `user:write` one permission short **gains nothing**; a second footer run changes nothing (idempotent).
- IT `GrantSubsetIT`: TS-1 (caller with `user:role:assign` but not `role:write` assigns a role carrying `role:write` → 403 + one denial row); EC7 empty role → 201; cross-tenant M13 rows ignored (foreign-tenant role with a matching user row does not widen the union).

**Definition of Done:**
- V6 present; all M2 test cases above green under `./mvnw verify -DskipITs`; the ITs above written and compiling.
- POST/DELETE gated by `user:role:assign`; `user:write` alone no longer assigns (FR-A1.b).
- M13/M14 non-locking, id-based, tenant-cross-checked; no permission names cross the port.
- No new feature flag. One commit.

### T-002 — A non-administrator cannot assign a role to themselves, and assign denials follow one precedence (A4)

**Milestone:** M2

**Description.**
- **(a) `rbac.domain.RbacAdministrators`.** `static boolean isAdminDefining(Set<UUID> rolePermissionIds, Set<UUID> catalogueIds)` = `!catalogueIds.isEmpty() && rolePermissionIds.containsAll(catalogueIds)`; per role, never the union; no custom `toString()`; under the `rbac.domain` 0.90 JaCoCo gate (design §2.1).
- **(b) M15.** `Set<UUID> findCatalogueIds()` on `UserRoleAssignmentPort` (JPQL over `Permission` in `JpaRoleRepository`), read **only** on the self-target branch.
- **(c) A4.** If `targetUserId == actor.userId()` and no role in M13's **per-role** partition is admin-defining, deny 403 `RBAC_001`, `DenialReason.SELF_ASSIGNMENT`, with one `ROLE_ASSIGNMENT_DENIED` row (TS-3). Union and per-role sets come from the one M13 read.
- **(d) Precedence (Decision 6).** Tenant 404 checks → throttle → legacy gate → A4 → A2 → duplicate 409. Exactly one audit row per request, carrying the first reason. Each new reason adds one bounded series to `nexus.rbac.permission_denied{permission, reason}`.
- **(e) EC2 resolved structurally.** No bootstrap exemption flag in `assign()`; A7 never calls it (T-007's ArchUnit rule enforces the other half).

**ACs covered:** A4 (FR-A4.a, FR-A4.b; FR-A4.c precedence resolved). Test scenarios TS-3, TS-4.

**Dependencies:** T-001.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/common/security/DenialReason.java`
- Tests: `rbac/application/RoleAssignmentServiceTest.java`, `rbac/GrantSubsetIT.java` (from T-001), `rbac/LastAdminLockoutIT.java` (MC-A block)

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RbacAdministrators.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/domain/RbacAdministratorsTest.java`

**Complexity:** M

**Risks:**
- **Authorization.** Computing "administrator" over the union instead of per role lets a two-partial-roles caller self-assign; per role fails closed (design §2.1, T-E34's lesson).
- **Authorization.** An empty catalogue must be `false`, or every caller is an administrator when `permissions` is unreadable. MC-1 pins it.
- **Audit.** Writing two rows when A4 and A2 both fire breaks the "one row, first reason" contract US-014's alert tuning expects.
- **Residual.** A4 closes only the literal self path of RES-1(b); the second-account path is RES-26 (T-E32). The task must not describe RES-1(b) as closed anywhere in code comments.

**Tests (written first):**
- **MC-1** `RbacAdministratorsTest`: empty catalogue → false; role set ⊇ catalogue → true; equal → true; one short → false; empty role set with non-empty catalogue → false.
- Unit precedence matrix in `RoleAssignmentServiceTest`: each gate alone (throttle, legacy, A4, A2, duplicate) produces its own outcome; each ordered pair (throttle+A4, legacy+A4, A4+A2, A2+duplicate, legacy+A2, throttle+A2) produces the earlier reason with **exactly one** `recordDenial` call; M15 never read on a non-self target (`verify(port, never()).findCatalogueIds()`); an administrator self-assigns successfully; a union-holder (catalogue split across two roles) is denied `SELF_ASSIGNMENT`.
- MC-A extended: M15 carries no `@Lock`.
- IT `GrantSubsetIT`: TS-3 (non-admin self-assign → 403 + exactly one `ROLE_ASSIGNMENT_DENIED` row with `reason=SELF_ASSIGNMENT`); TS-4 (the RES-1(b) sequence is blocked at the self-assign step, so the later attach has nothing to escalate); an administrator self-assigning succeeds.

**Definition of Done:**
- A4 and the precedence order implemented as above; one denial row per request; `rbac.domain` JaCoCo ≥ 0.90.
- `./mvnw verify -DskipITs` green; ITs written. No new flag. One commit.

### T-003 — Attaching a permission requires the caller to hold it (A3)

**Milestone:** M2

**Description.**
- In `RoleManagementService.attachPermission`, after `requireMutableRole` (409), `findPermission` (404) and the legacy AC11 name gate (still present in M2), require `permissionId` ∈ the caller's M13 union; deny 403 `RBAC_001` with `requiredPermission = role:write`. A3 runs **before** the duplicate check (409 `RBAC_005`), so a denied caller learns nothing about attachment state. It applies to **every** permission, which closes the non-dangerous attach gap (impact §0).
- Observability (Decision 7): WARN `RBAC_ATTACH_EXCEEDS_CALLER {tenantId, actorUserId, roleId, permissionId}` and `nexus.rbac.permission_denied{permission="role:write", reason="GRANT_EXCEEDS_CALLER"}`. **No `auth_events` row**, matching the shipped attach gate.
- Uses the existing `UserRoleAssignmentPort` collaborator (verify at `RoleManagementService.java:75-86`); M13 from T-001.

**ACs covered:** A3 (FR-A3.a). Test scenario TS-2. Closes the attach half of US-017 RES-13 (the detach half closes with role-subset in T-017).

**Dependencies:** T-001.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- Tests: `rbac/application/RoleManagementServiceTest.java`, `rbac/RoleManagementAdminGateIT.java`, `rbac/RoleManagementIT.java`, `rbac/GrantSubsetIT.java`

**Files created:** none.

**Complexity:** M (≈ 150–200 production lines; kept separate from T-001 because it is a different service, a different endpoint and a different denial posture: WARN only, no audit row).

**Risks:**
- **Authorization.** Placing A3 after the duplicate check turns the 409 into an attachment-state oracle for callers who lack the permission.
- **Authorization.** Mockito default-empty M13 now denies every attach; success-path tests need stubs.
- **Audit posture.** Adding an `auth_events` row here would change `ROLE_ASSIGNMENT_DENIED`'s contracted scope (`RbacAuditPort.java:31-50`).

**Tests (written first):**
- Unit `RoleManagementServiceTest`: non-dangerous permission not held → 403, no `role_permissions` write; held → 201; already attached **and** not held → 403 (not 409); unknown permission → 404 before A3; system role → 409 before A3; M13 throws → propagates; WARN carries the four fields; the metric series increments; `RbacAuditPort` never called on the denial.
- IT `RoleManagementAdminGateIT` / `RoleManagementIT`: a `role:write` holder without `audit:read` attaching `audit:read` → 403.
- IT `GrantSubsetIT`: TS-2.

**Definition of Done:**
- A3 on every permission, ordered as above; WARN + metric, no audit row.
- `./mvnw verify -DskipITs` green; ITs written. No new flag. One commit.

---

# M1 — A8 deny-by-default (PR 2)

**PR boundary.** T-004 alone, on `feature/US-018/M1`. Build-time controls only: no DB, API, UI or flag change. Must merge before M9 so C1/C3 handlers are classified from their first commit (design §3.3), and before M7 because T-009 consumes `PublicEndpointRequestMatcher`.

**Threats owned:** T-E39 (RC-40.2), T-E45 (RC-44.1, RC-44.3; the filter half is T-009), RC-24.1 (one source for "public").

**Merge checklist (M1):**
- [ ] Exit criterion: the three ArchUnit rules and `EndpointClassificationWebTest` green; each rule's negative fixture proves it fires (design §3.4, §14).
- [ ] `GuardedTestController` unaffected (outside `DoNotIncludeTests` scope, impact §1).

### T-004 — Every REST handler is classified as permission-guarded, authenticated-only or public, enforced at build time and at runtime (A8)

**Milestone:** M1

**Description.**
- **(a) Markers** in `common.security`: `@PublicEndpoint` and `@AuthenticatedEndpoint` (method-level, runtime retention, marker only, no AOP). Annotate the nine identity handlers `@PublicEndpoint` (login, refresh, logout, register ×3, password ×2, JWKS) and `UserProfileController.me()` `@AuthenticatedEndpoint` (Decision 1).
- **(b) Three ArchUnit rules** in `HexagonalArchitectureTest` (existing rules `:153-172` unchanged): `rest_handlers_must_carry_exactly_one_access_marker`; `no_self_invocation_of_requires_permission_methods`; `authenticated_endpoints_take_no_uuid_identifier` (no `@PathVariable` / `@RequestParam` of type `UUID` on an `@AuthenticatedEndpoint` handler; RC-40.2).
- **(c) `PublicEndpointRequestMatcher`** (`identity.infrastructure.web`), built once from `RequestMappingHandlerMapping.getHandlerMethods()` over `@PublicEndpoint` handlers. Matches **HTTP method and pattern together**, after `ServletRequestPathUtils.parseAndCache`; **any exception or ambiguity returns false** (non-public, fail closed; RC-44.1). Signature: `public boolean matches(HttpServletRequest request)`. Not yet wired into the filter (T-009 does that).
- **(d) `EndpointClassificationWebTest`** (MockMvc, full security chain, **every feature flag enabled**): for each handler, fill path variables with random UUIDs and send an anonymous request; `@PublicEndpoint` handlers must not return the **entry-point** 401, every other handler must return it, asserted on the `AUTH_003` body from `jwtAuthenticationEntryPoint`, not the status alone (RC-40.2). Matcher equivalence: for every `(method, pattern)`, `matches()` is true exactly when the handler is `@PublicEndpoint`, plus a test-only negative fixture with a public handler's path and a **different method** (RC-44.3).

**ACs covered:** A8 (FR-A8.a, FR-A8.b, FR-A8.c). Test scenario TS-7.

**Dependencies:** none (independent of M2; ordered after it by delivery plan).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/LoginController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/RegistrationController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/PasswordResetController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/JwksController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/UserProfileController.java`
- `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/common/security/PublicEndpoint.java`
- `nexus-backend/src/main/java/com/example/nexus/common/security/AuthenticatedEndpoint.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/PublicEndpointRequestMatcher.java` + `…/test/…/identity/infrastructure/web/PublicEndpointRequestMatcherTest.java`
- `nexus-backend/src/test/java/com/example/nexus/config/EndpointClassificationWebTest.java`
- Negative fixtures in a test-only package, e.g. `nexus-backend/src/test/java/com/example/nexus/architecture/fixtures/` (an unmarked handler, a self-invoking `@RequiresPermission` class, an `@AuthenticatedEndpoint` taking a `UUID`, a same-path different-method handler)

**Complexity:** M (≈ 200–250 production lines; one task because the static and runtime halves enforce one rule and share the matcher).

**Risks:**
- **Authorization.** A matcher that matches on path only, or treats an exception as "public", becomes a silent A9 bypass once T-009 wires it (T-E45). Unit tests must cover method mismatch and a thrown parse exception.
- **Authorization.** Asserting the 401 status instead of the entry-point body invites an exclusion list for refresh's own `AUTH_004` 401.
- Flag-gated RBAC controllers must be enabled in the web test, or they are silently skipped.
- `me()` must not be labelled `@PublicEndpoint`; reviewers read "public" as anonymous.

**Tests (written first):**
- ArchUnit: each new rule passes on production classes and **fails** on its negative fixture (three fixture assertions).
- `PublicEndpointRequestMatcherTest`: login, refresh and logout POSTs match; `GET /api/v1/auth/refresh` (same pattern, other method) does not; a request whose path parsing throws returns false; an unknown path returns false.
- `EndpointClassificationWebTest`: anonymous sweep over every handler with all flags on; the matcher-equivalence sweep including the different-method fixture.

**Definition of Done:**
- All handlers carry exactly one marker; three rules and the web test green under `./mvnw verify -DskipITs`.
- No DB/API/UI/flag change. One commit.

---

# M6 — A11 token claim validation (PR 3)

**PR boundary.** T-005 alone, on `feature/US-018/M6`. Must be **deployed on every instance** before M7's rolling deploy starts (design §1.2).

**Threats owned:** T-S10 (RC-40.1), T-E40 (the "accept v3 before it exists" part ✅).

**Merge checklist (M6):**
- [ ] Deviation from the literal AC ("≠ `CURRENT_VERSION`" → "∉ `ACCEPTED_VERSIONS`") recorded as approved at Gate 2 (design §8, Decision 18).
- [ ] v3 frozen at merge as v2 ∪ {`perm_epoch`}; any other claim change is v4 (ADR-0022 D7).
- [ ] Exit criterion: `nexus.auth.token_rejected{reason}` baseline recorded after deploy (design §14).

### T-005 — Tokens with an unsupported version, a missing or non-UUID `tenant_id` or `sub`, or a malformed v3 epoch are rejected with 401, never 500 (A11)

**Milestone:** M6

**Description.**
- `JwtRs256Service.verify()` throws `AUTH_003` (401) when: `schema_version ∉ JwtClaims.ACCEPTED_VERSIONS` (`Set.of(2, 3)`; `CURRENT_VERSION` stays 2); `tenant_id` is absent or not a UUID; `sub` is not a UUID (RC-40.1); `schema_version = 3` and `perm_epoch` is absent or not a non-negative long (value otherwise ignored in M6).
- This removes the `Map.of` NPE path in `JwtAuthenticationFilter` (`:80-84`) at its source; no filter change.
- Observability: `nexus.auth.token_rejected{reason ∈ signature, expired, claims_missing, schema_version, tenant_id, sub, perm_epoch}`; rejections log at DEBUG.

**ACs covered:** A11 (FR-A11.a, FR-A11.b). Test scenario TS-10.

**Dependencies:** none.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java` (additive `ACCEPTED_VERSIONS` constant; no field, no version bump)
- Tests: `identity/infrastructure/security/JwtRs256ServiceTest.java`, `identity/infrastructure/security/JwtRs256ServiceSecurityTest.java`, `identity/infrastructure/web/JwtAuthenticationFilterTest.java`, `identity/domain/JwtClaimsTest.java`

**Files created:** none.

**Complexity:** S (≈ 80–120 production lines; a whole PR on its own by the Gate 1 split, so it cannot merge with another task).

**Risks:**
- **Authentication / cryptography.** Strict equality on `CURRENT_VERSION` would make M7's rolling deploy ping-pong sessions into logouts (impact §14.1); the accepted-set shape is the point. The RS256 algorithm assertion (`JwtRs256Service.java:117-120`) must stay untouched.
- **Authentication.** Accepting v3 without validating its shape lets an M6 instance accept a future v3 variant (T-S10).
- Logging rejections above DEBUG floods logs during M7's rollout.

**Tests (written first):**
- `JwtRs256ServiceTest` / `JwtRs256ServiceSecurityTest`: versions 1 and 4 rejected; 2 and 3 accepted; missing `tenant_id`; non-UUID `tenant_id`; non-UUID `sub`; v3 with missing `perm_epoch`; v3 with negative `perm_epoch`; each asserts the `reason` tag.
- `JwtAuthenticationFilterTest`: a token missing `tenant_id` returns **401 and never 500** (TS-10).

**Definition of Done:**
- All rejections map to 401 `AUTH_003`; `./mvnw verify -DskipITs` green. No new flag. One commit.

---

# M4 — A6 atomic audit (PR 4)

**PR boundary.** T-006 alone, on `feature/US-018/M4`, rebased on merged M2 (same methods).

**Threats owned:** T-D22 (RC-40.5).

**Merge checklist (M4):**
- [ ] Availability coupling accepted (RES-36, ADR-0024): an `auth_events` outage blocks RBAC writes, including break-glass.
- [ ] Exit criterion: TS-5 green; `privileged_revoke_lock_hold` re-baselined after deploy (the audit insert now runs inside the set-lock region; design §6.3).

### T-006 — RBAC success events are written in the mutation's transaction, and an audit failure rolls the mutation back (A6)

**Milestone:** M4

**Description.**
- **(a) Port contract.** `RbacAuditPort` keeps one interface with two documented groups (Decision 9): Group A (atomic) `recordRoleAssigned`, `recordRoleRevoked`, `recordRoleCreated`, `recordRolePermissionGranted`, `recordRolePermissionRevoked` join the caller's transaction and **must throw** on failure; Group B `recordRoleAssignmentDenied` keeps `REQUIRES_NEW`, never throws, may buffer (FR-A6.c).
- **(b) Write path.** `SecureEventService.recordEventInCurrentTransaction(AuthEvent)` annotated `@Transactional(propagation = MANDATORY)`, calling a new `AuthEventPort.recordOrThrow(AuthEvent)` that `saveAndFlush`es and bypasses `JpaAuthEventAdapter`'s retry-buffer catch. The flush is required (assigned `@Id`; otherwise the failure surfaces at commit as an unmapped `TransactionSystemException`).
- **(c) Adapter.** `RbacAuthEventAdapter` Group A methods drop the catch-all `RBAC_AUDIT_WRITE_LOST` swallow and propagate, including metadata-serialization failures.
- **(d) Services.** Move the five `record*` calls out of `registerPostCommitSideEffects` and call them inline before return (inside the transaction, after the mutation) in `RoleAssignmentService` (assign, revoke) and `RoleManagementService` (create, attach, detach). Cache eviction, INFO logs and timers stay after commit.
- **(e) Failure semantics** (design §6.2): the exception propagates, the transaction rolls back, the response is 500 `INTERNAL_ERROR`; ERROR `RBAC_AUDIT_WRITE_FAILED {operation, tenantId, actorUserId}` and `nexus.rbac.audit_write_failed{operation, mode="atomic"}` (Group B failures use `mode="best_effort"`).

**ACs covered:** A6 (FR-A6.a, FR-A6.b, FR-A6.c). Test scenario TS-5.

**Dependencies:** T-001, T-002, T-003 (M2 merged).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/service/SecureEventService.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/AuthEventPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaAuthEventAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- Tests: `identity/infrastructure/audit/RbacAuthEventAdapterTest.java`, `identity/application/service/SecureEventServiceTest.java`, `identity/infrastructure/persistence/JpaAuthEventAdapterTest.java`, `rbac/application/RoleAssignmentServiceTest.java`, `rbac/application/RoleManagementServiceTest.java`, `rbac/RoleAssignmentAuditIT.java`, `rbac/RoleManagementAuditIT.java`

**Files created:** none.

**Complexity:** L (≈ 300–400 production lines across two contexts; kept as one task because the contract change and its five call sites must flip together or a commit ships a half-atomic audit).

**Risks:**
- **Locking/concurrency.** A Group B `REQUIRES_NEW` insert after a Group A insert in the same transaction can wait on its own outer transaction's audit-row locks (T-D22); MC-4's ordering rule prevents it.
- **Locking/concurrency.** The audit insert now runs inside the M11 X-lock region, lengthening lock hold (re-baseline is a checklist item, not a code change).
- **Transactions.** Without `saveAndFlush` the failure path is untestable and maps to the wrong error.
- **Audit integrity.** Leaving the retry buffer on the atomic path makes a "successful" audit non-atomic by definition (ADR-0011 scope note). The `auth_events` append-only triggers must not be touched.

**Tests (written first):**
- `RbacAuthEventAdapterTest`: Group A methods propagate a repository exception and a serialization exception (previously swallowed); Group B still swallows.
- **MC-4** unit: `recordEventInCurrentTransaction` is annotated `MANDATORY`; **extended (RC-40.5):** Mockito `InOrder` over each service method that can emit both groups proves no Group B call follows a Group A call.
- `SecureEventServiceTest` / `JpaAuthEventAdapterTest`: `recordOrThrow` flushes and does not enqueue to the retry buffer.
- Service unit tests that asserted post-commit audit ordering flip to "audit inside the transaction, before return"; eviction and timers remain post-commit.
- IT `RoleAssignmentAuditIT` and `RoleManagementAuditIT` (**TS-5**): a test-only `BEFORE INSERT` trigger on `auth_events` that signals only for RBAC success event types (installed and dropped by the test) makes assign / revoke / create / attach / detach return 500 with **no** `user_roles` / `roles` / `role_permissions` change; an IT that `recordEventInCurrentTransaction` fails outside a transaction (MC-4 IT half).

**Definition of Done:**
- Five success events atomic; denial path unchanged; 500 `INTERNAL_ERROR` on audit failure with the ERROR marker and metric.
- `./mvnw verify -DskipITs` green; ITs written. No migration, no grant change, no flag. One commit.

---

# M5 — A7 break-glass CLI (PR 5)

**PR boundary.** T-007 → T-008, on `feature/US-018/M5`. Needs V6 (M2: the new administrator must hold `user:role:assign`) and M4's atomic-audit path. Artifact-only deploy: the CLI is never run during a deploy.

**Threats owned:** T-S9 (RC-37.1, RC-37.2), T-R14 (RC-37.3), T-R15 (RC-37.4), T-S11 (RC-47), RC-37.5, RC-37.6 / RC-50(d), RC-54(a), L-6; EC2 (structural, with T-002).

**Merge checklist (M5):**
- [ ] **RC-37.3:** Ops sign-off that Kubernetes API audit logging (pod create and exec, with user identity) is on and retained ≥ 1 year. Without it `--change-ref` joins to nothing.
- [ ] **RC-37.4 staging drill:** a zero-admin tenant recovered, **and the page received from a Job run exactly as the runbook specifies**. The runbook forbids `--rm` unless the drill proves capture without it.
- [ ] **Daily reconciliation alert** (ticket) on new `ROLE_BREAK_GLASS_GRANT` rows is live (backstop for a lost page).
- [ ] **RES-6:** Ops retention sign-off for `RBAC_BREAK_GLASS_USED`.
- [ ] Runbook content (docs pass): requester verified against the tenant's **contractual contact of record**, never the target account; a **second Platform Security approver** recorded under the change reference; **one invocation at a time per reference**; `docs/features/US-012/runbook.md` step 4 (manual `INSERT`) replaced by the CLI procedure, so FR-A7.d holds.
- [ ] RC-47 padded-replay case and RC-54(a) covered by `BreakGlassAdminIT` (TM §11.8, §12.7).
- [ ] Zero-admin recovery demonstrated in an operational drill (requirements §13 success metric).

### T-007 — An operator can grant the first administrator of a zero-admin tenant, under the set lock, atomically audited, with every refusal audited and paged (A7 core)

**Milestone:** M5

**Description.**
- **(a) `BootstrapAdminService.grantFirstAdmin(targetUserId, changeRef)`** (`rbac.application`), never calling `RoleAssignmentService.assign()` (EC2). Order (design §7.1): resolve target user's tenant and status (missing or not `ACTIVE` → refuse, exit 3); resolve the tenant's system `TENANT_ADMIN` (`is_system_role`; absent → refuse `NO_SYSTEM_ADMIN_ROLE`, exit 4); prime M10, take the M11 set lock over the admin-defining ids plus `TENANT_ADMIN` (same single-statement ascending order as assign/revoke); if the tenant has ≥ 1 administrator under the lock → refuse `TENANT_HAS_ADMIN`, exit 5; else insert `user_roles` with `assigned_by = target` (Decision 10) and write `ROLE_BREAK_GLASS_GRANT` SUCCESS in the same transaction (M4 pattern), metadata `{actorType: BREAK_GLASS_CLI, changeRef}`; alert after commit; exit 0.
- **(b) Refusals** write `ROLE_BREAK_GLASS_GRANT` FAILURE with `reason` in their own transaction (Group B semantics) and alert. Before M3 the zero-admin precondition uses the shipped ADR-0018 caller-qualifying population (A-6).
- **(c) Alert.** `rbac.application.port.out.BreakGlassAlertPort`, implemented in `identity.infrastructure` by wrapping `AuditAlertPort` / `LoggingAuditAlertAdapter`: ERROR `RBAC_BREAK_GLASS_USED {tenantId, targetUserId, outcome, reason, changeRef}` on every invocation (log-based page; no metric, the process is never scraped).
- **(d) Audit type.** New `AuthEventType.ROLE_BREAK_GLASS_GRANT` (not `PRIORITY`).
- **(e) Containment.** ArchUnit: `BootstrapAdminService` may be called only from `rbac.interfaces.cli`.
- The service returns an outcome value carrying the exit code; T-008's runner maps it to `SpringApplication.exit`.

**ACs covered:** A7 (FR-A7.a, FR-A7.b, FR-A7.c; FR-A7.e resolved as CLI). Test scenario TS-6. EC2.

**Dependencies:** T-002 (V6, A4/EC2), T-006 (atomic audit).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java` (system-role lookup by name, if not already present)
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserDirectoryPort.java` (target status lookup, if not already present)
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- Tests: `identity/infrastructure/audit/RbacAuthEventAdapterTest.java`, `identity/domain/AuthEventTest.java`

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java` + `…/test/…/rbac/application/BootstrapAdminServiceTest.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/BreakGlassAlertPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/BreakGlassAlertAdapter.java` + test
- `nexus-backend/src/test/java/com/example/nexus/rbac/BreakGlassAdminIT.java`

**Complexity:** L

**Risks:**
- **Authorization.** Break-glass must never become a general admin-granting path: the zero-admin check must run **under** the set lock, and the ArchUnit rule must keep REST away from the service.
- **Locking/concurrency.** Taking any lock outside the shared single-statement ascending set lock re-opens the deadlock hazard ADR-0018 D6 closed; reuse M10/M11 exactly.
- **Audit.** A refusal written in the grant's transaction would vanish on rollback; refusals use their own transaction.
- **PII.** `changeRef` is the only operator attribution; no operator identity enters tenant data.

**Tests (written first):**
- Unit `BootstrapAdminServiceTest`: each refusal (missing user, non-ACTIVE, no system role, has admin) writes one FAILURE row with the right reason, alerts, and returns its exit code; the grant path inserts with `assigned_by = target`, writes SUCCESS inside the transaction and alerts after commit; `InOrder`: lock before precondition before insert.
- ArchUnit: a test-only fixture calling `BootstrapAdminService` from `rbac.interfaces.rest` fails the containment rule.
- IT `BreakGlassAdminIT`: grant on a zero-admin tenant (row, audit row, alert log line); refusal when an administrator exists; refusal with no seeded role; refusal for a non-ACTIVE user; a revoke of the last admin racing the CLI serializes on the lock and exactly one outcome holds; re-run after success refuses with exit 5 (idempotency).

**Definition of Done:**
- Service, ports, adapter, audit type and containment rule in place; `./mvnw verify -DskipITs` green; ITs written.
- No migration, no grant change (runs as `nexus_app`), no new dependency, no flag. One commit.

### T-008 — The break-glass runner validates its arguments, refuses replayed or malformed change references, and refuses to start in a serving context (A7 runner)

**Milestone:** M5

**Description.**
- **(a) Runner.** `BreakGlassAdminRunner` (`rbac.interfaces.cli`), an `ApplicationRunner` annotated `@Profile("break-glass")`; new `application-break-glass.yml` sets `spring.main.web-application-type=none` and `spring.flyway.enabled=false`. Exits through `SpringApplication.exit` with codes 0, 2, 3, 4, 5, 6. Waits one configured log-shipper flush interval (default 15 s) before exiting (RC-37.4). No picocli or spring-shell.
- **(b) Web-context guard** (RC-37.6, RC-50(d)): a bean-initialization check reads the effective `spring.main.web-application-type`; unless `none`, it logs ERROR `RBAC_BREAK_GLASS_USED {reason=WEB_CONTEXT}` and throws, failing the context refresh before the embedded server starts.
- **(c) Argument validation** (RC-54(a)): `--target-user-id` must be a UUID; `--change-ref` must match `^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$` (RC-47). On failure: **exit 2**, `BootstrapAdminService`'s refusal path writes one `ROLE_BREAK_GLASS_GRANT` FAILURE row with reason `INVALID_ARGUMENT`, **null `tenant_id`**, metadata `{actorType: BREAK_GLASS_CLI, reason: INVALID_ARGUMENT}` only, and emits the paging ERROR with `targetUserId` and `changeRef` **omitted**. The runner passes **no raw argument** to `BreakGlassAlertPort` (L-6).
- **(d) Replay refusal** (RC-37.2, RC-47): `rbac.application.port.out.BreakGlassGrantLookupPort.existsSuccessfulGrantWithChangeRef(String changeRef)`, implemented in `identity.infrastructure`: one non-locking, **global** (not tenant-scoped) `auth_events` read filtered on `event_type = 'ROLE_BREAK_GLASS_GRANT' AND outcome = 'SUCCESS'` (uses `idx_auth_events_event_type_created_at`), comparing the **unquoted** `metadata.changeRef` with a **bound parameter**. A hit → refuse `CHANGE_REF_REUSED`, exit 6, audited and paged. Runs before the user lookup.
- **(e) Containment.** ArchUnit: every bean in `rbac.interfaces.cli` is `@Profile("break-glass")`. A test asserts `DevDataInitializer`'s profile gating does not overlap `break-glass`.

**ACs covered:** A7 (FR-A7.c, FR-A7.d — no manual SQL remains once the runbook points at this runner). Test scenario TS-6 (runner half).

**Dependencies:** T-007.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java` (from T-007: invalid-argument and reuse refusal paths)
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaAuthEventRepository.java` (lookup query)
- `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/seed/DevDataInitializerTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/BreakGlassAdminIT.java` (from T-007)

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/cli/BreakGlassAdminRunner.java` + `…/test/…/rbac/interfaces/cli/BreakGlassAdminRunnerTest.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/BreakGlassGrantLookupPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/BreakGlassGrantLookupAdapter.java` + test
- `nexus-backend/src/main/resources/application-break-glass.yml`

**Complexity:** M

**Risks:**
- **Authorization.** A tenant-scoped or string-concatenated lookup lets an old approval be replayed or injected; the lookup must be global and parameter-bound (T-S11).
- **Authorization.** Allowing leading zeros makes `ABC-1` / `ABC-01` distinct strings for one ticket.
- **PII / log injection.** Echoing a rejected argument lets free text reach audit metadata and logs through the refusal path; the IT must prove absence in both.
- **Availability of the page.** Exiting before the shipper reads the pod's logs loses the page (T-R15); the flush wait and the drill are the controls.
- **Concurrency (accepted, T-S11).** Two concurrent runs with one reference can both pass the non-locking lookup; the set lock limits that to two different zero-admin tenants. Runbook-only control.

**Tests (written first):**
- Unit `BreakGlassAdminRunnerTest`: exit-code mapping for every outcome; non-UUID target → 2; `ABC-0`, `ABC-01`, lowercase and free text (`"fix tenant"`) → 2; no raw argument reaches the alert port (argument captor).
- Unit: the web-type guard throws for `servlet` and passes for `none`.
- IT `BreakGlassAdminIT` (extends T-007): exact-string replay of a used reference → exit 6, audited and paged; a reference used on a SUCCESS grant **in another tenant** → exit 6; `ABC-0001` after `ABC-1` → exit 2, no grant row, exactly one FAILURE row with `INVALID_ARGUMENT` and null `tenant_id`, and `ABC-0001` appears **neither** in that row's metadata **nor** in the captured log output; the runner under `spring.main.web-application-type=servlet` fails the context refresh.
- `DevDataInitializerTest`: profiles do not overlap.

**Definition of Done:**
- Runner, guard, validation, lookup and containment rules in place; `./mvnw verify -DskipITs` green; ITs written.
- **L-6:** `03-design.md` §7.2 *Alert* field list and *Audit* metadata list gain "(omitted on `INVALID_ARGUMENT`, §7.1)" (doc line, landed in this PR).
- No new dependency, no flag. One commit.

---

# M7 — A9 revocation epoch, A10 holder fan-out (PR 6)

**PR boundary.** T-009 → T-014 in one PR on `feature/US-018/M7`. **Hard prerequisite:** M6 (T-005) deployed on every instance. Uses `PublicEndpointRequestMatcher` from M1 (T-004). This is the first Redis call on the authenticated hot path (design §2.4).

**Threats owned:** T-D17 (RC-24), T-E37 (RC-29), T-E38 (RC-30), T-D20 (RC-31), T-D19 (RC-32), T-T16 (RC-34.1), T-D23 ✅, T-E40 (RC-40.6), T-E43 (RC-41), T-E44 (RC-42), T-D24 (RC-43), T-E45 (RC-44.2, RC-44.4), RC-45, T-E46 (RC-51), RC-52, T-E47 (RC-53), L-1, L-2, L-3, L-4.

**Merge checklist (M7):**
- [ ] **RES-30:** SRE and PM confirm the story owner's Gate 2 acceptance (a Redis outage longer than the window is a platform-wide authenticated 503) at this merge (TM §13.8).
- [ ] M6 is on every instance before the M7 rollout starts.
- [ ] **RC-34.1 production prerequisites** in place: Redis authentication (ACL user limited to `nexus:*`, or at least `requirepass`), network isolation, TLS wherever Redis is not on a private network. Ops confirms production activates the `prod` profile, so `require-auth=true` (T-014) is live (A-3).
- [ ] **Hot-path budget (merge-blocking):** k6 epoch-check run (T-009) shows ≤ 2 ms p95 for the epoch check at 200 RPS on a guarded endpoint in the staging topology, and the endpoint's RBAC overhead stays within EPIC-002's < 5 ms p95.
- [ ] **NAT refresh gate (merge-blocking, RC-32.3, RC-43.3, RC-51):** k6 run (T-013) in the **production ingress topology**: detach on a 200-holder role behind one IP gives zero forced logouts, including with an attacker behind the NAT sending invalid refreshes at 100/min and replaying rotated refresh tokens, with no reuse-detection revocation suppressed. Result recorded for both deployment shapes (direct client IP; behind the proxy). A failed proxied result blocks merge until DF-1 is resolved.
- [ ] RC-24's four `TokenFreshnessIT` cases, the RC-41 to RC-45 tests and the RC-51 tests are green (TM §10, §11.8, §12.7).
- [ ] Runbook and alert content (docs pass): **rollback to M6 pages Platform Security** (RC-40.6); incident-response step "check `RBAC_EPOCH_BUMP_FAILED` / `bump_failed{reason=overflow}` for the user's tenant before declaring access cut" (RC-30.3); Redis capacity (memory headroom under `noeviction`, latency, connection saturation; RC-31.5); window extension through config plus rolling restart (resets every instance's window); the §9.9 alert table (page: `skipped_error` > 1% for 5 min, `open` > 0 for 1 min, `closed` > 0, flap, any `bump_failed`; ticket: `recovering` > 10 min, p95 > 2 ms for 15 min, p99 > 25 ms for 5 min, `stale` > 5× baseline).
- [ ] Post-deploy: 1 h watch of `token_rejected{reason=schema_version}` (expected 0) and `epoch.check{outcome=stale}`.

### T-009 — Access tokens carry a per-user permission epoch, a revoked user's old token gets 401 on its next request, and public auth endpoints are never rejected (A9 core)

**Milestone:** M7

**Description.**
- **(a) Store.** `rbac.application.port.out.PermissionEpochPort` (`OptionalLong current(UUID tenantId, UUID userId)`, `void bump(UUID tenantId, Collection<UUID> userIds)`; empty = Redis could not answer). `RedisPermissionEpochAdapter` (`rbac.infrastructure.cache`): GET on a dedicated `StringRedisTemplate` over its own `LettuceConnectionFactory` with a **50 ms** command timeout; the bump Lua script (`old = GET`; `new = max(old + 1, redis TIME ms)`; `SET key new EX ttl`) on a **second** dedicated factory with `nexus.rbac.epoch.bump-timeout` (500 ms). Both factories take host, port, database, `password`, ACL `username` and `ssl` from `spring.data.redis.*`; only the timeout differs (RC-45.2). Key `nexus:rbac:epoch:{tenantId}:{userId}`.
- **(b) Key TTL** (RC-29): `key-ttl-seconds = max(access-token TTL, permission-cache TTL) + ≥ 60 s` (960 today); the application **fails to start** if it is ≤ either TTL.
- **(c) Policy.** `PermissionFreshnessService` (`rbac.application`): `long epochForMint(...)` (0 on absent key or failure); `FreshnessVerdict check(tenantId, userId, tokenEpoch)` → `FRESH` / `STALE` (iff `tokenEpoch < current`, absent = 0) / `SKIPPED_ERROR` (a single failed or slow read fails open **for that request only** and is counted); `void invalidateUser(...)` post-commit only. The degraded states are T-011.
- **(d) Token.** `JwtClaims` gains `permEpoch`; `CURRENT_VERSION` 2 → 3; mint v3; accept {2, 3}; a v2 token is treated as epoch 0. `JwtRs256Service.issue()` calls `epochForMint` **before** `RoleResolutionService.resolve(...)` (MC-7a).
- **(e) Filter.** `JwtAuthenticationFilter` gains the freshness collaborator (wired in `SecurityConfig`). On a request `PublicEndpointRequestMatcher` does **not** match: verify, then one `check`; `STALE` → entry point, 401 `AUTH_003`. On a matched (`@PublicEndpoint`) request (RC-24, RC-44.2): **never reject**, no epoch check; a bearer that fails verification is ignored (anonymous, `token_rejected{reason}` at DEBUG); a verified bearer sets the principal with an **empty `PERMISSIONS` detail and no authorities** (logout needs only the user id). This also fixes the pre-existing rejection of a reactive refresh that carries an expired bearer.
- **(f) Trigger.** `RoleAssignmentService.revoke()` calls `invalidateUser(target)` inside `registerPostCommitSideEffects` (after commit only; MC-7b).
- **(g) Observability.** `nexus.rbac.epoch.check{outcome}` counter and `nexus.rbac.epoch.check.latency` timer (p50/p95/p99). Config `nexus.rbac.epoch.{command-timeout, bump-timeout, key-ttl-seconds}` in `application.yml`; the platform's 2 s Redis timeout never applies to the hot path.

**ACs covered:** A9 (FR-A9.a, FR-A9.b, FR-A9.c for revoke, FR-A9.d; FR-A9.e as Gate 1 OQ1). Test scenario TS-8.

**Dependencies:** T-004 (matcher), T-005 (accepted-version set, deployed).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/resources/application.yml`
- Tests: `identity/infrastructure/security/JwtClaimsContractTest.java`, `identity/domain/JwtClaimsTest.java`, `identity/infrastructure/security/JwtRs256ServiceTest.java`, `identity/infrastructure/web/JwtAuthenticationFilterTest.java`, `config/SecurityConfigWebTest.java`, `rbac/application/RoleAssignmentServiceTest.java`, `identity/application/service/RefreshTokenPermissionResolutionIT.java`

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/PermissionEpochPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java` + `…/test/…/rbac/application/PermissionFreshnessServiceTest.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java` + `…/test/…/rbac/infrastructure/cache/RedisPermissionEpochAdapterIT.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java` (the two dedicated factories and the TTL startup assertion)
- `nexus-backend/src/test/java/com/example/nexus/rbac/TokenFreshnessIT.java`
- `nexus-test/performance-test/workloads/constant-arrival-rate.js`, `nexus-test/performance-test/tests/load/epoch-check-latency.js` (reuses `scenarios/rbac-read.js`)

**Complexity:** L

**Risks:**
- **Authentication / authorization (fail-open).** Reading permissions before the epoch at mint produces "new epoch, old permissions", which is accepted (MC-7a). Bumping before commit lets a mint in the gap read the new epoch with pre-commit permissions (MC-7b).
- **Authorization.** A principal on a public request that keeps the token's `permissions[]` turns any matcher misclassification into a silent A9 bypass (T-E45); the empty-`PERMISSIONS` rule is the backstop.
- **Availability.** Rejecting a stale bearer on `/auth/refresh` or `/auth/logout` logs holders out after every revoke and skips the server-side family revocation (T-D17, High).
- **Cryptography.** RS256 signing and the algorithm assertion are unchanged; `perm_epoch` is a monotonic Redis-time counter, not a secret. Do not derive it from app-instance clocks.
- **Hot path.** Any use of the 2 s default template on the request path breaks the ≤ 2 ms p95 budget under a slow Redis (EC6).
- **TTL.** A key TTL equal to the cache TTL fails open at key expiry (T-E37); the startup assertion prevents silent re-opening.

**Tests (written first):**
- `JwtClaimsContractTest` (11 claims, v3), `JwtClaimsTest` (`permEpoch`).
- `JwtRs256ServiceTest`: **MC-7a** `InOrder` (`epochForMint` before `resolve`); v3 minted with the epoch; a v2 token verifies as epoch 0.
- `JwtAuthenticationFilterTest`: stale token on a non-public handler → 401 `AUTH_003`; `SKIPPED_ERROR` → request proceeds; on a public request: stale, expired and bad-signature bearers never rejected; a verified bearer yields a principal with empty `PERMISSIONS` and no authorities.
- `RoleAssignmentServiceTest` **MC-7b**: `invalidateUser` fails the test if called with an active synchronization outside `afterCommit`; revoke registers it after commit.
- Startup assertion: `key-ttl-seconds` ≤ cache TTL fails; ≤ token TTL fails; 960 passes.
- `RedisPermissionEpochAdapterIT`: bump is monotonic across a key deletion (`max(old + 1, TIME)`); TTL set; the read template times out at 50 ms against a paused container.
- `TokenFreshnessIT` (Testcontainers Redis), bearer attached exactly as the SPA does: **TS-8** revoke → old token 401 → refresh returns a token without the permission, measured under 1 s; absent key → FRESH; a v2 token for a recently revoked user → 401; RC-24.3: refresh with a stale-epoch bearer → 200; logout with a stale-epoch bearer revokes the refresh family server-side; refresh with an **expired** bearer → 200; RC-44.4: logout with a stale-epoch bearer and **no cookie** revokes every family of that user; a stale-epoch bearer on a non-public handler → 401 while healthy. (The degraded-closed cases are T-011's.)
- **Hot-path load test (k6, run in `/test-validate` on the staging topology):** `tests/load/epoch-check-latency.js` drives **200 RPS** (constant arrival rate) on a guarded endpoint (`GET /api/v1/roles`); thresholds: server-side `nexus.rbac.epoch.check.latency` **p95 ≤ 2 ms**, and the endpoint's p95 regression against the M6 baseline **< 5 ms** (EPIC-002 RBAC overhead, requirements §5).

**Definition of Done:**
- Epoch claim, check, mint order, public-endpoint rules and revoke trigger in place; `./mvnw verify -DskipITs` green; ITs and the k6 test written and passing `npm run inspect` / `format:check` in `nexus-test/performance-test`.
- No new dependency (Lettuce and Spring scheduling already present), no flag. One commit.

### T-010 — Detaching a permission removes it from every active holder on their next request, including after a refresh (A10)

**Milestone:** M7

**Description.**
- **(a) Fan-out.** `PermissionFreshnessService.invalidateHolders(tenantId, userIds)`, post-commit only. `RoleManagementService.detachPermission` reads holders **after commit** with `findActiveUserIdsForRole` and calls it. Lua batches of **500** users per call, pipelined, **no cap**; WARN `RBAC_EPOCH_FANOUT_LARGE` when holders > 1000; `nexus.rbac.epoch.fanout{holders}` bucketed `0 | 1-10 | 11-100 | 101-1000 | >1000` (no tenant tag).
- **(b) Attach and assign evict but do not bump** (Decision 15, recorded deviation): `RoleManagementService` gains the cache-eviction collaborator it lacks today (`:75-86`); attach evicts every holder's entry.
- **(c) Epoch-keyed cache** (Decision 17): key becomes `nexus:rbac:permset:{tenantId}:{userId}:{epoch}`; `RoleResolutionService.resolve(userId, tenantId, epoch)`; `JwtRs256Service` passes the epoch it read first; the role-name fingerprint (`RoleResolutionService.java:59-62`) is kept. The bump script gains `DEL nexus:rbac:permset:{tenantId}:{userId}:{old or 0}`.

**ACs covered:** A10 (FR-A10.a), A9 (FR-A9.c for detach; the attach deviation is recorded). Test scenario TS-9.

**Dependencies:** T-009.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/PermissionCachePort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java`, `…/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java` (from T-009)
- Tests: `rbac/application/RoleManagementServiceTest.java`, `rbac/application/RoleResolutionServiceTest.java`, `rbac/application/RoleResolutionServiceIT.java`, `rbac/infrastructure/cache/RedisPermissionCacheAdapterTest.java`, `rbac/infrastructure/cache/RedisPermissionCacheAdapterIT.java`, `rbac/RoleAssignmentCacheIT.java`, `identity/application/service/RefreshTokenPermissionResolutionIT.java`, `rbac/TokenFreshnessIT.java`

**Files created:** none.

**Complexity:** L

**Risks:**
- **Authorization (fail-open).** Eviction alone loses the evict-then-repopulate race (design §9.4): a mint that read pre-commit permissions writes them back after the eviction. The epoch in the key is the fix; do not drop it as "redundant with eviction".
- **Authorization.** Capping the fan-out silently leaves holders unrevoked (T-D23 ✅ accepted as uncapped).
- **Locking/concurrency.** The holder read must run after commit, or assignments committed between read and commit are missed.
- The 204 now waits for the fan-out on the request thread (admin-only, rare; accepted).

**Tests (written first):**
- Unit `RoleManagementServiceTest`: detach calls `invalidateHolders` after commit with every holder; attach evicts each holder and never bumps; 1,001 holders → 3 script calls and one WARN; bucket tag per holder count.
- Unit `RoleResolutionServiceTest` / `RedisPermissionCacheAdapterTest`: key includes the epoch; a hit under epoch E is a miss under R.
- `TokenFreshnessIT`: **TS-9** detach on a role with 3 holders → each loses P on the next request, **including after refresh** (impact §8.2 regression); the §9.4 race reproduced with a latch that pauses a mint between its DB read and its cache write → the next refresh is not served the stale set; **RC-29.3** first-bump race at key expiry: a latch-paused mint with old epoch 0 writes its stale set after the bump, and after the key expires no freshly minted token carries the revoked permission.
- `RoleResolutionServiceIT`, `RedisPermissionCacheAdapterIT`, `RoleAssignmentCacheIT`, `RefreshTokenPermissionResolutionIT` updated for the key shape.

**Definition of Done:**
- Detach fans out; attach/assign evict without bump; cache keyed by epoch; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-011 — During a Redis outage each instance fails open for at most the time box, then returns 503 instead of logging users out (A9 outage policy)

**Milestone:** M7

**Description.**
- **(a) State machine in `PermissionFreshnessService`** (design §9.5), per instance, driven by an injected `Clock`: Healthy → DegradedOpen on **3 or more read or probe failures within a 10 s sliding window**, `t0` at the first failure of that window (RC-41); DegradedOpen → DegradedClosed when `fail-open-window` (15 min) since `t0` elapses; DegradedOpen/DegradedClosed → Recovering when a probe succeeds **and** the drain-complete predicate holds (trivially true until T-012 wires the replay queue); Recovering → Healthy after **60 s** of consecutive successes, clearing `t0`; Recovering relapses on the same 3-in-10 s rule to DegradedOpen, or straight to DegradedClosed if the window has elapsed, keeping `t0`. **Only epoch-read and probe failures count** (RC-53).
- **(b) Verdicts.** DegradedOpen → `SKIPPED_DEGRADED` (request proceeds); DegradedClosed → `UNAVAILABLE`, and the filter returns **503 `AUTH_005` with `Retry-After: 30`** in the RFC 9457 shape, **never** on a `@PublicEndpoint` request.
- **(c) Probe.** A 1 s scheduled task probes Redis in the degraded states. It is enabled by its **own unconditional `@EnableScheduling` configuration in `rbac`**, not by `SchedulingConfig` (conditional on `nexus.identity.audit.retry-buffer.enabled`; RC-52).
- **(d) Observability.** Gauge `nexus.rbac.epoch.degraded{state}`; counter `nexus.rbac.epoch.degraded_entries`; WARN `RBAC_EPOCH_DEGRADED_ENTER` / `RBAC_EPOCH_DEGRADED_FLAP` (3 entries in 15 min), INFO `RBAC_EPOCH_DEGRADED_EXIT` `{instance, cause}`. Config `fail-open-window=PT15M`, `entry-failure-threshold=3`, `entry-failure-window=PT10S`, `recovery-sustain=PT60S`. No runtime toggle endpoint. Readiness stays blind to Redis.

**ACs covered:** A9 (FR-A9.e, Gate 1 OQ1 "time-boxed fail-open with alert"); EC6.

**Dependencies:** T-009.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java` (from T-009)
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`
- `nexus-backend/src/main/resources/application.yml`
- Tests: `identity/infrastructure/web/JwtAuthenticationFilterTest.java`, `rbac/application/PermissionFreshnessServiceTest.java`, `rbac/TokenFreshnessIT.java`, `identity/infrastructure/audit/SchedulingConfigTest.java` (unchanged; reference for the independence test)

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochSchedulingConfig.java` (unconditional `@EnableScheduling`)
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/EpochSchedulingIndependenceTest.java`

**Complexity:** L

**Risks:**
- **Authorization (fail-open).** A "consecutive failures" counter never trips on F F S F F S (T-E43); the sliding window is required. Counting bump/drain failures would let a write-only Redis failure turn off enforceable read checks (T-E47).
- **Availability.** A 401 instead of 503 after the window sends every client into a refresh/reject loop and logs users out platform-wide; a 503 on public endpoints would block refresh and logout (T-D17).
- **Concurrency.** The state machine is shared by request threads and the scheduler; transitions and `t0` must be updated atomically (no lost relapse).
- Restarts reset the window (RC-31.4, recorded and accepted); RES-30's platform-wide 503 is the accepted end state.

**Tests (written first):**
- `PermissionFreshnessServiceTest` (fixed `Clock`): one or two failures do not trip; the third within 10 s trips DegradedOpen with `t0` at the first; three failures spread over > 10 s do not trip; an **F F S F F S … pattern sustained past the window trips DegradedOpen, then DegradedClosed** (RC-41.3); a probe success moves to Recovering and keeps `t0`; 60 s of successes returns Healthy and clears `t0`; relapse in Recovering before the window → DegradedOpen, after → DegradedClosed; 3 entries in 15 min increments the flap signal.
- `JwtAuthenticationFilterTest`: `UNAVAILABLE` on a non-public request → 503 `AUTH_005`, `Retry-After: 30`, ProblemDetail body; on a public request → passes.
- `TokenFreshnessIT`: refresh while the instance is DegradedClosed with a bearer attached → 200 (RC-24.3); a stale-epoch bearer on a non-public handler while DegradedClosed → 503 `AUTH_005` (RC-44.4).
- `EpochSchedulingIndependenceTest` (context test): with `nexus.identity.audit.retry-buffer.enabled=false`, the 1 s probe still executes (RC-52; drain half in T-012).

**Definition of Done:**
- All transitions and verdicts implemented as above; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-012 — A bump lost to a Redis failure is replayed within seconds, in every state (A9 lost-bump replay)

**Milestone:** M7

**Description.**
- **(a) Replay queue** in `PermissionFreshnessService` (design §9.3): bounded per instance (`replay-capacity-users`, default 100,000), **coalescing by `(tenantId, userId)`** and keeping the **oldest** `failedAt`; overflow **drops the newest** arrivals and increments `bump_failed{reason="overflow"}` **by the number of ids dropped**. A failed fan-out batch enqueues that batch **and every batch not yet sent** (a down Redis costs one bump timeout per request).
- **(b) Drain.** T-011's 1 s task drains a non-empty queue **on every tick, in every state, Healthy included** (in the degraded states only after that tick's probe succeeds), re-running the bump script in batches of 500 on the bump template. A partial failure **re-enqueues the unreplayed remainder with its original `failedAt`**. Entries older than `key-ttl-seconds` are dropped. T-011's drain-complete predicate is wired to "queue empty".
- **(c) Failure accounting** (RC-53, L-4): bump and drain failures keep entries queued and page through `bump_failed`, but **never** count towards the 3-in-10 s entry or relapse window and **do not reset the 60 s sustain** while Recovering.
- **(d) Observability.** ERROR `RBAC_EPOCH_BUMP_FAILED {operation, tenantId, userCount}` + `nexus.rbac.epoch.bump_failed{operation, reason}`; INFO `RBAC_EPOCH_BUMP_REPLAYED {tenantId, userCount, ageMs}` + `nexus.rbac.epoch.bump_replayed`; gauge `nexus.rbac.epoch.replay_queue_users`.

**ACs covered:** A9 (FR-A9.c durability under failure), A10 (fan-out durability).

**Dependencies:** T-010 (fan-out batches), T-011 (scheduled task and state machine).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java`
- `nexus-backend/src/main/resources/application.yml`
- Tests: `rbac/application/PermissionFreshnessServiceTest.java`, `rbac/TokenFreshnessIT.java`, `rbac/application/EpochSchedulingIndependenceTest.java`

**Files created:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/EpochReplayQueue.java` (bounded, coalescing; package-private collaborator of the service) + `EpochReplayQueueTest.java`.

**Complexity:** M

**Risks:**
- **Authorization (fail-open).** Draining only on a degraded-state probe leaves the common single failure unreplayed for ~30 minutes of exposure (T-E44).
- **Concurrency.** Enqueue (request thread, post-commit) and drain (scheduler) race; coalescing must keep the oldest `failedAt` under concurrent enqueue, and a drained entry must not be lost if the drain fails.
- **Memory.** The queue must stay bounded; overflow is counted per dropped id and pages.
- Not covered (RES-31, Low, accepted): queue lost on restart; bumps lost to async replication at a Sentinel failover.

**Tests (written first):**
- `EpochReplayQueueTest`: coalescing keeps the oldest `failedAt`; capacity counts distinct users; overflow drops the newest and reports the dropped count; drop-by-age at drain.
- `PermissionFreshnessServiceTest`: the drain runs in Healthy; a partial drain re-enqueues the remainder with original `failedAt`; a failed batch enqueues the rest of the fan-out unsent; **RC-53:** sustained drain failures with successful epoch reads leave the instance Healthy with checks enforced, and `bump_failed` increments; bump failures alone never trip or relapse; **L-4:** a drain failure while Recovering does not reset the 60 s sustain (Healthy is reached 60 s after the probe success).
- `TokenFreshnessIT`: a bump that fails while Redis is paused is replayed on recovery and the holder's old token is then rejected (RC-30); a **single** bump failure with the instance still Healthy is replayed within **2 s** and the old token is then rejected (RC-42.4).
- `EpochSchedulingIndependenceTest`: with the retry buffer disabled, the drain still runs (RC-52 drain half).

**Definition of Done:**
- Queue, drain and accounting implemented; `./mvnw verify -DskipITs` green; ITs written.
- **L-4 doc line:** `03-design.md` §9.5 states that a drain failure during Recovering does not reset the 60 s sustain. No flag. One commit.

### T-013 — A permission change cannot log out users behind a shared NAT, and failing refreshes can neither block valid ones nor suppress reuse detection (refresh limits)

**Milestone:** M7

**Description.**
- **(a) Family bucket.** In `RefreshTokenUseCase`, after `findByTokenHash` and before rotation: `REFRESH_FAMILY:{sha256(familyId)}` at 30/60 s through `RateLimitStore.tryConsume`; exceeding it → 429 with `Retry-After`. Unknown/invalid tokens have no family and never consume it.
- **(b) Per-IP total** `REFRESH_IP:{ip}` raised to **300/60 s** (`refresh-ip-max-attempts`) in `LoginRateLimitFilter`, which **no longer consults** any failure bucket.
- **(c) Reuse first** (RC-51): on a revoked token, **always** run `revokeFamily` before the failure bucket is consulted. `revokeFamily` returns the number of **unrevoked** rows it revoked, propagated through all four layers (repository `int` from the `@Modifying` update, `RefreshTokenPort`, `JpaRefreshTokenAdapter`, `SecureEventService.revokeFamily` under `REQUIRES_NEW`) so the use case acts on the committed count (L-3). Count ≥ 1 → always write `TOKEN_REFRESH_REUSE` and return today's 401 `AUTH_004`. Count 0 → treated as an ordinary failure (L-2). The count never enters the response, a header, a log line or metadata (L-3).
- **(d) Failure bucket** `REFRESH_IP_FAIL:{ip}` at 30/60 s, consumed **only on failure outcomes**, inside the use case, **before** the `TOKEN_REFRESH_FAILURE` write (RC-43). A rejection → 429 with `Retry-After`, **no audit row**, `nexus.auth.refresh_failure_throttled` incremented, at most one WARN `AUTH_REFRESH_FAILURE_THROTTLED {suppressedCount}` per window, raw IP never logged. A valid token is never blocked by it. `RateLimitStore` unchanged (no `isExhausted`).

**ACs covered:** A9 (FR-A9.d "client refreshes" stays safe at scale), A10 (detach storm). Supports TS-8/TS-9 at NAT scale.

**Dependencies:** T-010 (detach fan-out drives the storm the k6 gate measures).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/application/service/RefreshTokenUseCase.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/service/SecureEventService.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/RefreshTokenPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaRefreshTokenAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaRefreshTokenRepository.java`
- `nexus-backend/src/main/resources/application.yml`
- Tests: `identity/application/service/RefreshTokenUseCaseTest.java`, `identity/infrastructure/web/LoginRateLimitFilterTest.java`, `identity/application/service/SecureEventServiceTest.java`, `identity/infrastructure/persistence/RefreshTokenIT.java`

**Files created:**
- `nexus-backend/src/test/java/com/example/nexus/identity/application/service/RefreshFailureThrottleIT.java`
- `nexus-test/performance-test/scenarios/detach-refresh-storm.js`, `nexus-test/performance-test/tests/load/detach-refresh-storm.js` (write-path scenario; needs seeded holders and cleanup, an exception to the suite's current read-only scope)

**Complexity:** L

**Risks:**
- **Authentication.** A filter-side failure check blocks valid refreshes behind an IP (T-D24); consulting the bucket before `revokeFamily` lets an attacker suppress theft response and evidence (T-E46).
- **Cryptography.** `REFRESH_FAMILY` uses plain SHA-256 of a non-secret UUID only to keep it out of logs and keys; it is not a MAC and must not be presented as one.
- **Concurrency.** The failure consume must be the store's atomic `tryConsume` (N concurrent failures write ≤ 30 rows); concurrent replays of one token serialize on the conditional `UPDATE` (one sees N, the other 0).
- **Audit volume.** Unauthenticated, append-only audit writes must stay at today's 30/60 s per source (RES-40).

**Tests (written first):**
- `RefreshTokenUseCaseTest`: the family bucket is consumed after lookup and never for an unknown token; 30 invalid refreshes from an IP, then a valid refresh from the same IP → 200; the 31st invalid refresh → 429 with `Retry-After`, no `auth_events` write, counter incremented, one WARN per window; **RC-51:** with the IP's failure bucket exhausted, a replay of a rotated token still revokes the family and writes exactly one `TOKEN_REFRESH_REUSE` row, and the attacker's successor token then gets 401 `AUTH_004`; a second replay (revokes nothing) is throttled with no row; **L-2:** a replay that revoked nothing with the bucket **not** exhausted writes one `TOKEN_REFRESH_FAILURE` (STANDARD lane) and no `TOKEN_REFRESH_REUSE`; the revoked count never appears in the response.
- `LoginRateLimitFilterTest`: the filter never consults `REFRESH_IP_FAIL`; the per-IP total is 300.
- **L-3** IT in `RefreshTokenIT` (MySQL): `revokeFamily` returns the number of unrevoked rows and excludes already-revoked ones; the count reaches the use case through all four layers.
- `RefreshFailureThrottleIT` (Redis): N concurrent invalid refreshes write at most 30 `TOKEN_REFRESH_FAILURE` rows.
- **k6** `tests/load/detach-refresh-storm.js` (merge gate, production ingress topology): detach on a 200-holder role behind one IP → zero forced logouts; an attacker behind the NAT at 100 invalid refreshes/min throughout → still zero; rotated-token replays during the attack → every replay that revokes an active family is answered as reuse and leaves a `TOKEN_REFRESH_REUSE` row; recorded for both deployment shapes.

**Definition of Done:**
- Three buckets and the reuse-first ordering implemented; `./mvnw verify -DskipITs` green; ITs and k6 test written.
- **L-1 doc line:** "at least one **active** token" becomes "at least one **unrevoked** token" in `03-design.md` §0 #19 and §9.7 and in ADR-0022 D8; the code Javadoc uses "unrevoked". No flag. One commit.

### T-014 — Production refuses to start against an unauthenticated Redis (Redis trust boundary)

**Milestone:** M7

**Description.**
- New property `nexus.rbac.redis.require-auth` (default `false` in `application.yml`, **`true` in the existing `application-prod.yml`**; RC-45.1). When `true`, startup fails if `spring.data.redis.password` is blank for the **main factory and both dedicated epoch factories** (RC-34.1, RC-45.2).
- The startup assertion lives in `rbac.infrastructure.cache` (Redis types stay there; ADR-0016 D6).

**ACs covered:** A9 (production prerequisite for an authorization-bearing Redis; RES-32).

**Dependencies:** T-009 (dedicated factories).

**Files impacted:**
- `nexus-backend/src/main/resources/application.yml`
- `nexus-backend/src/main/resources/application-prod.yml` (exists; adds `require-auth=true`, A-3)
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java` (from T-009)

**Files created** (`application-prod.yml` already exists, so it is under Files impacted, A-3):
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java` + `RedisAuthStartupAssertionTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/cache/AuthenticatedRedisIT.java`

**Complexity:** S (≈ 80–120 production lines; separate because it is a distinct production-safety control with its own failure mode and tests, and T-009 is already at the top of the size band).

**Risks:**
- **Authorization.** Redis write access equals permission injection at mint and revocation suppression (RES-32). An assertion that checks only the main factory leaves the hot-path factories unauthenticated (the RC-34 Partial finding).
- A `prod` profile file that production never activates makes the control inert (A-3, checklist).

**Tests (written first):**
- `RedisAuthStartupAssertionTest`: `require-auth=true` with a blank password fails for each of the three factories; non-blank passes; `false` never fails; the `prod` profile resolves `require-auth=true`.
- `AuthenticatedRedisIT`: a Testcontainers Redis with `requirepass` and an ACL user; epoch read and bump authenticate through both dedicated factories; with the password removed from the app config and `require-auth=true`, startup fails.

**Definition of Done:**
- Assertion and `application-prod.yml` in place; `./mvnw verify -DskipITs` green; IT written. No flag. One commit.

---

# M7b — drop v2 token acceptance (PR 7)

**PR boundary.** T-015 alone. Deployed only after M7 is on **every** instance **and** at least 900 s (the access-token TTL; skew is 0) have passed (design §9.6). May merge while M3 is in flight (A-4).

**Merge checklist (M7b):**
- [ ] M7 confirmed on every instance for ≥ 900 s.
- [ ] Exit criterion: `token_rejected{reason=schema_version}` = 0 after deploy (design §14). Rollback is redeploying M7 (accepts {2, 3}).

### T-015 — Only v3 tokens are accepted once M7 is fully rolled out (A9 contract step)

**Milestone:** M7b

**Description.** `JwtClaims.ACCEPTED_VERSIONS = Set.of(3)`; remove the "v2 is epoch 0" branch from the freshness check; a v2 token gets 401 `AUTH_003` with `token_rejected{reason=schema_version}`.

**ACs covered:** A9 (completes the version policy; EC10), A11 (FR-A11.a in its final form).

**Dependencies:** T-009 deployed everywhere for ≥ 900 s.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java`
- Tests: `identity/infrastructure/security/JwtRs256ServiceTest.java`, `identity/infrastructure/security/JwtRs256ServiceSecurityTest.java`, `rbac/TokenFreshnessIT.java`

**Files created:** none.

**Complexity:** S (≈ 20–40 production lines; a separate PR by design, so it cannot merge with any other task).

**Risks:**
- **Authentication.** Shipping before the 900 s wait 401s every live v2 session (EC10); the checklist gate is the control.

**Tests (written first):** `JwtRs256ServiceTest`: v2 → 401 with `reason=schema_version`, v3 accepted; `TokenFreshnessIT`: the v2 case inverts to "v2 rejected".

**Definition of Done:** v2 rejected everywhere; `./mvnw verify -DskipITs` green. No flag. One commit.

---

# M3 — A5 retire superseded machinery, plus D3 (PR 8, risk: Critical)

**PR boundary.** T-016 → T-019 in one PR on `feature/US-018/M3`. **Hard prerequisites:** ~~M2 soaked in staging ≥ 1 sprint~~ (waived 2026-10-05, no environment exists; the soak moves to the first staging deployment, see the Decision at the top), M4 and M7 merged (design §1.2). Carries its **own threat-model re-pass** before merge.

**Retirement rule (FR-A5.d, design §5, endorsed TM §5).** A test is *obsolete* only if ADR-0021 names the control that now enforces its assertion **and** an equivalent test against that control lands in the same PR. A test that goes green by inversion signals a lost control. Every task below lists the tests it retires and their replacements; each retirement needs the re-pass sign-off.

**Threats owned:** T-E33 (RC-25), T-E34 (RC-26), T-E36 (RC-28), T-E32 (RC-23.2, R1-1 / RC-50(a)), T-E35 (RES-14 via RC-27.1), RC-50(b), RES-27, RES-28, RES-42.

**Merge checklist (M3):**
- [ ] **Step B re-pass** signs off each ledger row (design §5.1, TM §5) against the code.
- [ ] **RES-26:** the Platform Security Owner confirms the story owner's Gate 2 acceptance at this re-pass (TM §13.8); review date 2026-11-27 and Epic-3 hard expiry unchanged.
- [ ] M4 and M7 merged. ~~M2 soaked in staging for ≥ 1 sprint with no `RbacAdministrators` anomalies~~ waived for the merge on 2026-10-05 (no environment); the soak and the anomaly check are now conditions on the first staging deployment.
- [ ] **Harness C** (`LastAdminLockoutIT`) passes repeatedly with the re-scoped lock set, the benign thread and the **RC-25.3** race case; **MC-H'** green.
- [ ] **Zero-admin sweep** under the new definition in every environment where either parent flag was ever `true`, done forensically (US-017 RC-21 pattern); a remediation ticket or written acceptance per affected tenant before production deploy.
- [ ] **RES-6:** Ops retention sign-off for `RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS`, `RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT`, `RBAC_ATTACH_PROVENANCE_REFUSED` and the role-subset denial WARN (design §2.3; A-8).
- [ ] RES-13 closed at this merge (A3 + role-subset); RES-28 and RES-42 accepted as recorded.
- [ ] Alert content (docs pass): `nexus_rbac_gate_bypass_canary` re-pointed at `self_assign_admin_disagreement` (page); the `self_role_assignment_total` ticket dropped; row 13 ticket/page and row 14 page; `admin_role_assigned{selfTarget}` ticket.

### T-016 — Assign and revoke decide "administrator" from the set lock's own rows, and revoke-subset replaces the T-E17 gates (ledger rows 1–6, 10)

**Milestone:** M3

**Description.**
- **(a) M10'.** `UserRoleAssignmentPort.findRolePermissionIdsForTenantRoles(UUID tenantId)` returns `(roleId, permissionId)` per tenant role, non-locking, replacing M10 (row 6); admin-defining role ids come from `RbacAdministrators` over it plus M15.
- **(b) Assign** (row 1): the legacy US-016/017 gate diamond is removed. If the target is admin-defining (M14 + M15), take the set lock first (M10' → lock set = admin-defining ids ∪ target → M11, single statement, ascending unsigned-byte order; ADR-0018 D5–D7 upheld), and A4's "is the caller an administrator?" comes from **M11's locked rows** (the caller is an active holder in the result), never from M13 (RC-25.1). A2 still compares against M13's union.
- **(c) Revoke** (row 2, design §5.3): tenant 404 → `M3` 404 → throttle → classify → if admin-defining, set lock → **revoke-subset** (403): M13 union ⊇ M14(R), and if R is admin-defining the caller is an administrator **from M11's rows** (RC-25.1, RC-26.2) → distinct-holder lockout (409, row 3, population = holders of admin-defining roles) → UPDATE. 403 always precedes 409 (ADR-0017 D4). Denial reasons: subset failure `GRANT_EXCEEDS_CALLER`; administrator-requirement failure keeps `NOT_TENANT_ADMIN` (A-13), so kept 403 assertions stay byte-identical.
- **(d) Removed:** the H-1 caller-qualifying filter (row 5) and M5b on decision paths. **Kept:** lock-hold timer and lock-set-size summary with `{operation, outcome}` (row 10).
- RC-26.1's false sentence is already gone from the design and ADR-0021; no code comment may reintroduce it.

**ACs covered:** A5 (FR-A5.a for rows 1–6 and 10, FR-A5.b, FR-A5.d). Test scenario TS-16 (partial).

**Dependencies:** T-002, T-006, T-009 (M2, M4, M7 merged).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- Tests: `rbac/application/RoleAssignmentServiceTest.java`, `rbac/LastAdminLockoutIT.java`, `rbac/AdminEquivalentLockoutIT.java`, `rbac/RoleRevocationSymmetryIT.java`, `rbac/security/RoleAssignmentSecurityIT.java`, `rbac/RoleAssignmentEscalationIT.java`

**Files created:** none.

**Complexity:** L

**Risks:**
- **Authorization.** Taking administrator status from M13 on a set-lock path lets a compromised administrator race their own revocation (T-E33); it must come from M11's rows.
- **Authorization.** Revoke-subset without the administrator requirement lets a union-holder strip administrators (T-E34).
- **Locking/concurrency.** Any new acquisition outside the single-statement ascending set lock, or a comparator that is `UUID.compareTo` instead of unsigned byte order, re-opens the RES-10 deadlock; harness C is the exit gate.
- **Test retirement.** `RoleRevocationSymmetryIT` and `LastAdminLockoutIT.should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin` must stay **verbatim**; a diff in either is a defect.
- **Behaviour change (recorded):** a caller without `user:read` can no longer revoke `MEMBER` (revoke-subset tightening).

**Tests (written first):**
- Unit `RoleAssignmentServiceTest`: admin-defining target takes M10' → M11 before the decision, benign target takes no lock; A4 administrator status read from M11's rows (M13 stubbed to say "admin" while M11 says "not" → 403); revoke-subset union failure → `GRANT_EXCEEDS_CALLER`; admin-defining revoke by a union-holder → 403 `NOT_TENANT_ADMIN` (RC-26.2); 403 before 409; distinct-holder lockout over admin-defining holders (one user, two admin-defining roles counted once); unsigned byte-wise comparator pinned by captor; caller without `user:read` revoking `MEMBER` → 403.
- MC-A: M10' carries no `@Lock`.
- IT `LastAdminLockoutIT` harness C: re-scoped lock set with the `assign` admin thread and the benign thread; **RC-25.3:** a revoke of the caller's admin-defining role races the caller's own admin-defining assign → the assign returns 403; outcome scenarios re-seeded under the new definition; the named 403 test unchanged.
- IT `RoleRevocationSymmetryIT` unchanged plus new revoke-subset cases; `AdminEquivalentLockoutIT` becomes admin-defining cases; `RoleAssignmentSecurityIT`: assign cases rewritten as A2 cases, and the **T-E7 stale-JWT / out-of-band-revocation proof kept**, moved onto the set-lock path.

**Definition of Done:**
- Rows 1–6 and 10 implemented; every retired assertion names its covering control (ADR-0021) and its replacement test in this PR.
- `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-017 — Detach requires role-subset, an attach that would create an administrator role is refused while non-administrator-assigned holders exist, and attach signals are re-derived (ledger rows 11–14, 19)

**Milestone:** M3

**Description.**
- **(a) Attach** (row 11): the name-based AC11 gate is removed; A3 (T-003) covers every permission.
- **(b) Detach role-subset** (row 12): the caller must hold every permission of R (M13 union ⊇ M14(R)); when R is admin-defining the caller must also be an administrator **through a role other than R** (M13 per-role sets). Failure → 403 `RBAC_001`, WARN `RBAC_ROLE_SUBSET_DENIED` (A-14) plus `permission_denied{permission="role:write", reason="GRANT_EXCEEDS_CALLER"}`, no audit row. This replaces US-017 D13 and closes row 19 except for the concurrent race (RES-28).
- **(c) Narrow provenance rule** (row 14, R1-1, RC-50(a)): in `attachPermission`, after A3 and before the duplicate check, if R is **not** admin-defining now **and** M14(R) ∪ {P} ⊇ M15, and R has an active holder whose `assigned_by` is not currently an administrator → **409 `RBAC_010`** (new code; `detail` names no holder). One extra non-locking read, only on that branch (R's holders with `assigned_by` against the tenant's administrator user set). WARN `RBAC_ATTACH_PROVENANCE_REFUSED {tenantId, actorUserId, roleId, permissionId, nonAdminAssignedCount}` and `permission_denied{permission="role:write", reason="ATTACH_PROVENANCE"}`; no audit row. A duplicate attach to an already admin-defining role still gets 409 `RBAC_005`.
- **(d) Provenance signal** (row 13, RC-23.2): on **every** attach, after commit, the A10 holder read returns `(userId, assignedBy)` plus one read of the tenant's administrator user set; WARN `RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS {tenantId, roleId, permissionId, holderCount, nonAdminAssignedCount}` and `nexus.rbac.attach_escalates_non_admin_assigned{holders}` (bucketed, no tenant tag). Ticket when `nonAdminAssignedCount > 0`; page when additionally the permission is `user:role:assign` or `role:write`, or the attach makes R admin-defining (A-15 for how the page condition is made observable).
- **(e) Role became admin-defining** (row 14): `RBAC_ROLE_BECAME_ADMIN_DEFINING` + `nexus.rbac.role_became_admin_defining{holders}`, paged when `holders > 0`.
- `RoleController` `@ApiResponse` text for attach/detach updated (removes the stale "No AC11 gate" note, impact §0).

**ACs covered:** A5 (FR-A5.a for rows 11–14 and 19); closes US-017 RES-13 (detach half); A3 consolidated.

**Dependencies:** T-016.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/RoleController.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/common/security/DenialReason.java` (`ATTACH_PROVENANCE`, if the metric tag is derived from it)
- Tests: `rbac/application/RoleManagementServiceTest.java`, `rbac/RoleManagementAdminGateIT.java`, `rbac/RoleManagementIT.java`, `rbac/DangerousPermissionHolderSignalIT.java` (renamed, below), `rbac/security/RolePermissionSecurityIT.java`

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/AttachProvenanceConflictException.java` (409 `RBAC_010`, extending the existing conflict base so no new handler is needed) + test
- `nexus-backend/src/test/java/com/example/nexus/rbac/AttachEscalationSignalIT.java` (replaces `DangerousPermissionHolderSignalIT`)

**Complexity:** L

**Risks:**
- **Authorization.** Role-subset that tests only the union lets a union-holder demote an admin-defining role (T-E34); "through a role other than R" stops an administrator detaching away their own last administrator status.
- **Authorization.** The provenance rule must check "not admin-defining now", or a duplicate attach to an administrator role returns the wrong 409 (RC-50(a)). It is preventive only for the admin-defining payoff; partial escalations stay detective (RES-26, Medium).
- **Locking/concurrency.** Both new reads are non-locking and after commit (row 13) or on a rare branch (row 14); detach is deliberately **not** added to the lock family (RES-28 race accepted, detected by the indicator).
- **PII.** `RBAC_010`'s `detail` and every WARN carry ids and counts only.

**Tests (written first):**
- Unit `RoleManagementServiceTest`: role-subset matrix (holder of all R's permissions → 204; union-holder detaching from an admin-defining custom role → 403; an administrator whose only admin-defining role is R detaching from R → 403; an administrator through another role → 204); attach no longer runs a name gate; provenance: completing attach with one non-administrator-assigned holder → 409 `RBAC_010` and no write; same attach with only administrator-assigned (or break-glass, `assigned_by = target`) holders → 201 and the row-14 signal fires; duplicate attach to an already admin-defining role → 409 `RBAC_005`; row-13 WARN fields, bucket, ticket and page conditions (including `user:role:assign` and `role:write`).
- IT `RoleManagementAdminGateIT`: attach cases rewritten as A3 cases; detach cases kept as outcome assertions; union-holder detach → 403 (row 19).
- IT `AttachEscalationSignalIT` (renamed and re-targeted): provenance cases, row-14 page with holders > 0.

**Definition of Done:**
- Rows 11–14 and 19 implemented; `RBAC_010` registered; retired tests mapped to replacements.
- `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-018 — An independent check still pages when a self-assignment disagrees with A4, and the M12 canary and name-based counters are deleted (ledger rows 7–9, 18)

**Milestone:** M3

**Description.**
- **(a) Independent capture** (row 7, RC-28.1, RC-50(b)): on every successful **self-target** assign, **before the INSERT**, one non-locking statement over the caller's own active roles, driven by `fk_user_roles_user`, `GROUP BY ur.role_id HAVING COUNT(DISTINCT rp.permission_id) = (catalogue count)`, with its **own** `r.tenant_id = ur.tenant_id` and active-assignment predicates (the `deleted_at IS NULL` predicate is added in T-026), sharing no input with M13. If it disagrees with A4: ERROR `RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT {tenantId, actorUserId, roleId}` + `nexus.rbac.self_assign_admin_disagreement`. Never consulted for authorization.
- **(b) Deleted:** the M12 port method, query and adapter delegation (row 8) and its MC-G unit blocks; `nexus.rbac.self_role_assignment_total`; D23 `admin_minted_by_non_named_admin` and `privileged_role_change_allowed{callerMatchedOn}` (row 9).
- **(c) Re-derived:** `nexus.rbac.admin_role_assigned{selfTarget}` when the assigned role is admin-defining (ticket, never page).
- **(d) ArchUnit** (row 18): `role_management_service_must_not_call_the_non_locking_admin_read` is removed; MC-2 becomes a compile-time fact because M12 no longer exists.

**ACs covered:** A5 (FR-A5.a for rows 7–9 and 18).

**Dependencies:** T-016.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- Tests: `rbac/application/RoleAssignmentServiceTest.java` (MC-C / MC-G blocks retired), `rbac/LastAdminLockoutIT.java` (MC-A block)

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/HeldPermissionPartitionIT.java` (MC-H').

**Complexity:** M

**Risks:**
- **Authorization (detection).** A union-level count would page on every union-holder; the statement must group by role (RC-50(b)). Reusing M13 as its input re-creates T-E29 (one read feeding every decision with nothing independent watching).
- Capturing after the INSERT repeats US-017 RES-25.
- **Shared combinator (RES-42, accepted).** Gate and capture both rest on the catalogue-count definition; the `rbac.domain` 0.90 gate and MC-1 are the controls.

**Tests (written first):**
- Unit: **RC-28.1** a forced disagreement (independent statement stubbed to "administrator" while A4 says "not", and the reverse) emits the ERROR and increments the counter; agreement emits nothing; the capture runs before the INSERT (`InOrder`); `admin_role_assigned{selfTarget}` fires for an admin-defining target only.
- MC-A extended to the independent statement.
- IT **MC-H'** `HeldPermissionPartitionIT`: M13's per-role partition equals M14 called per role over the US-017 MC-H matrix (foreign-tenant role, zero-permission role, `TENANT_ADMIN`; the soft-deleted role is added in T-026).

**Definition of Done:**
- Replacement capture live; M12, D23 and the dropped counter gone with zero references; MC-C/MC-G retirements mapped to MC-H' and the disagreement test.
- `./mvnw verify -DskipITs` green; IT written. No flag. One commit.

### T-019 — The zero-admin indicator, `assignedBy` redaction and break-glass all use the one "administrator" definition, and the superseded predicates and narratives are deleted (ledger rows 15–17, D3)

**Milestone:** M3

**Description.**
- **(a) Indicator** (row 15): `RbacZeroActiveAdminsHealthIndicator` / `ZeroAdminTenantReader` report "tenant has ≥ 1 admin-defining role with zero distinct active holders", comparing `COUNT(DISTINCT rp.permission_id)` with the catalogue count (no names passed). The 30 s actuator cache and the liveness/readiness exclusion stay protected properties.
- **(b) Redaction** (row 16): `listActive` redacts `assignedBy` unless the caller is an administrator (§2.1).
- **(c) Break-glass** (A-6): `BootstrapAdminService`'s zero-administrator precondition switches to the §2.1 definition through `RbacAdministrators`.
- **(d) Deleted** (row 17): `RbacDangerousPermissions`, `RbacAdminEquivalence` and their tests once rows 1, 2, 11, 12 and 15 have migrated.
- **(e) FR-A5.c proxy:** a grep-based test in `HexagonalArchitectureTest` asserts no symbol from `RbacDangerousPermissions`, `RbacAdminEquivalence`, M5b, M12 or the D23 counters is referenced from `rbac.application`.
- **(f) D3:** rewrite the security comments in both services once, stating each invariant in plain language with ticket codes only as trailing references; the duplicated narratives (`RoleAssignmentService.java:158-208`, `:385-436`) become one class-level paragraph plus a pointer to ADR-0021; the stale comment at `:627` ("every self-registered MEMBER holds `user:read`") is corrected (C5 / D2).

**ACs covered:** A5 (FR-A5.a rows 15–17, FR-A5.c), D3. A7 (precondition re-scoped).

**Dependencies:** T-016, T-017, T-018.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/ZeroAdminTenantReader.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java` (from T-007)
- Deleted: `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RbacDangerousPermissions.java`, `…/rbac/domain/RbacAdminEquivalence.java`
- Tests: `rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorTest.java`, `rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorIT.java`, `rbac/infrastructure/health/AdminEquivalenceSqlJavaEquivalenceIT.java` (re-targeted as MC-I), `rbac/infrastructure/health/HealthProbeConfigurationTest.java` (unchanged, must stay green), `architecture/HexagonalArchitectureTest.java`, `rbac/BreakGlassAdminIT.java`, `rbac/application/RoleAssignmentServiceTest.java`; retired with sign-off: `rbac/domain/RbacDangerousPermissionsTest.java`, `rbac/domain/RbacAdminEquivalenceTest.java`, `rbac/AdminEquivalenceEquivalenceIT.java`

**Files created:** none.

**Complexity:** L (much of it deletion).

**Risks:**
- **Authorization.** Deleting the predicates before every consumer has migrated leaves a gate silently computing "never admin" or "always admin"; delete last, after the grep test is green.
- **Detection.** Weakening the indicator's 30 s cache or its probe exclusion re-opens US-017 RES-21 (DB load / probe flapping).
- **PII.** Redaction widening is deliberate and small (row 16); no other field changes visibility.
- **D3.** Paraphrasing an invariant incorrectly is worse than the old narrative; each rewritten comment must be checked against ADR-0021.

**Tests (written first):**
- `RbacZeroActiveAdminsHealthIndicatorTest` / `IT` re-seeded: a custom admin-defining role with zero holders → DOWN; `TENANT_ADMIN` with a holder → UP; a role one permission short is not counted.
- **MC-I:** Java (`RbacAdministrators`) versus SQL equivalence over the fixture matrix.
- Unit (re-targeted MC-2-style): an administrator sees `assignedBy`; a union-holder gets the redacted shape.
- `BreakGlassAdminIT`: a tenant whose only administrator holds a custom admin-defining role → refused (exit 5); a tenant whose custom role lost admin-defining status → grant allowed.
- Grep test (FR-A5.c proxy) green.

**Definition of Done:**
- Rows 15–17 and D3 done; predicate classes deleted with zero references; every retired test mapped to its replacement for the re-pass.
- `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

---

# M8 — Group B hardening (PR 9)

**PR boundary.** T-020 → T-024 on `feature/US-018/M8`, after M3 (B1/B8 edit the smaller post-A5 files) and M7 (B6 needs the epoch-keyed cache). Contains V7 and V8; **V8 runs in a maintenance window**. B4 has no task (A-11).

**Threats owned:** T-R13 (RC-39.2, RC-50(c)), T-D18 (RC-33.1), T-I18 (RC-33.2), T-T19 (RC-40.3), T-D21 (RC-40.4), T-T21 (RC-48.1 scanner), T-D25 (RC-49.1), RC-45.1 (shared-store half), RC-54(b), RC-34.2 (B6 consideration).

**Merge checklist (M8):**
- [ ] **V8 pre-flight** (`SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.tenant_id <> r.tenant_id`) = 0 in **every** environment before deploy (A-9). Non-zero → stop; remediation needs a DBA exception procedure with Security sign-off.
- [ ] **Maintenance window** booked for V8 (`ALGORITHM=COPY`; writes to `user_roles` blocked, reads continue).
- [ ] Runbook (docs pass): a failed V7/V8 is recovered by **`flyway repair` then a re-run, as the Flyway DDL user**; `nexus_app` grants are not widened (RC-49.1, RES-44).
- [ ] `require-shared-store=true` present in `application-prod.yml` and checked by the runbook; RES-11 closed at deploy.
- [ ] **RES-6:** Ops retention sign-off for `RBAC_CROSS_TENANT_TARGET` and `RBAC_DENIAL_THROTTLED`.
- [ ] Cross-tenant **rate ticket alert** at `max(5 × 7-day baseline, 20 per 15 min)` defined (RC-39.2, RC-50(c)); RES-34 accepted.
- [ ] Exit criteria: TS-11 and TS-12 green; the **pool-pressure k6** re-run green (T-024).
- [ ] Docs pass: US-012 and US-015 API docs describe the 404; `US-015/monitoring.md:75` no longer groups by `tenantId`; ADR-0023 (B4) accepted; ADR-0022 carries the B6 addendum (T-023).

### T-020 — Cross-tenant targets return a byte-identical 404, and no RBAC metric carries a tenant tag (B1, B3)

**Milestone:** M8

**Description.**
- **(a) B1** (Decision 20): `RoleAssignmentService.verifySameTenant`, `resolveRoleInTenant`, `listActive` and `RoleManagementService.resolveRoleInTenant` throw the **same** `ResourceNotFoundException` (`USER_NOT_FOUND` / `ROLE_NOT_FOUND`, same message) as a genuine not-found. Before throwing, the service emits WARN `RBAC_CROSS_TENANT_TARGET {tenantId, actorUserId, targetKind, operation}` and increments the **same** `nexus.rbac.permission_denied{permission, reason="CROSS_TENANT_TARGET"}` series. The synchronous cross-tenant `REQUIRES_NEW` denial row is **dropped** and **not** re-routed through `AuthEventRetryBuffer` (R1-5). `RbacAuditPort.recordRoleAssignmentDenied`'s Javadoc scope shrinks to `NOT_TENANT_ADMIN`, `SELF_ASSIGNMENT`, `GRANT_EXCEEDS_CALLER` and the revoke-subset denial. All 54 `CROSS_TENANT_TARGET` occurrences in 11 files change in this one task (no per-endpoint increments, requirements R8). `@ApiResponse` text in the three controllers updated.
- **(b) B3:** remove every remaining `tenantId` metric tag (impact §9 names `RoleAssignmentService.java:354` and `RoleManagementService.java:254`; M3 may already have deleted both meters, A-16). Attribution stays in WARN fields.

**ACs covered:** B1 (FR-B1.a, FR-B1.b), B3 (FR-B3.a). Test scenario TS-11.

**Dependencies:** T-019 (M3 merged).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java`, `RoleController.java`, `PermissionController.java`
- `nexus-backend/src/main/java/com/example/nexus/common/security/DenialReason.java` (only if `CROSS_TENANT_TARGET` usage changes)
- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js` (cross-tenant scenario removed)
- Tests: `rbac/security/RoleAssignmentSecurityIT.java`, `rbac/RoleAssignmentAuditIT.java`, `rbac/RoleAssignmentCacheIT.java`, `rbac/application/RoleAssignmentServiceTest.java`, `rbac/application/RoleManagementServiceTest.java`, `rbac/security/RolePermissionSecurityIT.java`; **not** `rbac/security/CrossTenantPermissionIT.java` (must stay unmodified, its 403 is `PERMISSION_ABSENT`)

**Files created:**
- `nexus-backend/src/test/java/com/example/nexus/rbac/security/CrossTenantNotFoundEquivalenceIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/RbacMetricCardinalityTest.java` (MC-8)

**Complexity:** M

**Risks:**
- **Authorization (oracle).** A body or timing difference between cross-tenant and not-found keeps the existence oracle (requirements R8); the DB write on one path only is the timing difference, hence its removal.
- **Audit (accepted, RES-34).** Cross-tenant evidence becomes log-only; it depends on the RES-6 retention sign-off and the rate alert.
- Touching `CrossTenantPermissionIT` is a defect (non-regression contract).

**Tests (written first):**
- `CrossTenantNotFoundEquivalenceIT` (**TS-11**): on each of the 5 handler paths, a cross-tenant id and a non-existent id give identical status, `code`, `detail` and header set (only `traceId` / `instance` differ); a WARN only on the cross-tenant path; no `auth_events` row on either path.
- **MC-8** `RbacMetricCardinalityTest`: after exercising both services' success and denial paths, no meter in the `MeterRegistry` has a `tenantId` tag key.
- Updated service and security tests assert 404 where they asserted 403 `CROSS_TENANT_TARGET`.

**Definition of Done:**
- All 54 occurrences migrated in one commit; `CrossTenantPermissionIT` unmodified; `./mvnw verify -DskipITs` green; ITs written. No flag.

### T-021 — The database rejects a cross-tenant assignment, and a permission-adding migration cannot ship without a correctly bound footer (B2, B7)

**Milestone:** M8

**Description.**
- **(a) V7** `V7__rbac_roles_id_tenant_unique.sql`: one `ALTER TABLE roles ADD CONSTRAINT uq_roles_id_tenant UNIQUE (id, tenant_id)` (INPLACE). **V8** `V8__rbac_user_roles_role_tenant_fk.sql`: one `ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_role_tenant FOREIGN KEY (role_id, tenant_id) REFERENCES roles (id, tenant_id)` (COPY). One statement per file (RC-40.4); `fk_user_roles_role` kept; no entity change; no grant change. The optional `users` composite FK is declined (TM §11.4).
- **(b) B7 footer template** published with one placeholder, `{{INSERTED_PERMISSION_IDS}}`, in two variants (pre-V9; V9-and-later adding `r.deleted_at IS NULL`), plus the custom-admin exposure check and cache flush as template comments (design §4.7, §10.7).
- **(c) B7 scanner** (unit test over `db/migration/V*.sql`): detection of a `permissions` insert is case-insensitive and variant-aware (`insert into`, `INSERT IGNORE INTO`, `REPLACE INTO`, backticked or schema-qualified; RC-40.3); such a file must contain both footer statements; statement (a)'s exclusion list must equal **exactly** the ids that file inserts (RC-48.1); from V9 on, (a) must filter `deleted_at IS NULL`.
- **(d)** `JpaUserRoleRepository`'s T-S1 Javadoc (`:30-35`) records the DB backstop.

**ACs covered:** B2 (FR-B2.a, FR-B2.b), B7 (FR-B7.a). Test scenario TS-12.

**Dependencies:** T-001 (V6 is the scanner's first positive case).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java` (Javadoc)
- Tests: `rbac/application/RoleResolutionServiceIT.java` (`:162-183` rewritten), `rbac/RbacSchemaMigrationIT.java`

**Files created:**
- `nexus-backend/src/main/resources/db/migration/V7__rbac_roles_id_tenant_unique.sql`
- `nexus-backend/src/main/resources/db/migration/V8__rbac_user_roles_role_tenant_fk.sql`
- `nexus-backend/src/main/resources/db/templates/permission-migration-footer.sql` (outside Flyway's `db/migration` location)
- `nexus-backend/src/test/java/com/example/nexus/rbac/PermissionMigrationFooterScannerTest.java` + negative SQL fixtures under `nexus-backend/src/test/resources/db/footer-fixtures/`

**Complexity:** M (≈ 60–100 production lines of SQL and template; the scanner is the main test asset. One task because both halves protect the same thing: migration-time tenant and catalogue invariants).

**Risks:**
- **Locking.** V8's COPY rebuild blocks `user_roles` writes (assign, revoke, break-glass) for its duration; maintenance window on the checklist.
- **Migration failure.** MySQL DDL is not transactional; a failed file blocks every booting instance until `flyway repair` (RES-44). One `ALTER` per file keeps nothing half-applied.
- **Authorization.** A footer copied verbatim from V6 into a later file excludes the wrong ids and silently attaches nothing, demoting every custom administrator (T-T21 → T-E35); the exclusion-list check is the guard.
- `SET foreign_key_checks=0` is forbidden (it skips validating existing rows).

**Tests (written first):**
- `PermissionMigrationFooterScannerTest`: V6 passes; negative fixtures fail: a lowercase `insert into permissions` with no footer; `REPLACE INTO` and backticked `` `nexus`.`permissions` `` without footer; V6's footer copied into a file that inserts a different id (exclusion mismatch); a V9-numbered fixture whose statement (a) lacks `deleted_at IS NULL`.
- `RoleResolutionServiceIT` (**TS-12**): a raw `user_roles` insert whose `tenant_id` differs from the role's fails with an FK violation (replaces the test that deliberately inserted a mismatched row).
- `RbacSchemaMigrationIT`: both constraints exist; `fk_user_roles_role` still exists; `CrossTenantPermissionIT`'s seed survives.

**Definition of Done:**
- V7, V8, template and scanner in place; `./mvnw verify -DskipITs` green; ITs written. Version numbers confirmed at merge. No flag. One commit.

### T-022 — Permission strings come from one typed catalogue on both backend and frontend (B5)

**Milestone:** M8

**Description.**
- **(a) Backend.** `common.security.Permissions`: a final class with one `String` constant per catalogue entry (including `user:role:assign`) plus `ALL`. Every `@RequiresPermission` value and every service `requiredPermission` constant references it (`UserRoleController.java:62-63`, `RoleController.java:60-61`, `PermissionController.java:34`, `RoleAssignmentService`, `RoleManagementService`). No startup check (rejected: boot-time DB dependency).
- **(b) Frontend.** `shared/types/permission.ts` exports `type Permission = 'tenant:read' | … | 'user:role:assign'` and `PERMISSIONS: readonly Permission[]`. `HasPermissionDirective`'s input and `permissionGuard`'s `data.permission` read are typed `Permission`. The fake names `roles:read` / `users:delete` are fixed in code and specs. **The guard's runtime fail-open semantics do not change**; a new `app.routes.spec.ts` walks the route table and asserts every route using `permissionGuard` carries a `data.permission` in `PERMISSIONS`.

**ACs covered:** B5 (FR-B5.a, FR-B5.b, FR-B5.c). Test scenario TS-13.

**Dependencies:** T-020 (same controllers; avoids a second rebase), T-001 (catalogue includes `user:role:assign`).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java`, `RoleController.java`, `PermissionController.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `RoleManagementService.java`
- `nexus-frontend/src/app/core/guards/permission.guard.ts`
- `nexus-frontend/src/app/shared/directives/has-permission.directive.ts`
- Specs: `nexus-frontend/src/app/core/guards/permission.guard.spec.ts` (the four fail-open tests unchanged), `…/core/guards/permission-guard-contract.spec.ts`, `…/shared/directives/has-permission.directive.spec.ts`
- `docs/DEVELOPMENT_GUIDE.md` (`:107`, `:146` fake names only)

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/common/security/Permissions.java`
- `nexus-backend/src/test/java/com/example/nexus/common/security/PermissionsCatalogueTest.java` (Test 1, unit)
- `nexus-backend/src/test/java/com/example/nexus/rbac/PermissionsCatalogueIT.java` (Test 2, IT)
- `nexus-frontend/src/app/shared/types/permission.ts`
- `nexus-frontend/src/app/app.routes.spec.ts`

**Complexity:** M

**Risks:**
- **Authorization.** "Fixing" the guard's fail-open while typing it breaks a deliberate, pinned contract (RES-39, accepted); the route spec is the compensating control.
- Constants are inlined at compile time, so Test 1 must check annotation **values** found by classpath scan, not references.
- The TypeScript and Java lists are kept in step manually (documented in D4); Test 2 and the route spec fail on their respective sides when a referenced permission is unknown.

**Tests (written first):**
- `PermissionsCatalogueTest` (**TS-13**): every `@RequiresPermission` value on the classpath is in `Permissions.ALL`; a test-only handler with `"roles:read"` makes it fail.
- `PermissionsCatalogueIT`: `Permissions.ALL` equals `SELECT name FROM permissions` after Flyway.
- `app.routes.spec.ts` (Vitest): every `permissionGuard` route has a `data.permission` in `PERMISSIONS`; a fixture route with a non-member fails.
- Directive and guard specs updated for real names; the four fail-open tests unchanged.

**Definition of Done:**
- Backend `./mvnw verify -DskipITs` and frontend `npm run test:ci`, `npm run lint`, `npm run format:check` green.
- DEVELOPMENT_GUIDE fake names fixed (doc line). No flag. One commit.

### T-023 — A benchmark keeps or removes the Redis permission cache by a stated rule (B6)

**Milestone:** M8

**Description.**
- Add a test-only property that bypasses `PermissionCachePort` (a pass-through adapter selected by property) so the same build can run cache on and off.
- k6 against the staging topology (design §10.6): refresh at 50 RPS, users holding 1–5 roles, cache on versus off. **Keep** only if refresh p95 drops by ≥ 5 ms **or** mint-attributable MySQL QPS drops by ≥ 30%; otherwise **remove**; an inconclusive result (variance larger than the effect) defaults to **remove**.
- **Remove branch:** delete `PermissionCachePort`, `RedisPermissionCacheAdapter`, the permset keyspace, the bump script's `DEL` step and every eviction call; `RoleResolutionService` reads the DB on each mint; A9's epoch alone suffices. **Keep branch:** record that the Redis-write → permission-injection path is accepted under the RC-34 prerequisites (RC-34.2).
- The measured numbers are recorded as an ADR-0022 addendum.

**ACs covered:** B6 (FR-B6.a).

**Dependencies:** T-010 (epoch-keyed cache), T-014 (Redis prerequisites), M7 merged.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/PermissionCachePort.java` (deleted on remove)
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java` (deleted on remove)
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java` (bump script `DEL`, on remove)
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `RoleManagementService.java` (eviction calls, on remove)
- Tests: `rbac/application/RoleResolutionServiceTest.java`, `rbac/application/RoleResolutionServiceIT.java`, `rbac/infrastructure/cache/RedisPermissionCacheAdapterTest.java` / `IT.java` (deleted on remove), `rbac/RoleAssignmentCacheIT.java`, `rbac/TokenFreshnessIT.java`
- `docs/adr/0022-permission-token-freshness.md` (addendum only)

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/PassThroughPermissionCacheAdapter.java` (benchmark bypass; kept only if the cache is kept)
- `nexus-test/performance-test/scenarios/token-refresh.js`, `nexus-test/performance-test/tests/load/permission-cache-benchmark.js`

**Complexity:** S if kept, L if removed (A-7).

**Risks:**
- **Authorization (fail-open).** On the remove branch, leaving any eviction or epoch-key reference half-deleted can leave TS-9 green for the wrong reason; `TokenFreshnessIT` must still pass unchanged in intent.
- **Measurement.** Numbers from a shared CI runner are meaningless (k6 README); the run must be on the staging topology.

**Tests (written first):**
- Unit: the bypass adapter never stores or returns a cached set.
- k6 `permission-cache-benchmark.js`: both arms at 50 RPS; thresholds encode the decision rule and the result is attached to the PR.
- Remove branch: `TokenFreshnessIT` TS-9 and the §9.4 race test still pass with no cache; `RoleResolutionServiceIT` asserts a DB read on every mint.

**Definition of Done:**
- Decision made by the rule, numbers in the ADR-0022 addendum, chosen branch implemented; `./mvnw verify -DskipITs` green. No flag. One commit.

### T-024 — The denial throttle blocks only privileged and self-targeted changes, stores its state in Redis, and production refuses to start without the shared store (B8)

**Milestone:** M8

**Description.**
- **(a) Scope** (Decision 25): classification (M14 + M15) runs **before** the throttle decision (RES-33, Low, accepted: a throttled actor learns whether a target is admin-defining). When the actor is throttled, only requests that take the set lock (admin-defining target) or target the actor themself are blocked; others are evaluated normally, so authorized benign changes succeed (FR-B8.a).
- **(b) No audit flood** (RC-33.1): while throttled, an evaluated and **denied** request returns its 403 **without** a new `ROLE_ASSIGNMENT_DENIED` row; it increments `nexus.rbac.denial_throttled{operation}` and emits at most **one** WARN `RBAC_DENIAL_THROTTLED {tenantId, actorUserId, operation, suppressedCount}` per window. Denials before the throttle trips are recorded in full.
- **(c) Shared store.** A Redis-native `RoleChangeThrottlePort` adapter keeps the sliding window **and** the throttled-until marker in Redis (`nexus:rbac:throttle:{tenantId}:{actorUserId}`), closing RES-11's per-JVM map.
- **(d) Assertion.** `nexus.rbac.throttle.require-shared-store` (default `false`; **`true` in `application-prod.yml`**, RC-45.1); `true` with `store-type=memory` fails startup.

**ACs covered:** B8 (FR-B8.a, FR-B8.b). EC8 (re-ordered, accepted as RES-33).

**Dependencies:** T-014 (`require-auth` in `application-prod.yml`), T-016 (classification), T-020 (same service, rebased).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RoleChangeThrottlePort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/RateLimitRoleChangeThrottleAdapter.java` (selected only for `store-type=memory`)
- `nexus-backend/src/main/resources/application.yml`, `nexus-backend/src/main/resources/application-prod.yml` (existing; T-014 also edits it)
- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js`, `nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js`
- Tests: `rbac/application/RoleAssignmentServiceTest.java`, `identity/infrastructure/security/RateLimitRoleChangeThrottleAdapterTest.java`

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisRoleChangeThrottleAdapter.java` + `RedisRoleChangeThrottleAdapterIT.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/ThrottleSharedStoreStartupAssertion.java` + test

**Complexity:** L

**Risks:**
- **Authorization / availability.** Writing a `REQUIRES_NEW` row per throttled denial re-opens US-016 T-D10 (pool pressure, audit flooding) (T-D18).
- **Locking/concurrency.** The throttle exists to bound set-lock acquisitions by unauthorized callers; a throttled actor must never reach M11 on an admin-defining target.
- **Concurrency.** Window and marker updates in Redis must be atomic (one script), or two instances disagree on "throttled".
- **Information disclosure (accepted).** RES-33's one bit.

**Tests (written first):**
- Unit `RoleAssignmentServiceTest`: throttled + benign target → proceeds and succeeds; throttled + admin-defining target → blocked; throttled + self-target → blocked; throttled + benign-but-denied → 403, **no** audit row, counter incremented, one WARN per window (second denial in the window logs nothing).
- `RedisRoleChangeThrottleAdapterIT`: two application contexts share the throttle (trip in one, blocked in the other).
- Startup: `require-shared-store=true` with `store-type=memory` fails; **RC-54(b):** the `prod` profile resolves `require-shared-store=true`.
- k6: pool-pressure test re-run as the M8 exit gate.

**Definition of Done:**
- Scope, audit suppression, Redis adapter and assertion in place; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

---

# M9 — Group C missing features (PR 10)

**PR boundary.** T-025 → T-030 on `feature/US-018/M9`, after M1 (new handlers classified from day one) and M8 (V7's `(role_id, tenant_id)` index for C3). Contains V9 (expand), which **runs in a maintenance window** (it rebuilds `roles`). Rollout order: code → grants per environment → (next release) V10 in T-031. New endpoints ride the existing `feature.nexus-us015-rbac-role-management` flag.

**Threats owned:** T-T17 (RC-35), T-T18 (RC-36), T-T20 (RC-46), T-I17 (RC-38), T-I19 (RC-40.7), T-D25 (RC-49.2), RC-37.5, RES-37, RES-45, L-5.

**Merge checklist (M9):**
- [ ] **Maintenance window** booked for V9 (`ALGORITHM=COPY` on `roles`; create/PATCH/DELETE blocked; recovery `flyway repair` then a re-run, RC-49).
- [ ] **Grants** `GRANT UPDATE (name, description, deleted_at) ON nexus.roles` applied per environment; the three ADR-0014 D6 artifacts byte-consistent.
- [ ] **`RolesPrivilegeIT` green as `nexus_app`** under both grant sets (RC-36.2).
- [ ] **RC-36.4 detector** `deletedRoleActiveAssignments` live, paging on > 0.
- [ ] `RoleDeleteConcurrencyIT` green, including the holder-less admin-defining case with **no 500** (RC-46.2); MC-9 green.
- [ ] **`audit:read` pre-deploy detection query** (custom roles carrying it, by tenant, ids only); a non-zero production count reviewed with Security before the flag flips (RC-38.3).
- [ ] Docs pass: C3 API docs and ADR-0021 state the administrator-roster disclosure (RES-37); the access-review runbook says reviewers are administrators or use the `ROLE_BREAK_GLASS_GRANT` join for `assignedBy = userId` rows (RC-37.5, R1-4); API changelog for C2 paging.
- [ ] RES-45 accepted (Low, Architect); revisit if the C1 1213 rate is ever non-zero.

### T-025 — A custom role with no active holders can be soft-deleted, and a concurrent assign can never attach a holder to a deleted role (C1 DELETE)

**Milestone:** M9

**Description.**
- **(a) V9 (expand)** `V9__rbac_roles_soft_delete.sql`: one `ALTER TABLE roles` with three clauses: `deleted_at DATETIME(6) NULL`; STORED generated `active_name VARCHAR(64) COLLATE utf8mb4_0900_ai_ci AS (CASE WHEN deleted_at IS NULL THEN name END)`; `UNIQUE INDEX uq_roles_tenant_active_name (tenant_id, active_name)`. `Role` gains `@Column(name = "deleted_at") Instant deletedAt` and entity-level `@SQLRestriction("deleted_at IS NULL")`; `active_name` is not mapped.
- **(b) Grants** in lockstep: `02-grants-post-schema.sql`, `nexus-app-provisioning.md`, `TestcontainersConfiguration`. `RbacDbPrivilegeHealthIndicator`'s `roles` leg accepts exactly this column set and still flags `UPDATE` on `is_system_role` / `tenant_id` / `id`, table-level `UPDATE`, and any `DELETE`.
- **(c) Conditional assign insert** (RC-36.1): the assign INSERT becomes native `INSERT INTO user_roles (…) SELECT … FROM roles WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`; zero rows → 404 `ROLE_NOT_FOUND`; the adapter supplies the UUIDv7 id; `uq_user_role_active` still maps to 409 `RBAC_004`. No locking read on `roles`.
- **(d) `DELETE /api/v1/roles/{roleId}`** (`@RequiresPermission(Permissions.ROLE_WRITE)`): resolve in tenant (404 missing, cross-tenant or deleted) → **role-subset** 403 (as detach, RC-35) → 409 `RBAC_003` for a system role → if R is admin-defining, **set lock first, M10' → M11** (RC-46 option (a)) → `UPDATE roles SET deleted_at = now WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL` (0 rows → 404) → `FOR UPDATE` read of active `user_roles` for the role; any row → 409 **`RBAC_009`** (rolls back) → `ROLE_DELETED` atomic audit (Group A, `recordRoleDeleted`) → 204. Role-subset denials use the detach posture (WARN, metric, no audit row).

**ACs covered:** C1 (FR-C1.b, FR-C1.c for DELETE, FR-C1.d). Test scenario TS-14.

**Dependencies:** T-004 (classification), T-016/T-017 (role-subset, M10'/M11), T-021 (V7/V8 numbering), T-006 (atomic audit).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/Role.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/RoleController.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RoleManagementPort.java`, `RbacAuditPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleManagementAdapter.java`, `JpaRoleRepository.java`, `JpaUserRoleRepository.java`, `JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java`, `…/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `nexus-database/mysql/init/02-grants-post-schema.sql`, `docs/runbooks/nexus-app-provisioning.md`, `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java`
- Tests: `rbac/RbacSchemaMigrationIT.java` (`:73-76` column list), `rbac/infrastructure/health/RbacDbPrivilegeHealthIndicatorTest.java` / `IT.java`, `rbac/RolePermissionsPrivilegeIT.java`, `rbac/RoleManagementIT.java`, `rbac/application/RoleManagementServiceTest.java`, `rbac/interfaces/rest/RoleControllerTest.java`, `rbac/interfaces/rest/RbacRoleManagementFeatureFlagTest.java`, `rbac/RoleAssignmentIT.java`

**Files created:**
- `nexus-backend/src/main/resources/db/migration/V9__rbac_roles_soft_delete.sql`
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RoleHasHoldersException.java` (409 `RBAC_009`, extending the existing conflict base) + test
- `nexus-backend/src/test/java/com/example/nexus/rbac/RolesPrivilegeIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleDeleteConcurrencyIT.java`

**Complexity:** L

**Risks:**
- **Locking/concurrency.** DELETE on an admin-defining role must take the set lock **before** the role row, as assign does, or the two deadlock with a 500 (T-T20). The remaining three-way classification-flip deadlock is RES-45 (accepted).
- **Privilege.** A `FOR SHARE` on `roles` would need `UPDATE` and fail in production while passing Testcontainers as superuser (US-016 D5 trap); the conditional insert avoids it, and `RolesPrivilegeIT` runs as `nexus_app` only.
- **Authorization.** Without role-subset any `role:write` holder can delete an admin-defining role they could never detach from (T-T17).
- **Migration.** V9 rebuilds `roles`; maintenance window on the checklist. To verify in IT: `updated_at ON UPDATE CURRENT_TIMESTAMP` needs no column privilege under column-scoped UPDATE.

**Tests (written first):**
- Unit `RoleManagementServiceTest`: order 404 → 403 → 409 `RBAC_003` → lock (admin-defining only, `InOrder` M11 before the `UPDATE`) → 409 `RBAC_009` with rollback → audit → 204.
- `RoleManagementIT` (**TS-14**): delete a custom role with an active holder → 409 `RBAC_009`; delete a system role → 409 `RBAC_003`; revoke then delete → 204, then GET → 404; **RC-35.2:** a non-administrator `role:write` holder deleting a holder-less admin-defining custom role → 403.
- `RoleDeleteConcurrencyIT`: assign versus delete raced 50 times, never an active row on a deleted role; **RC-46.2** assign versus DELETE of a holder-less admin-defining custom role: no 500 ever; each attempt ends in 201 then 409 `RBAC_009`, or 204 then 404.
- `RolesPrivilegeIT` (as `nexus_app`): pre-grant set → assign works, DELETE fails with a privilege error; post-grant set → everything works.
- `RbacDbPrivilegeHealthIndicatorTest` / `IT`: the exact column set is accepted; `UPDATE (is_system_role)` and any `DELETE` flagged.

**Definition of Done:**
- V9, grants (three artifacts), conditional insert, DELETE and indicator change in place; `./mvnw verify -DskipITs` green; ITs written.
- **L-5 doc line:** in `03-design.md` §11.1 the "Option (b) … would add a residual (RES-45)" sentence drops the id, so RES-45 means only the three-way flip. No new flag. One commit.

### T-026 — A soft-deleted role is invisible to every read, and an active holder of a deleted role pages (C1 soft-delete invariant)

**Milestone:** M9

**Description.**
- Native queries are not covered by `@SQLRestriction`; add explicit `deleted_at IS NULL` to M10', M11, M13, M14, the T-018 independent capture statement, `RoleResolutionService`'s two reads, `ZeroAdminTenantReader` / the health indicator SQL, and the CLI's `findRoleIdByName` (RC-36.3).
- Count-only detail `deletedRoleActiveAssignments` on `RbacZeroActiveAdminsHealthIndicator` (under the existing 30 s cache, excluded from probes); > 0 pages via the zero-admin alert path; no ids (RC-36.4).
- The tenant role cap (`max-roles-per-tenant`, 500) counts only non-deleted roles.

**ACs covered:** C1 (FR-C1.b correctness).

**Dependencies:** T-025.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`, `JpaRoleRepository.java`, `ZeroAdminTenantReader.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java`, `RoleManagementService.java`
- Tests: `rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorTest.java` / `IT.java`, `rbac/HeldPermissionPartitionIT.java` (MC-H' gains the soft-deleted role), `rbac/BreakGlassAdminIT.java`

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/SoftDeletedRoleVisibilityIT.java` (MC-9).

**Complexity:** M

**Risks:**
- **Authorization.** A native read that misses the filter lets a deleted role contribute permissions or administrator status; the primary control is still the "deleted role has no active holders" invariant, with the filters and the detector as defense in depth.
- The detector must stay count-only and inside the cached, probe-excluded indicator (US-017 RES-21).

**Tests (written first):**
- **MC-9** `SoftDeletedRoleVisibilityIT`: after soft-deleting a role, it is invisible to M13, M14, M10', M11, both `RoleResolutionService` reads, `ZeroAdminTenantReader` and `findRoleIdByName` (the C3 queries are added by T-029).
- MC-H' with a soft-deleted role in the matrix.
- Indicator IT: a hand-made active `user_roles` row on a deleted role → `deletedRoleActiveAssignments = 1`, no ids in the body.
- Role-cap unit: 500 roles of which one deleted → a create succeeds.

**Definition of Done:**
- Every listed read filters explicitly; detector live; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-027 — A custom role's name and description can be edited, bounded by the caller's authority (C1 PATCH)

**Milestone:** M9

**Description.**
- `PATCH /api/v1/roles/{roleId}` with `UpdateRoleRequest { name?: 1..64 (create's pattern), description?: 0..255 or null }`, at least one field → **200** `RoleResponse` (unchanged). Order: 400 `VALIDATION_FAILED` → 404 (missing, cross-tenant, deleted) → **role-subset 403** before any 409 (RC-35) → 409 `RBAC_003` system role → 409 `RBAC_006` active name taken → 409 `RBAC_007` reserved name. No `If-Match`.
- Atomic `ROLE_UPDATED` audit (`recordRoleUpdated`): changed field names, old name, new name; **never the description text**.
- A rename does not bump the epoch (cosmetic for authorization). CORS `allowedMethods` gains `PATCH` (`SecurityConfig.java:178`). Handler carries `@RequiresPermission(Permissions.ROLE_WRITE)`.

**ACs covered:** C1 (FR-C1.a, FR-C1.c for PATCH).

**Dependencies:** T-025.

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/RoleController.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RoleManagementPort.java`, `RbacAuditPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleManagementAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java`, `…/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`
- Tests: `rbac/interfaces/rest/RoleControllerTest.java`, `rbac/application/RoleManagementServiceTest.java`, `rbac/RoleManagementIT.java`, `rbac/RoleManagementAuditIT.java`, `config/SecurityConfigWebTest.java`, `rbac/interfaces/rest/RbacRoleManagementFeatureFlagTest.java`

**Files created:** `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/dto/UpdateRoleRequest.java` + `UpdateRoleRequestTest.java`.

**Complexity:** M

**Risks:**
- **Authorization.** Without role-subset a `role:write` holder renames an admin-defining role to "Read Only" so an administrator later assigns it believing it harmless (T-T17).
- **PII / log injection.** Description text never logged or audited; names keep US-015 D6's CR/LF-excluding allow-list.
- **Uniqueness.** Until V10, a deleted role's name still collides (409 `RBAC_006`), safe but restrictive.

**Tests (written first):**
- `UpdateRoleRequestTest`: empty body, both null, oversize, bad pattern → violations.
- `RoleControllerTest`: 200 path, 400s, flag off → 404/disabled per existing flag test.
- `RoleManagementIT`: system role → 409 `RBAC_003`; duplicate active name → 409 `RBAC_006`; reserved → 409 `RBAC_007`; **RC-35.2:** a non-administrator `role:write` holder renaming an admin-defining role to a benign name → 403.
- `RoleManagementAuditIT`: `ROLE_UPDATED` metadata has field names and old/new name, no description; audit failure rolls back the rename.
- `SecurityConfigWebTest`: CORS preflight allows PATCH.

**Definition of Done:**
- PATCH live behind the existing flag; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-028 — Role, permission and assignment lists are paginated per the API standard (C2)

**Milestone:** M9

**Description.**
- `GET /api/v1/roles`, `GET /api/v1/permissions`, `GET /api/v1/users/{userId}/roles` accept `page` (0-based, default 0) and `size` (default 20, max 100); out of range → 400 `VALIDATION_FAILED`, never clamped.
- Envelope `{ data, page: { size, number, totalElements, totalPages }, links: { next, prev } }`, `links` relative to `/api/v1/...`, always present.
- Stable sort: roles `(name, id)`, permissions `name`, assignments `(assignedAt, id)`. Repositories gain `Pageable` variants; reads non-locking.

**ACs covered:** C2 (FR-C2.a).

**Dependencies:** T-026 (role reads filter deleted roles).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/RoleController.java`, `PermissionController.java`, `UserRoleController.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/dto/RoleListResponse.java`, `PermissionListResponse.java`, `RoleAssignmentListResponse.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`, `RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`, `JpaPermissionRepository.java`, `JpaUserRoleRepository.java`
- Tests: `rbac/interfaces/rest/RoleControllerTest.java`, `PermissionControllerTest.java`, `UserRoleControllerTest.java`, `rbac/RbacRepositoryRoundTripIT.java`

**Files created:** `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/dto/PageMetadata.java` and `PageLinks.java` (shared envelope parts, used by C2 and C3).

**Complexity:** M

**Risks:**
- **Behaviour change.** Default 20 truncates lists that were complete (up to 500 roles); no consumer today, and `totalElements` / `links.next` make it visible.
- An unstable sort makes pages overlap or skip rows under concurrent writes.
- Tenant scoping must stay on every paged query (ids from the JWT).

**Tests (written first):**
- Controller slice tests: defaults, `size=100` ok, `size=101` → 400, `page=-1` → 400, `links.next`/`prev` correct on first, middle and last pages.
- Repository `Pageable` ITs in `RbacRepositoryRoundTripIT`: stable ordering, tenant scoping, deleted roles excluded.

**Definition of Done:**
- Three endpoints paginated; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

### T-029 — Access reviewers can list who holds a role or permission and a user's effective permissions, tenant-scoped, ids only, and a new registrant holds nothing (C3, C5)

**Milestone:** M9

**Description.**
- **(a)** New `AccessReviewController` (`rbac.interfaces.rest`), every handler `@RequiresPermission(Permissions.AUDIT_READ)`, behind `feature.nexus-us015-rbac-role-management`. Tenant from the JWT only.
  - `GET /api/v1/roles/{roleId}/holders?page&size` → paged `RoleHolder { userId, assignmentId, assignedAt, assignedBy }`; 404 `ROLE_NOT_FOUND` (missing, deleted, cross-tenant); **`assignedBy` redacted unless the caller is an administrator**, same rule and shape as `listActive` (R1-4).
  - `GET /api/v1/permissions/{permissionId}/holders?page&size` → paged `PermissionHolder { userId, viaRoleIds }` over distinct users ordered by `userId`; 404 `PERMISSION_NOT_FOUND`.
  - `GET /api/v1/users/{userId}/effective-permissions` → `EffectivePermissions { userId, permissions: [ { name, viaRoleIds } ] }`, unpaginated; 404 `USER_NOT_FOUND` (cross-tenant too).
- **(b) Queries:** a tenant-scoped, paged variant of `findActiveUserIdsForRole`; a permission-holders query driven by `role_permissions.permission_id`, then non-deleted tenant roles, then `user_roles` via the V7/V8 `(role_id, tenant_id)` index, paged over distinct users; effective permissions reuse `UserRoleQueryPort.findActivePermissionNames` plus role ids. All non-locking, filter `deleted_at IS NULL`, no new index.
- **(c)** INFO `RBAC_ACCESS_REVIEW_QUERY {actorUserId, tenantId, endpoint, subjectId}` and `nexus.rbac.access_review_query{endpoint}`. Responses carry ids only (no email, no name).
- **(d) C5 pin** (A-12): no code change to registration; `RegistrationIT` asserts a new user has zero `user_roles` rows, and `AccessReviewIT` asserts that user's effective permissions are empty.

**ACs covered:** C3 (FR-C3.a, FR-C3.b), C5 (FR-C5.a). Test scenario TS-15.

**Dependencies:** T-026, T-028 (paging envelope), T-019 (administrator redaction rule).

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`, `UserRoleQueryPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`, `JpaUserRoleQueryAdapter.java`, `JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java` (shared redaction helper)
- Tests: `identity/infrastructure/persistence/RegistrationIT.java`, `rbac/SoftDeletedRoleVisibilityIT.java` (MC-9 adds the three C3 queries), `rbac/interfaces/rest/RbacRoleManagementFeatureFlagTest.java`

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/AccessReviewController.java` + `AccessReviewControllerTest.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/AccessReviewService.java` + `AccessReviewServiceTest.java`
- DTOs `RoleHolderResponse.java`, `PermissionHolderResponse.java`, `EffectivePermissionsResponse.java` under `rbac/interfaces/rest/dto/`
- `nexus-backend/src/test/java/com/example/nexus/rbac/AccessReviewIT.java`

**Complexity:** L

**Risks:**
- **Authorization / information disclosure.** C3 is the first live use of `audit:read` and discloses the administrator roster (RES-37, Low, accepted); unredacted `assignedBy` would bypass row 16 (T-I17).
- **Tenant isolation.** Each query must scope by the JWT tenant and return 404 for foreign ids, consistent with B1.
- **PII.** Ids only; the client joins names under identity's own permissions.
- Paging over distinct users must not drop a user who holds the permission through several roles.

**Tests (written first):**
- `AccessReviewIT` (**TS-15**): two tenants, each endpoint returns only the caller's tenant; cross-tenant ids → 404; a revoked holder disappears; a deleted role → 404; `assignedBy` redacted for a non-administrator `audit:read` holder and present for an administrator; a user holding a permission through two roles appears once with both `viaRoleIds`; a freshly registered user has empty effective permissions.
- `RegistrationIT`: zero `user_roles` rows after registration (C5).
- MC-9 extended to the three C3 queries.
- Controller slice: `@RequiresPermission("audit:read")` on all three; paging bounds as C2.

**Definition of Done:**
- Three endpoints live behind the flag, classified by A8's rules; `./mvnw verify -DskipITs` green; ITs written. No new flag. One commit.

### T-030 — An `RBAC_001` 403 sends the user to the Access Denied page unless the caller opts out (C6)

**Milestone:** M9

**Description.**
- `api-error.interceptor.ts`: when `status === 403 && appError.code === 'RBAC_001'` and the request's `HttpContext` does not carry `SKIP_ACCESS_DENIED_REDIRECT`, call `router.navigate(['/access-denied'])`, then rethrow the `AppError` as today. **No query parameters** derived from server data (no `returnUrl`; RC-40.7). Filter-level `ACCESS_DENIED`, 401 and 404 do not redirect.
- Export `SKIP_ACCESS_DENIED_REDIRECT = new HttpContextToken<boolean>(() => false)` from `core/http`. Interceptor order (`correlationId, apiError, auth`) unchanged. Standalone, `inject()`, per `ANGULAR_STANDARDS.md`.

**ACs covered:** C6 (FR-C6.a).

**Dependencies:** none beyond M9's branch (independent of T-025..T-029).

**Files impacted:**
- `nexus-frontend/src/app/core/http/api-error.interceptor.ts`
- `nexus-frontend/src/app/core/http/api-error.interceptor.spec.ts`

**Files created:** `nexus-frontend/src/app/core/http/skip-access-denied-redirect.ts` (the context token; exported from the `core/http` entry point).

**Complexity:** S (≈ 30–50 production lines; the only frontend behaviour in Group C, so it cannot share a commit with a backend slice).

**Risks:**
- **Open redirect.** Any server-derived query parameter in the navigation puts this in the open-redirect class (T-I19).
- Navigation loops: `/access-denied` is unguarded and makes no API calls, and navigation is idempotent.
- Swallowing the error instead of rethrowing breaks components that handle 403 inline.

**Tests (written first, Vitest):** redirects on `RBAC_001`; no redirect on `ACCESS_DENIED`, on 401, on 404, or with the opt-out token; the navigation has no query params; the error still propagates to the subscriber.

**Definition of Done:** `npm run test:ci`, `npm run lint`, `npm run format:check` green. No flag. One commit.

---

# M9-contract — V10 (PR 11, the release after M9 is live everywhere)

**PR boundary.** T-031 alone, deployed only once M9's code (which filters deleted rows and uses the active-name key) is on every instance.

**Merge checklist (M9-contract):**
- [ ] M9 confirmed live on every instance; V10 version number confirmed at merge.

### T-031 — A deleted role's name can be reused (C1 contract step)

**Milestone:** M9-contract

**Description.** `V10__rbac_roles_drop_tenant_name_unique.sql`: `DROP INDEX uq_roles_tenant_name`. Uniqueness is then enforced only by `uq_roles_tenant_active_name` over non-deleted roles.

**ACs covered:** C1 (FR-C1.b, completes expand/contract).

**Dependencies:** T-025 deployed everywhere.

**Files impacted:** Tests `rbac/RbacSchemaMigrationIT.java`, `rbac/RoleUniquenessIT.java`, `rbac/RoleNameUniquenessConcurrencyIT.java`.

**Files created:** `nexus-backend/src/main/resources/db/migration/V10__rbac_roles_drop_tenant_name_unique.sql`.

**Complexity:** S (a one-statement contract migration; a separate release by the expand/contract rule).

**Risks:** dropping the index before every instance filters deleted rows would let two live roles share a name; the checklist gate is the control. Concurrent same-name creates must still collide on the active-name key.

**Tests (written first):** `RoleUniquenessIT`: delete role "Auditor", create "Auditor" → 201; two live "Auditor" roles still → 409 `RBAC_006`; `RoleNameUniquenessConcurrencyIT` unchanged and green; `RbacSchemaMigrationIT` asserts the index is gone.

**Definition of Done:** V10 applied; `./mvnw verify -DskipITs` green; ITs written. No flag. One commit.

---

# M11 — Group D documentation (PR 12)

No implementation tasks. M11 is delivered by the Phase 9 `/docs` pass after all other milestones are merged (design §12, "Lands last. No code"):
- **D1:** move the US-016/US-017 implementation-status sections into `docs/features/US-016|US-017/`; EPIC-002 keeps one line per story (including RES-1(b) as "self path closed; transformed into RES-26").
- **D2:** the stale statements (US-002 → US-009 as Epic 3 gate, story-point totals, US-013 "reads from the JWT", the `MEMBER` default matching C5); dated amendment notes on ADR-0008 and ADR-0016 (the "jti denylist implemented" error; the RC-34 Redis prerequisites under ADR-0016 D2) and on ADR-0014/0015 (V5's stale header comment).
- **D4:** `DEVELOPMENT_GUIDE.md` documents grant-subset rules and "administrator", the three access markers, token freshness (latency, 15-minute window, 503), `Permissions` constants and the migration footer, the frontend `Permission` type and `SKIP_ACCESS_DENIED_REDIRECT`.
- **D5:** traceability only; US-016/US-017 staging soak, RC-21 staging execution and RC-19 Ops sign-off stay on their own checklists.
- Proposed ADRs 0021–0025 move to Accepted as their milestones merge.

---

## Sequencing summary

M2 (T-001 → T-002 → T-003) → M1 (T-004) → M6 (T-005, deployed everywhere) → M4 (T-006) → M5 (T-007 → T-008) → M7 (T-009 → T-010 → T-011 → T-012 → T-013 → T-014) → M7b (T-015, once M7 has been everywhere ≥ 900 s; may overlap M3) → M3 (T-016 → T-017 / T-018 → T-019; after the M2 staging soak and its own re-pass) → M8 (T-020 → T-021 → T-022 → T-023 → T-024; V8 in a maintenance window) → M9 (T-025 → T-026 → T-027 → T-028 → T-029; T-030 independent; V9 in a maintenance window) → M9-contract (T-031, next release) → M11 (Phase 9 docs). Strictly one task at a time.

---

## Traceability 1 — Threat-model required changes and Low items → task

"Checklist" means the item is non-code (ops sign-off, runbook, alert definition) and sits on that milestone's merge checklist above. "Landed" means the design/ADR text change was already folded in at Gate 2; the task listed implements or preserves it.

| Item | Threat | Requirement (short) | Task(s) |
|---|---|---|---|
| RC-23.1 | T-E32 | RES-26 recorded; RES-1(b) "self path closed; transformed into RES-26" | Landed; T-002 (no "closed" wording in code); **M2 checklist**; M11 (D1 epic line) |
| RC-23.2 | T-E32 | Attach provenance WARN, counter, ticket/page | T-017 |
| RC-23.3 (R1-1) | T-E32 | Narrow provenance 409 `RBAC_010` | T-017 |
| RC-24.1 | T-D17 | Public endpoints never rejected; one source for "public" | T-004 (matcher), T-009 (filter) |
| RC-24.2 | T-D17 | Correct §9.5 / impact §7.2 claims | Landed; enforced by T-009 tests |
| RC-24.3 | T-D17 | Four `TokenFreshnessIT` cases | T-009 (three), T-011 (degraded-closed refresh); **M7 checklist** |
| RC-25.1 | T-E33 | Administrator status from M11's locked rows | T-016 |
| RC-25.2 | T-E33 | RES-27 restated | Landed; T-016 (paths that take no lock unchanged) |
| RC-25.3 | T-E33 | Keep T-E7 proof; harness-C race case | T-016; **M3 checklist** |
| RC-26.1 | T-E34 | Delete the false sentence | Landed; T-016 DoD (not reintroduced in comments) |
| RC-26.2 (R1-2) | T-E34 | Administrator requirement on revoke-subset and role-subset | T-016 (revoke), T-017 (detach), T-025 / T-027 (C1 reuse) |
| RC-26.3 | T-E34 | Row 19 rewritten; RES-28 | T-017 |
| RC-27.1 (R1-3) | T-E35 | Footer preserves admin-defining status | T-001 (V6), T-021 (scanner, template) |
| RC-27.2(a) | T-E35 | Corrected remedy sentence | Landed; **M2 checklist** (custom-admin exposure check) |
| RC-27.2(b)–(d) | T-E35 | Only if RC-27.1 rejected | Not applicable (RC-27.1 adopted, TM §11.3) |
| RC-28.1 | T-E36 | M13-independent self-assign capture, paging | T-018; **M3 checklist** (alert re-point) |
| RC-28.2 | T-E36 | MC-H' | T-018, T-026 (soft-deleted row) |
| RC-28.3 | T-E36 | Drop `self_role_assignment_total` ticket | T-018; **M3 checklist** |
| RC-29.1, .2 | T-E37 | Key TTL formula; startup assertion | T-009 |
| RC-29.3 | T-E37 | Key-expiry race IT | T-010 |
| RC-30.1 | T-E38 | Bounded replay queue | T-012 |
| RC-30.2 | T-E38 | Restated exposure argument | Landed; T-012 tests prove it |
| RC-30.3 | T-E38 | Incident-runbook step | **M7 checklist** |
| RC-31.1 | T-D20 | N ≥ 3 entry (refined by RC-41) | T-011 |
| RC-31.2 | T-D20 | 60 s sustained exit; flap page | T-011 |
| RC-31.3 | T-D20 | Reconcile paging | **M7 checklist** (alert table) |
| RC-31.4 | T-D20 | Restarts reset the window (recorded) | T-011 (risk recorded) |
| RC-31.5 | T-D20 | RES-30 owner; p99 early warning; Redis capacity runbook | T-009 (latency timer); **M7 checklist** (RES-30, alert, runbook) |
| RC-32.1, .2 | T-D19 | Family bucket in use case; per-IP failure bucket | T-013 |
| RC-32.3 | T-D19 | k6 in production ingress topology, both shapes | T-013; **M7 checklist** |
| RC-33.1 | T-D18 | Throttled denials write no audit row | T-024 |
| RC-33.2 | T-I18 | EC8 order disclosed (RES-33) | T-024 |
| RC-34.1 | T-T16 | Redis auth/isolation/TLS; startup assertion | T-014; **M7 checklist**; M11 (ADR-0016 note) |
| RC-34.2 | T-T16 | B6 consideration | T-023 |
| RC-35.1, .2 | T-T17 | C1 PATCH/DELETE role-subset; 403 ITs | T-025 (DELETE), T-027 (PATCH) |
| RC-36.1 | T-T18 | Conditional `INSERT … SELECT` | T-025 |
| RC-36.2 | T-T18 | `RolesPrivilegeIT` as `nexus_app` | T-025; **M9 checklist** |
| RC-36.3 | T-T18 | MC-9 coverage list | T-026, T-029 (C3 queries) |
| RC-36.4 | T-T18 | Deleted-role-holder detector | T-026; **M9 checklist** |
| RC-37.1 | T-S9 | Requester verification, second approver, ticket-id pattern | T-008 (pattern); **M5 checklist** (runbook) |
| RC-37.2 | T-S9 | Reuse refusal, exit 6 | T-008 |
| RC-37.3 | T-R14 | Kubernetes audit logging ≥ 1 year | **M5 checklist** |
| RC-37.4 | T-R15 | Page capture: flush wait, no `--rm`, drill, daily reconciliation | T-008 (flush wait); **M5 checklist** |
| RC-37.5 | — | Break-glass `assigned_by = target` reviewer note | **M9 checklist** (access-review runbook) |
| RC-37.6 | — | Web-context guard | T-008 |
| RC-38.1 | T-I17 | First live use of `audit:read` | Landed; T-029 |
| RC-38.2 (R1-4) | T-I17 | Redact `assignedBy` | T-029 |
| RC-38.3 | T-I17 | Roster disclosure documented; detection query | **M9 checklist** |
| RC-39.1 (R1-5) | T-R13 | Retry-buffer re-route: not adopted, reason recorded | T-020 (row dropped, not re-routed) |
| RC-39.2 | T-R13 | Rate ticket alert; WARN retention | T-020; **M8 checklist** |
| RC-40.1 | T-S10 | `sub` UUID; v3 `perm_epoch` shape; v3 freeze | T-005 |
| RC-40.2 | T-E39 | Web test: all flags, entry-point 401; UUID ArchUnit rule | T-004 |
| RC-40.3 | T-T19 | Variant-aware B7 scanner | T-021 |
| RC-40.4 | T-D21 | One `ALTER` per file (V7, V8) | T-021 |
| RC-40.5 | T-D22 | MC-4 Group B-after-Group A rule | T-006 |
| RC-40.6 | T-E40 | Rollback runbook pages Security | **M7 checklist** |
| RC-40.7 | T-I19 | C6 no query parameters | T-030 |
| RC-41.1, .3 | T-E43 | 3-in-10 s sliding window; F F S test | T-011 |
| RC-41.2 | T-E43 | `skipped_error` page; Recovering ticket | T-011 (metrics); **M7 checklist** (alerts) |
| RC-42.1, .3, .4 | T-E44 | Drain in every state; queue semantics; 2 s replay IT | T-012 |
| RC-42.2 | T-E44 | Separate bump timeout | T-009 |
| RC-43.1–.3 | T-D24 | Failure bucket in use case; no `isExhausted`; tests and NAT attacker | T-013 |
| RC-44.1, .3 | T-E45 | Matcher method+pattern, fail closed; equivalence test | T-004 |
| RC-44.2 | T-E45 | Permission-free principal on public requests | T-009 |
| RC-44.4 | T-E45 | Three `TokenFreshnessIT` cases | T-009 (two), T-011 (503 case) |
| RC-45.1 | RC-34 partial | `require-auth` / `require-shared-store` in `application-prod.yml` | T-014, T-024 |
| RC-45.2 | RC-34 partial | Dedicated factories from `spring.data.redis.*`; auth IT | T-009, T-014 |
| RC-46.1, .2 | T-T20 | DELETE takes set lock first; no-500 IT | T-025 |
| RC-47.1–.3 | T-S11 | Canonical pattern; global bound lookup; padded replay IT | T-008 |
| RC-48.1 | T-T21 | Template with one placeholder; scanner checks exclusion and `deleted_at` | T-001 (V6 uses it), T-021 |
| RC-48.2 | T-T21 | Every permission migration IT seeds a full-catalogue custom role | T-001 (V6 IT), T-021 (template step) |
| RC-49.1 | T-D25 | `flyway repair` runbook step, DDL user | **M8 checklist** |
| RC-49.2 | T-D25 | V9 maintenance window | **M9 checklist** |
| RC-50(a) | — | `RBAC_010` condition | T-017 |
| RC-50(b) | — | Independent statement groups by role | T-018 |
| RC-50(c) | — | Cross-tenant alert floor | **M8 checklist** |
| RC-50(d) | — | Bean-initialization web guard | T-008 |
| RC-51 | T-E46 | Reuse never gated by failure bucket | T-013 |
| RC-52 | — | Unconditional scheduling for probe and drain | T-011 (probe), T-012 (drain) |
| RC-53 | T-E47 | Only read-path failures drive the state machine | T-011, T-012 |
| RC-54(a) | — | Exit 2, `INVALID_ARGUMENT` row, no argument values | T-008 |
| RC-54(b) | — | `prod` resolves `require-shared-store=true` | T-024 |
| L-1 | T-E46 | "unrevoked" wording | T-013 (DoD doc line) |
| L-2 | T-E46 | Reuse-revokes-nothing test | T-013 |
| L-3 | T-E46 | Count through four layers, MySQL IT, not in response | T-013 |
| L-4 | T-E47 | Drain failure in Recovering keeps the 60 s sustain | T-012 |
| L-5 | — | RES-45 id fix in design §11.1 | T-025 (DoD doc line) |
| L-6 | — | §7.2 field-list exception for `INVALID_ARGUMENT` | T-008 (DoD doc line) |
| ✅ T-D23 | — | Uncapped fan-out accepted | T-010 |
| ✅ T-E40 | — | Mint order, attach-no-bump, v2 = 0, M6 accepts v3 | T-005, T-009, T-010 |
| ✅ T-E41, T-E42 | — | Accepted | T-002, T-001 |
| RES-6 | — | Log-retention sign-off | **M2, M3, M5, M8 checklists** |
| RES-26 | T-E32 | Owner confirmation | **M2 checklist** (recorded), **M3 checklist** (confirmed) |
| RES-30 | T-D20 | SRE + PM confirmation | **M7 checklist** |
| RES-11 | — | Closed by B8 at deploy | T-024; **M8 checklist** |
| RES-13 | — | Closed at M3 merge | T-003, T-017; **M3 checklist** |

Nothing in RC-23..RC-54 or L-1..L-6 is unmapped.

---

## Traceability 2 — Acceptance criteria → task

| AC | FRs | Task(s) |
|---|---|---|
| A1 | FR-A1.a–d | T-001 |
| A2 | FR-A2.a, b | T-001 (M2), T-016 (set-lock path after M3) |
| A3 | FR-A3.a | T-003, T-017 (name gate removed) |
| A4 | FR-A4.a–c | T-002, T-016 (administrator status from M11 rows) |
| A5 | FR-A5.a–d | T-016, T-017, T-018, T-019 |
| A6 | FR-A6.a–c | T-006 (C1 events extend it in T-025, T-027) |
| A7 | FR-A7.a–e | T-007, T-008, T-019 (definition switch) |
| A8 | FR-A8.a–c | T-004 |
| A9 | FR-A9.a–e | T-009, T-010, T-011, T-012, T-013, T-014, T-015 |
| A10 | FR-A10.a | T-010, T-012 |
| A11 | FR-A11.a, b | T-005, T-015 |
| B1 | FR-B1.a, b | T-020 |
| B2 | FR-B2.a, b | T-021 |
| B3 | FR-B3.a | T-020 |
| B4 | FR-B4.a | No task: ADR-0023 (drafted) accepted on the **M8 checklist** (A-11) |
| B5 | FR-B5.a–c | T-022 |
| B6 | FR-B6.a | T-023 |
| B7 | FR-B7.a | T-001 (first footer), T-021 (template and scanner) |
| B8 | FR-B8.a, b | T-024 |
| C1 | FR-C1.a–d | T-025, T-026, T-027, T-031 |
| C2 | FR-C2.a | T-028 |
| C3 | FR-C3.a, b | T-029 |
| C4 | — | **Out of scope (M10)**, Gate 1 OQ5 |
| C5 | FR-C5.a | T-029 (pin), T-019 (stale comment); EPIC-002 text in M11 |
| C6 | FR-C6.a | T-030 |
| D1 | FR-D1.a | M11 (Phase 9 docs, no task) |
| D2 | FR-D2.a | M11 (Phase 9 docs, no task) |
| D3 | — | T-019 |
| D4 | FR-D4.a | M11 (Phase 9 docs, no task) |
| D5 | FR-D5.a | M11 (traceability only, no task) |

Story test scenarios: TS-1 T-001 · TS-2 T-003 · TS-3/TS-4 T-002 · TS-5 T-006 · TS-6 T-007/T-008 · TS-7 T-004 · TS-8 T-009 · TS-9 T-010 · TS-10 T-005 · TS-11 T-020 · TS-12 T-021 · TS-13 T-022 · TS-14 T-025 · TS-15 T-029 · TS-16 each milestone's `/test-validate` (retirements under T-016..T-019 with re-pass sign-off).

---

## Open items (not mappable to a task)

| # | Item | Owner role |
|---|---|---|
| O-1 | The design's A2/A3 budget (< 10 ms p95 added) has no stated verification method; not a hot path under requirements §5, so no load test was added (G-2). | Architect |
| O-2 | No availability SLO for RBAC or the authorization path (G-3); RES-30 accepted without one. | SRE + PM |
| O-3 | Production revocation-latency p95/p99 target (requirements §13) is unset; only the IT's < 1 s exists (G-6). | PM + Platform Security Owner |
| O-4 | ADR numbering collision with existing `0019-tenant-fairness-and-quotas.md` / `0020-tenant-data-lifecycle.md` (A-2). **Closed at Gate 3:** renumbered to 0021–0025. | Architect |
| O-5 | Marker and tag names the design leaves unnamed and this breakdown chose (A-14, A-15); confirm at M3 `/review`. | Architect |


---

## Deviations recorded at M2 review

Recorded from `06-code-review.md` (T-001, T-002). Each is intentional; the reasons are sound.

1. **M15 hosting (T-002(b)).** The catalogue read (M15, `findCatalogueIds`) lives on `JpaPermissionRepository`, not `JpaRoleRepository` as the design and T-002(b) say. This avoids a tenant-isolation ArchUnit exemption for a read of the global `permissions` table.
2. **M14 signature (T-001(c)).** `findPermissionIdsForRole` / `findPermissionIdsByRoleAndTenantId` take `(roleId, tenantId)`, not `(UUID roleId)`. The tenant predicate satisfies `TenantIsolationArchitectureTest`; it is not an authorization control, and an empty result means no permissions or a tenant mismatch, so callers must first verify the role's tenant (`resolveRoleInTenant`).
3. **Adapter constructor (T-001/§4.3).** `JpaUserRoleAssignmentAdapter`'s constructor changed (§4.3 says unchanged): it now also injects `JpaPermissionRepository`. Its inherited `save`/`delete` methods are therefore reachable from the adapter; this relies on the DB grants (`nexus_app` holds `SELECT` only on `permissions`) rather than on the type. The optional narrow `PermissionCatalogueReader` interface was deliberately not created.

### Deviations recorded at the M2 security-review fix (`07-security-review.md` M-1, L-1, L-2, L-5)

4. **Revoke-subset pulled into M2 (M-1).** `revoke()` now runs the union check (M13 ⊇ M14) via `requireGrantWithinCallerHoldings(…, OPERATION_REVOKE, …)`, after the throttle and the legacy gate and before the last-admin 409 (design §5.3 places it in M3). Denial: 403 `RBAC_001`, one `ROLE_ASSIGNMENT_DENIED` row with `GRANT_EXCEEDS_CALLER`, `operation=revoke` and `missingCount`; the metric comes from the central handler only. The M3 administrator requirement on admin-defining targets is **not** included; the legacy gate still covers privileged targets in M2. The 404 still runs before the throttle (L-6, deferred).
5. **Fresh endpoint-permission check (L-1).** `assign()` (before A4/A2) and `revoke()` (before revoke-subset) deny with 403 `PERMISSION_ABSENT`, one denial row and a WARN `RBAC_ENDPOINT_PERMISSION_NOT_HELD` (ids only) when the caller's M13 rows no longer contain `user:role:assign`. `attachPermission` does the same for `role:write`, with no audit row (Decision 7, as for A3). Both checks reuse the existing M13 read, so there are no extra queries. The seeded ids live in the new `rbac.domain.RbacSeededPermissionIds` (V5/V6 literals). Consequence: service-level callers must actually hold the endpoint permission. IT fixtures that called the service with an actor holding no roles now grant that actor `user:role:assign` (or `role:write`) through a custom role.
6. **M14 fails closed (L-2), replacing deviation 2's precondition.** `UserRoleAssignmentPort.findPermissionIdsForRole` returns `Optional<Set<UUID>>`; empty means the role is not in the tenant, and the service denies (`CROSS_TENANT_TARGET`, no role name on the row). `JpaRoleRepository.findPermissionIdsByRoleAndTenantId` is now one `roles LEFT JOIN role_permissions` statement returning `List<UUID>`: no rows means not in tenant, and a single `null` row means no permissions. The adapter maps this to the `Optional`.
7. **M15 on a read-only repository (L-5), superseding deviation 3.** `findCatalogueIds()` moved from `JpaPermissionRepository` (now back to its pre-US-018 shape) to the new `JpaPermissionCatalogueRepository extends Repository<Permission, UUID>`, which declares nothing else. The assignment adapter injects that instead, so it has no `save`/`delete` on `permissions`. `TenantIsolationArchitectureTest`'s `UNSCOPED_ALLOWLIST` is unchanged (`Permission` has no `tenantId` field).
