# US-017 — Task Breakdown: Extend last-admin lockout protection to admin-equivalent custom roles

**Phase:** 4 (Task Breakdown) — Gate 3
**Epic:** EPIC-002 (RBAC Foundation)
**Inputs (both read in full, binding):**
- `docs/features/US-017/03-design.md` — **Revision 2**, Gate 2 Step A approved. D1–D25, MC-A…MC-J + MC-6, ADR-0018 D1–D8.
- `docs/features/US-017/03b-threat-model.md` — Gate 2 Step B, **CLOSED 2026-09-18** (§9.7). RC-15…RC-22 folded into the design; §9.4's four blocking fold-ins confirmed landed; §9.5's residuals (dangling §4.9 anchor, §4.3 heading count, §11.3 coverage gaps, editorial 5, benign-thread naming, the E20 typo, D23's pre-commit WARN timing) are **non-blocking** and are priced below rather than reopening Gate 2.

**Verification basis for this document:** `feature/US-017` on top of `QA-002` @ `5f74ac7` (design §0, verified). Every file path, existing method name and repository name below was re-read this session or is cited directly from the design's own code citations (`RoleAssignmentService.java`, `RoleManagementService.java`, `UserRoleAssignmentPort.java`, `JpaUserRoleRepository.java`, `RbacZeroActiveAdminsHealthIndicator.java`), not trusted from prose alone.

**Scope confirmed empty, stated rather than omitted (design §0 scope delta, re-confirmed at Gate 2):** **no Flyway migration, no schema/grant change, no new dependency, no REST/DTO change, no Angular file, no Redis, no new feature flag.** The Database and Frontend groups below are therefore intentionally thin — each carries one confirmation task or an explicit empty-group note, not silence.

**Grain note (revised for the Gate-3 consolidation).** This document was consolidated from an original 46-task breakdown into 8 implementation-sized units at the reviewer's request — a re-grouping, not a re-analysis: every requirement, risk, testing item and DoD bullet from the original breakdown survives inside a merged task below. `RoleAssignmentService.java` and `RoleAssignmentServiceTest.java` remain split across exactly **two** tasks, deliberately, even though both sit on the same class: **T-002** (`revoke()` — the widened lockout, the story's central risk) and **T-003** (`assign()` — the RES-10 fix, canary re-derivation, and the new promotion/instrumentation signals). Each is independently Large and independently the empirical proof of a distinct defect (D5's row-vs-holder correction vs. D7's acquisition-order fix); collapsing them into one task would obscure which proof obligation a given sub-item discharges. Mechanical controls that assert a single verb's property (MC-D, the `revoke()` half of MC-E) travel with T-002; the `assign()` half of MC-E and the harness-C reshape travel with T-003 — see each task's Description for the exact sub-item split.

**Per-task gate (per CLAUDE.md §4 and design §11.3):** from `nexus-backend/`, `./mvnw verify -DskipITs` (`mvnw.cmd` on Windows). New/changed `*IT` classes are written by the tasks that own them; the full `./mvnw verify` with Docker up, including the reshaped `LastAdminLockoutIT` harness C over **≥5 runs** (design §10.3 step 1/2), runs once in Phase 8 test-validate. No frontend gate — zero files under `nexus-frontend/` change.

---

## ⚠ Ambiguities resolved by judgment (read before starting T-001/T-003/T-007)

| # | Where | The ambiguity | Resolution taken (and why) |
|---|---|---|---|
| **A-1** | Design §9.2 / threat-model §9.5 item 7 | `RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN` (D23) is emitted "at the gate's pass point," which precedes the M2 duplicate check and the INSERT — so it can fire on a self-assignment attempt that subsequently 409s (`RBAC_004`) or rolls back. | **Emit it at the pass point, pre-commit, exactly as specified.** The threat model reviewed this explicitly (§9.5 item 7) and ruled it the *safe* direction for a detection signal (over-firing, never under-firing) and recorded that a future reader must not "fix" it by moving it post-commit without re-reading T-E28. T-003(c) carries this note verbatim so the implementer does not relocate it. |
| **A-2** | Design §9.2, `admin_equivalent_lock_set_size` | The `DistributionSummary` records "the number of rows M11 locked," but the design does not say whether that is recorded once per privileged call (both verbs) or only on `revoke()`. | **Record it once, immediately after M11 returns, on both verbs.** RES-17/RC-20.4 is explicit that the amplification is reachable from `assign()`'s denial path too (T-D14), and the instrument's whole purpose is a p99 across the population that actually acquires M11 — restricting it to `revoke()` would silently halve the sample the soak-derived threshold (§10.3 step 2) is computed from. Untagged, 1 series, per D15. |
| **A-3** | Design §11.2 MC-H | "the canary's M12-derived answer is computed from a **distinct** port method invocation from the gate's M10-derived set — verified by argument-captor or interaction count" leaves the assertion technique open. | **Interaction count via Mockito `verify(port, never()).findPermissionNamesForTenantRoles(...)` inside the canary-only test, and `verify(port, never()).findPermissionNamesForActiveAssignmentsOfUser(...)` inside the gate-only test path.** Cheaper and more direct than an argument captor for a "these two call sites never share a method" property, and it is the same technique MC-G already uses for M5b vs. the redaction helper. |
| **A-4** | Design §11.3 | `AdminEquivalentLockoutIT` is specified as "a dedicated class, not an extension of the already-1 059-line `LastAdminLockoutIT`" but the package/location is not stated. | **New file, same package and directory as `LastAdminLockoutIT`** (`nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalentLockoutIT.java`), reusing its `CyclicBarrier`/`Future`/outcome-counting harness shape and its Testcontainers base class verbatim, per the design's own instruction to reuse the shape without inheriting the file. |
| **A-5** | Design §4.8/§2 diagram (as landed post-Gate-2, §9.7 item 4) | `ZeroAdminTenantReader`'s package is named as `rbac.infrastructure.health` in the threat-model's illustrative interface sketch (T-T14) but the §2 architecture diagram places it in `rbac.infrastructure.persistence`, adjacent to the repositories it narrows access to. | **`rbac.infrastructure.persistence`, alongside `JpaUserRoleRepository`, which implements it** — the diagram governs (it is the artefact §9.7 confirmed was corrected at Gate 2 closure), and it keeps the interface next to the repository whose capability it narrows rather than next to its one consumer. |
| **A-6** | Design §4.1 | `carriesAll`'s spec ("per-name, case-insensitive `anyMatch`") does not state whether `null` elements in the input collection must be tolerated. | **Null-tolerant, mirroring the shipped `RbacDangerousPermissions.contains`'s null-safety** (§4.1 explicitly cross-references this: *"mirrors the shipped null-safe `contains`"*, MC-B assertion 3). A `null` element is simply never a case-insensitive match for any of the three names. |

---

## Epic: US-017 — group map

**Consolidation note (Gate 3 revision).** This breakdown originally shipped as 46 fine-grained tasks; the reviewer asked for 5–10 implementation-sized units instead. The map below reflects the consolidated 8-task structure. Consolidation is a re-grouping, not a re-analysis — every sub-item, risk, testing requirement and DoD bullet from the original 46 tasks is carried forward verbatim or near-verbatim inside the merged task that now owns it; each merged task's Description enumerates its constituent sub-items with a letter tag `(a)`, `(b)`, … so a reviewer can trace any original task's content to its new home. The original section boundaries (Database / Domain / Application / Infrastructure / Cross-cutting / Tests / Documentation) no longer align 1:1 with tasks, since several merged tasks span what were previously separate sections (e.g., T-001 folds the former standalone Database confirmation gate into its first sub-item).

```
Epic: US-017
├─ Database (migrations / schema)          — folded into T-001(a) (confirmation gate only; N/A by design §8.1/D10)
├─ Backend
│   ├─ Domain                              — T-001 (sub-items b–d)
│   ├─ Application                         — T-001 (sub-items e–f), T-002 (RoleAssignmentService.revoke()), T-003 (RoleAssignmentService.assign()), T-004 (RoleManagementService)
│   ├─ Infrastructure                      — T-005
│   └─ Interfaces (controllers)            — none (see note below)
├─ Frontend                                — none, both subgroups (see note below)
├─ Cross-cutting (security / flag / obs.)  — T-006
├─ Tests (load scenarios, e2e)             — T-007 (dedicated ITs); unit-test proof obligations for T-002/T-003/T-004 travel with those tasks
└─ Documentation                           — T-008
```

**Total: 8 tasks** — Domain+Port foundation (incl. schema-confirmation gate) 1 (T-001) · Application: RoleAssignmentService 2 (T-002 revoke, T-003 assign) · Application: RoleManagementService 1 (T-004) · Infrastructure 1 (T-005) · Cross-cutting mechanical controls & governance 1 (T-006) · Integration test suite 1 (T-007) · Documentation & governance close-out 1 (T-008).

### Empty groups — stated, not omitted

**Backend / Interfaces — no tasks, confirmed.** `UserRoleController` and `RoleController` are unchanged: no new endpoint, no path change, no request/response DTO change, no new error code, no versioning need (design §6.1). The only wire-adjacent change anywhere is the free-text `issue` string inside `/actuator/health` → `rbacZeroActiveAdmins`, whose **keys** are unchanged and which no `src/main` code parses — that string is rewritten as part of T-005(f) (the health-indicator rewrite), not as an interfaces-layer task. `UserRoleControllerTest` and `RoleControllerTest` need no edit.

**Frontend — N/A, confirmed, both subgroups.** Zero files under `nexus-frontend/` change (design §2, §6.1, re-verified against the codebase this session — impact §4). Services/state and Components/routes are both empty for the same reason: no Angular file, no new endpoint to consume, no DTO shape change. The one Epic-3 forward note in design §2 (a future role-management UI must treat 409 `RBAC_002` on revoking a **custom** role as a normal outcome, not only on `TENANT_ADMIN`) is already recorded in the design and needs no task here — it is Epic 3's problem, not this story's.

---

# Backend — Domain, Port & Shared Refactor

### T-001 — Domain + port foundation: schema confirmation, admin-equivalence predicates, new records, and the shared resolution refactor

**Description:** The foundation every other task in this story builds on. Six sub-parts, sequenced (a)→(f) internally.

**(a) Schema/migration confirmation gate** — a gate, not an implementation, mirroring US-016's T-001. Before any code task starts, confirm that every read this story adds — M10, M11, M5b, M12, and FR-2's two tenant-set queries — resolves against indexes that already exist in `V5__rbac_schema.sql`, so that no `V6__*.sql` is written for something the design already proves is covered and so ADR-0003's append-only rule is never engaged. Specifically confirm: `fk_user_roles_role` (M11's IN-list range and M5b's forced access path, and the removed M1's former access path); `pk_role_permissions (role_id, permission_id)` and `uq_permissions_name` (M10's driving join, and the basis of `carriesAll`'s "duplicates cannot occur today" argument, §4.1); `uq_roles_tenant_name` (FR-2 query (a)'s driving scan); `fk_user_roles_user` (M12's driving index, D24); `active_key`'s STORED-generated definition (M6's mutation target, referenced by §7.3's per-index restatement).

**(b) `RbacDangerousPermissions.carriesAny` / `carriesAll`** (D1, RC-18.1). Add two static combinators to the existing `RbacDangerousPermissions`, keeping `NAMES` as the sole definition of the set (§4.1).

- `carriesAny(Collection<String> permissionNames)` — `true` iff at least one element case-insensitively matches a member of `NAMES`. Straightforward; no fail-open shape exists for ANY.
- `carriesAll(Collection<String> permissionNames)` — **MUST be implemented as a per-name, case-insensitive `anyMatch`**, never a count (`filter(...).count() >= 3`, which returns `true` for `["user:write","user:write","user:write"]` — the caller-side fail-open trap T-E30 part 3 names) and never `containsAll` (case-**sensitive**, fails closed silently on a case variant like `Role:Write`). Null-tolerant (A-6): a `null` element matches nothing.

**(c) New `rbac.domain.RbacAdminEquivalence`** (D1, D2). New final class hosting the two named, deliberately different admin-equivalence predicates (§4.1), built only on `RbacRoleNames.TENANT_ADMIN` and (b)'s combinators — never redefining the permission set.

- `isAdminEquivalent(String roleName, Collection<String> permissionNames)` — target side: name match OR `carriesAny`. Identical in effect to the shipped US-016 gate condition (ADR-0017 D1).
- `isFullyAdminEquivalent(String roleName, Collection<String> permissionNames)` — caller side: name match OR `carriesAll`. **Strictly narrower.** Javadoc must carry, verbatim, the "never substitute one for the other; an ANY caller test is vacuous" warning (§4.1, ADR-0018 D2) — the sentence that stops a future engineer from "simplifying" the caller side into the target-side predicate.

No custom `toString()` on this class (it is stateless, all-static) — not applicable to the JaCoCo `toString()` trap this repo has previously hit on domain records, but note it for (d), which adds records.

**(d) New domain records `ActiveAssignmentHolder`, `RolePermissionName`** (D3, D6). Two JPQL constructor-expression projection records, mirroring `ActiveAssignmentRef`'s existing shape and rationale exactly — ids/names only, never entities, so a caller cannot load-mutate-save a `UserRole` from a locking read (§4.3, §8.3):

```java
public record ActiveAssignmentHolder(UUID assignmentId, UUID userId) {}
public record RolePermissionName(UUID roleId, String permissionName) {}
```

No custom `toString()` on either — the known JaCoCo `toString()` coverage trap on domain records applies; exercise by construction and accessor use only, per `ActiveAssignmentRef`'s own precedent.

**(e) `UserRoleAssignmentPort`: remove M1, add M10, M11, M5b, M12** (D3, D4, D24). The port-discipline sub-task. Remove `List<UUID> lockActiveAssignmentIds(UUID tenantId, UUID roleId)` (M1 — M11 with a singleton list is a strict superset; leaving it would ship a second, unused locking-read site). Add, with the full contract Javadoc from design §4.3 copied verbatim — load-bearing, not decoration, since it is the only record of several production-only failure modes:

- `List<RolePermissionName> findPermissionNamesForTenantRoles(UUID tenantId)` — M10. Javadoc must carry the capitalised **MUST NOT** cross this port as a `Set<String> dangerousNames` parameter in either direction (D3, ADR-0017 D2 upheld) and **MUST be non-locking / MUST NEVER be annotated `@Lock`** (`permissions` is `SELECT`-only for `nexus_app`; MC-A).
- `List<ActiveAssignmentHolder> lockActiveAssignmentHolders(UUID tenantId, List<UUID> roleIds)` — M11. Javadoc must state the **ascending order contract exactly**: unsigned byte-wise order of the 16-byte representation, matching MySQL's `BINARY(16)` comparison — **explicitly not** `UUID.compareTo`, which is signed on `mostSigBits` (D6, RC-20.7/T-D15 part 3 — the sentence MC-E's own correctness depends on). Must state: driven off `role_id` (`fk_user_roles_role`) as an IN-list range, never `tenant_id`; MUST NOT join `Role`; returns ids only, never entities; must be called inside an active transaction.
- `boolean hasActiveAssignmentOfAnyRole(UUID userId, List<UUID> roleIds, UUID tenantId)` — M5b. Javadoc carries M5's non-negotiable contract verbatim (fresh, locking `FOR SHARE`, never a JWT claim, `FORCE INDEX (fk_user_roles_role)`) generalised to a set, **plus the editorial-4 correction**: the adapter must inspect only `.isEmpty()`/`.size()` and must never mutate the returned rows (carried from M5, per the threat-model's confirmed-landed Editorial 4). An empty `roleIds` means the caller MUST fail closed and MUST NOT call this method at all (D9, R-10/T-E18 precedent).
- `List<RolePermissionName> findPermissionNamesForActiveAssignmentsOfUser(UUID userId, UUID tenantId)` — M12 (D24). Javadoc must state: exists solely to give the bypass canary a derivation sharing **no input** with the gate; MUST be driven off `fk_user_roles_user`; MUST be non-locking; **MUST NEVER be used for an authorization decision** — the gate's only determination is M5b (MC-G asserts this negative).

**(f) `RoleAssignmentService`: `resolveAdminEquivalentRoles` and the unified `privileged` predicate** (D1, D3, D5, D9). The prerequisite refactor both verbs build on. Add a small carrier type `AdminEquivalentRoles` (record: `adminEquivalentIds`, `fullyAdminEquivalentIds`, `namedAdminRoleId` — an `Optional<UUID>`) and:

```java
private AdminEquivalentRoles resolveAdminEquivalentRoles(UUID tenantId, Role targetRole, boolean nameMatch);
```

resolving from **one** M10 call plus M8, per the protocol in §7.2 — never two separate reads that could disagree (D9's fail-closed guarantee depends on this). Replace `carriesDangerousPermission(UUID roleId)` with a call to `RbacAdminEquivalence.isAdminEquivalent(role.getName(), port.findPermissionNamesForRole(roleId))` (M7, unchanged), so the gate's `privileged` condition and the target-side predicate become **the literal same function call** — FR-7 by construction. This is the change that makes revoke's lock-set construction (T-002), assign's canary (T-003) and the health indicator (T-005) all trace to one domain function.

**Dependencies:** none — do first.

**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RbacDangerousPermissions.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/domain/RbacDangerousPermissionsTest.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`

**Files created:** `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RbacAdminEquivalence.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/domain/RbacAdminEquivalenceTest.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/domain/ActiveAssignmentHolder.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RolePermissionName.java`, and their `*Test.java` companions

**Complexity:** L

**Risks:**
- (a) The risk removed by the confirmation step is a speculative `roles(name)` index (design §8.1's named contingency, explicitly **not** pre-bought) being added before the staging soak (§10.3 step 2) shows it is needed.
- (b) A count-based `carriesAll` compiles, is shorter, and passes every happy-path test — it only fails on the one input class MC-B exists to catch. Do not "simplify" it later without re-reading §4.1. M10 cannot produce a duplicate `(roleId, permissionName)` pair today (`pk_role_permissions` + `uq_permissions_name`), so this trap is **latent, not live** — do not treat "unreachable today" as "safe to implement carelessly."
- (c) Writing the two predicates as private methods on `RoleAssignmentService` instead of a standalone class would repeat exactly the mistake `RbacDangerousPermissions`'s own Javadoc warns against — two services and a health indicator now reason about admin-equivalence, and it must be directly unit-testable under the `rbac.domain` coverage gate, independent of any service's mocks.
- (d) Adding a custom `toString()` "for debuggability" reproduces the exact coverage-gap defect the JaCoCo gate has caught before on this codebase (SEC-3 precedent) — do not add one without a companion test.
- (e) **Interim non-compiling state, expected.** `JpaUserRoleAssignmentAdapter` will not implement the four new methods until T-005; proceed straight there rather than adding a `default` method (a stub returning empty would make M5b fail closed silently on every request and M10 make `privileged` permanently false — the gate silently disabled). Copying the Javadoc as a summary instead of verbatim loses the ascending-order definition, which is the exact thing revision 2's Gate-2 delta flagged as under-specified until it lands here in the code, not just in prose. Removing M1 without first confirming (a) that `LastAdminLockoutIT`'s references to it are being handled by T-002/T-003 leaves a dangling compile error with no assigned owner.
- (f) Building `AdminEquivalentRoles` from two separate port calls at two different call sites (rather than one method resolving both sets from one M10 read) reopens exactly the "M10 disagrees with itself" risk D9 closes. `privileged` computed from anything other than `RbacAdminEquivalence.isAdminEquivalent` (e.g., a hand-rolled `nameMatch || dangerousPermission` check left over from the pre-refactor code) silently reintroduces the FR-7 drift risk T-T15 names for the SQL side and would apply it to the Java side too.

**Testing requirements:**
- (a) Run `RbacSchemaMigrationIT` unmodified and confirm green. No new test.
- (b) Unit — **this is MC-B's foundation and must carry all three regression assertions verbatim from §4.1**: (1) `["user:write","user:write","user:write"]` ⇒ `carriesAll` is **false**; (2) `["Role:Write","USER:write","tenant:WRITE"]` ⇒ `carriesAll` is **true**; (3) exactly two of three present ⇒ `carriesAll` is **false**; plus `null`/empty-collection non-throwing cases for both methods, named as regression tests per MC-B (§11.2). Holds the `rbac.domain` 0.90 JaCoCo gate.
- (c) Unit — the ANY/ALL matrix over `{none, one, two, all three, case variants, empty, null} × {named TENANT_ADMIN, not named}` (§11.3). This is the four-shipped-403-ITs' underlying unit proof; it does not replace them (those live in T-004/T-007 as ITs).
- (d) Unit — construction + accessor coverage only, matching `ActiveAssignmentRefTest`'s existing shape.
- (e) None directly (an interface). Coverage supplied by T-005 (adapter delegation), T-002/T-003 (service unit tests against a mocked port), T-006 (MC-E/MC-F/MC-G).
- (f) Unit — `resolveAdminEquivalentRoles` against a mocked port returning a fixture role/permission matrix; assert the three derived sets are correct for a tenant with zero/one/two admin-equivalent roles.

**Definition of Done:**
- (a) `RbacSchemaMigrationIT` passes with zero modification; `git status` shows no file under `nexus-backend/src/main/resources/db/migration/`; the five index/constraint names above are confirmed present in `V5__rbac_schema.sql` with line numbers recorded in the task's completion note. Discharges design §8.1.
- (b) Both methods added; `NAMES` unchanged; all MC-B assertions present and named as regression tests; `./mvnw verify -DskipITs` green. Discharges design §4.1 and §11.2 MC-B's domain half.
- (c) Both predicates present with the verbatim "never substitute" Javadoc; full matrix covered; `rbac.domain` JaCoCo gate ≥ 0.90 maintained. Discharges design §4.1/D1/D2.
- (d) Both records present, no custom `toString()`, `rbac.domain` JaCoCo gate maintained. Discharges design §4.3/§8.3's "two new records" line.
- (e) M1 removed; M10/M11/M5b/M12 declared with §4.3's Javadoc verbatim, including the exact ascending-order wording; no `default` implementations; T-005 begins immediately after.
- (f) `AdminEquivalentRoles` carrier added; `resolveAdminEquivalentRoles` implemented per §7.2's protocol; `privileged` now calls `RbacAdminEquivalence.isAdminEquivalent` directly; `carriesDangerousPermission` removed with zero remaining callers. Discharges design §4.2 (the two new private-method declarations) and the FR-7-by-construction claim.

---

# Backend — Application (`RoleAssignmentService`)

### T-002 — `RoleAssignmentService.revoke()`: the widened lockout (the story's central risk)

**Description:**

**(a) `revoke()`: the widened lockout** (D5, D6, D15). The story's target-side heart. On the privileged path: acquire M11 over the ascending-sorted lock set (`adminEquivalentIds ∪ namedAdminRoleId ∪ {targetRole.getId()}`, per §7.2), then M5b (caller gate — 403 before 409, position unchanged), then compute:

```java
private static boolean wouldLeaveTenantWithoutAdminEquivalentHolder(
    List<ActiveAssignmentHolder> lockedHolders, UUID revokedAssignmentId);
```

— **distinct `user_id`s of the locked rows, excluding the row whose `assignmentId` equals the one being revoked** (D5). If empty, throw `LastAdminRoleException` (409 `RBAC_002`) — otherwise proceed to M6. `nameMatch`/`M7`-only paths (benign roles) cost **+0**: no M10, no M8, no lock (§7.2's "one condition, one call site" property preserved). Update `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`'s message text and add its new fields (`matchedOn`, `adminEquivalentRoleCount`, `lockedRowCount`) and the new counter `nexus.rbac.last_admin_lockout_blocked{matchedOn}` **beside** the existing coarse `nexus.domain.conflict{code="RBAC_002"}`, never editing `GlobalExceptionHandler` (§9.2, answers requirements Open Question 8).

**(b) Javadoc replacement** (§4.2). Replace, never delete (US-015 D13 / US-016 §12.2 item 7 discipline), the sentence at `RoleAssignmentService.java` (design-cited at `:138-140`/`:276-278`) that currently reads *"AC5's last-admin lockout still protects only the literally-named TENANT_ADMIN (RES-3), and the caller-side admin test remains name-based (RES-9)"* with the three-paragraph replacement text in design §4.2 **verbatim**: (1) RES-3/RES-9 closed for assign/revoke, with the "do not simplify the caller-side test to ANY" warning; (2) the mint-side asymmetry relocated-not-eliminated, **explicitly not a containment** (RC-16.1's corrected framing — do not write the pre-Gate-2 "the mint side staying narrower is the safe direction" language); (3) the RES-1(b)/T-E21 amplification note (RC-15.2) stating this change confers *caller-side* administrative capability, effective on the next request, not just admin-equivalent permissions at the next mint. **Sequencing note:** this Javadoc must describe the shipped behaviour of both verbs, so it can only be finalized after T-003 (assign) lands — implement (a) and its own tests first, then land this paragraph as the last step before closing this task's DoD.

**(c) MC-D unit coverage and inversions.** Invert the ~6 `verify(port, never()).lockActiveAssignmentIds(...)` assertions on the dangerous path (they encode today's "no lock on the non-name-match path" behaviour, which FR-1 changes by design) to `verify(port).lockActiveAssignmentHolders(...)`. Add **MC-D**: a unit assertion that one user holding two admin-equivalent roles counts once, and that excluding `ref.id()` still leaves that user a holder (D5's core defect, the one a naive per-role extension would ship). Add unit coverage for Edge Cases 1 (one user/two roles ⇒ counted once), 2 (two users/two roles ⇒ no lockout), 3 (deterministic core), 6 (no admin-equivalent role at all), 9 (403 before 409), 10 (negative baseline), 11 (404 before 403), 12 (lookup empty/throws ⇒ fail closed/500).

**(d) MC-E — the `revoke()` half: unsigned byte-wise ascending-order assertion.** An argument-captor assertion that the role-id list passed to M11 on `revoke()`'s privileged path is sorted by **unsigned byte-wise order of the 16-byte representation** matching MySQL's `BINARY(16)` comparison — **explicitly not** `UUID.compareTo`, which is signed on `mostSigBits`. An MC-E that merely asserts "sorted ascending" (i.e., accepts `UUID.compareTo`'s ordering) passes today but gives **false assurance** about the exact property D6 rests on — the precise defect the Gate-2 delta review caught still present in the design document itself before the fold-in (§9.4 item 2). The `assign()` half of this same control is T-003's; both halves land in `RoleAssignmentServiceTest.java`.

**Dependencies:** T-001. (Sub-item (b) and the full inversion/edge-case matrix in (c) describe both verbs' final shipped behaviour and should be finalized after T-003 lands — see the sequencing note in (b); this does not block starting (a), (c)'s revoke-only assertions, or (d).)

**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`

**Files created:** none

**Complexity:** L

**Risks:**
- **Row-vs-holder confusion is the exact defect D5 exists to prevent.** A `size() <= 1` row-count check (the naive extension) silently miscounts one user holding two admin-equivalent roles. MC-D is the mechanical tripwire — write it alongside (a), not after.
- M1's removal (T-001) means every call site that referenced `lockActiveAssignmentIds` must move to M11 in this same task; a partial migration leaves the code non-compiling, not partially correct.
- 403-before-409 must be preserved by construction (M5b's call must precede the lockout computation) — Gate 1 Resolution 2's binding requirement, re-verified by §6.2.
- Paraphrasing instead of copying §4.2 verbatim is exactly the failure mode the threat model caught at Gate 2 in the design document itself (§9.4 item 1) — a paraphrase here would repeat it in code, where it is even less likely to be re-reviewed.
- "Fixing" any of the four untouched 403 tripwires named in design §5.2 to assert success instead of 403 would silently undo US-016 — leave them byte-identical; a diff touching any of the four named test methods should be treated as a defect, not a refactor.
- Writing the comparator assertion against `Collections::sort`'s natural `UUID` ordering (i.e., testing that the list is sorted, without pinning *which* ordering) is a test that would pass under the wrong comparator and is exactly what MC-E exists to not do.

**Testing requirements:**
- Unit — MC-D (one user, two admin-equivalent roles ⇒ counted once; excluding `ref.id()` still leaves that user a holder); Edge Cases 1, 2, 3, 9 (403 before 409), 11 (404 before 403), 12 (M10 throws ⇒ propagate 500).
- Unit — argument captor on `port.lockActiveAssignmentHolders(...)` on `revoke()`, asserting the byte-wise comparator (a fixture pair of UUIDs that would sort *differently* under `UUID.compareTo` vs. unsigned byte-wise order if such a pair can be constructed within the id space in use, or direct comparator-object inspection if not).
- None directly for the Javadoc (documentation only). `/pre-pr-check`'s javadoc-lint gate, if any, must pass.
- Integration — covered by T-007's dedicated `AdminEquivalentLockoutIT` and T-003(f)'s reshaped harness C.

**Definition of Done:**
- `revoke()`'s privileged path uses M11 + the distinct-holder predicate; benign path is unchanged at the statement-count level; WARN fields and the new counter present; MC-D unit test green; four untouched 403 tripwires (§5.2) unmodified. Discharges design §7.2 (revoke half), §9.1/§9.2's lockout row.
- All three Javadoc paragraphs present verbatim per §4.2; no "safe direction" containment language anywhere in this class's Javadoc. Discharges design §4.2, RC-15.2, RC-16.1's code-side landing.
- All `never()` assertions inverted; MC-D present; full Edge Case matrix covered; the four §5.2 tripwires show **zero diff**. Discharges design §11.1 (inversions), §11.2 MC-D, §11.3's `RoleAssignmentServiceTest` bullet.
- Revoke-side ascending-order comparator asserted and verified as unsigned byte-wise 16-byte order (not `UUID.compareTo`). Discharges the revoke half of design §11.2 MC-E, RC-20.7 (ordering half).

---

### T-003 — `RoleAssignmentService.assign()`: the RES-10 fix, canary re-derivation, new signals, and the empirical exit gate

**Description:**

**(a) `assign()`: the RES-10 fix** (D7, D15). On the privileged path, acquire the **same** M11 union lock **first** — before M5b, before the M2 duplicate check, before the INSERT — making the acquisition order total across both verbs (§7.2, §7.3). This is check 4.5 preceding check 5 in §6.2's ordering table; **do not reorder it relative to M5b**, or D8's containment proof (ALL ⊆ ANY ⊆ lock set) collapses and the S→X hazard ADR-0017 D4 was written to prevent returns. Add `nexus.rbac.privileged_role_change_allowed{operation, callerMatchedOn}` at the gate's **pass** point (4 series, zero new queries — both values already in hand) and extend `nexus.rbac.privileged_revoke_lock_hold` with the `operation` tag (`assign`/`revoke`) and the `assigned`/`conflict` outcomes alongside the shipped `{denied, lockout, revoked, error}` — **`{operation="assign", outcome="denied"}` is a first-class series** (RC-20.2), not an incidental combination; it is the only direct measurement of RES-19.

**(b) Canary re-derivation via M12** (D24, RC-17). Replace the shipped US-016 canary derivation with:

```java
private boolean callerHoldsActiveAdminEquivalentRole(RoleChangeActor actor) {
  var views = userRoleAssignmentPort.findActiveAssignmentViews(actor.userId(), actor.tenantId());
  var permsByRole = userRoleAssignmentPort.findPermissionNamesForActiveAssignmentsOfUser(actor.userId(), actor.tenantId()); // M12
  return views.stream().anyMatch(a ->
      RbacAdminEquivalence.isFullyAdminEquivalent(a.roleName(), permissionNamesOf(permsByRole, a.roleId())));
}
```

Deliberately **not** the method `listActive` uses (D17's redaction helper stays untouched), and deliberately **not** reusing M10's tenant-scoped result — M12 is user-scoped, driven off `fk_user_roles_user`, so an over-broad M10 cannot silence this detector (§9.3). Alert PromQL for `nexus_rbac_gate_bypass_canary` and `nexus_rbac_admin_privileged_self_assignment` stays **byte-identical** — only the tag-value derivation changes.

**(c) D23 promotion signal + RC-16.3 log companion.** At `requireActiveTenantAdmin`'s pass point (see A-1 for timing), when `callerMatchedOn == ALL_DANGEROUS_PERMISSIONS` **and** the target role is the literal `TENANT_ADMIN`: emit WARN `RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN` `{tenantId, actorUserId, targetUserId, roleId}` and increment `nexus.rbac.admin_minted_by_non_named_admin{selfTarget}` (2 series; **page** when `selfTarget="true"`, per this repo's PromQL-driven page tier — `nexus_rbac_gate_bypass_canary` precedent). Separately, give `privileged_role_change_allowed` (a) a **log companion**: an INFO/WARN `{tenantId, actorUserId, targetUserId, roleId, roleName, operation}`, emitted **only** for the `ALL_DANGEROUS_PERMISSIONS` population (T-R11 — the metric alone has no subject to investigate from).

**(d) `admin_equivalent_lock_set_size` instrumentation** (RES-17, RC-20.4). A `DistributionSummary` (no tags — 1 series) recording the size of the list M11 returns, on **both** verbs, immediately after M11 executes (A-2). This is a plain instrument, not a threshold — the p99 alert and runbook action are soak-derived and land in T-008 (design §10.3 step 2), not here.

**(e) MC-E — the `assign()` half.** The sibling of T-002(d): an argument-captor assertion that the role-id list passed to M11 on `assign()`'s privileged path is likewise sorted by unsigned byte-wise order, never `UUID.compareTo` order.

**(f) Reshape `LastAdminLockoutIT` harness C: restore `assign(TENANT_ADMIN)`, add the benign thread** (RC-20.6) — **this fix's empirical exit gate.** Harness C's shipped fixture had the `assign(TENANT_ADMIN)` thread **removed** rather than the RES-10 defect fixed (US-016 §7.2, §12.3). (a) closes RES-10 at the root; this sub-item is its empirical exit gate. Restore the `assign(TENANT_ADMIN)` thread alongside `assign(dangerousCustomRole)`, `revoke(TENANT_ADMIN)`, `revoke(dangerousCustomRole)` and the denied non-admin `revoke` — **and add a new *benign* `assign(benignRole)`/`revoke(benignRole)` thread against the same users the privileged threads touch** (RC-20.6, §7.3's "the interaction is genuinely new" argument, and threat-model §9.5 item 5's confirmation this must appear in **both** §11.1's bullet and §10.3 step 1's exit criterion, not just the design's prose). Same `CyclicBarrier` shape, same "any unexpected exception type fails loudly" rule. Rewrite the RES-10 Javadoc block to record the closure rather than the workaround; update the `:522-525`-style "M1 is never invoked on this path at all" comment, which is now false. **Without the benign thread this sub-item is incomplete**, per the design's own reasoning: every other thread in the harness is privileged, so it would exercise only the privileged×privileged case D7's mutual-exclusion argument already covers, proving nothing about the privileged×benign remainder §7.3's per-index restatement leaves to inspection.

**Dependencies:** T-001, T-002. (Assign's M11 acquisition builds directly on the lock-set/ordering primitives (a)'s revoke implementation and T-002(d)'s ascending-order proof establish; (f)'s harness reshape needs both MC-E halves — T-002(d) and (e) here — in place before it can assert the acquisition order across the reshaped concurrency fixture.)

**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java`

**Files created:** none

**Complexity:** L

**Risks:**
- **The ordering is the whole point and must not be "optimized."** M11 before M5b is correct even though it means a non-admin `user:write` caller who will be denied forces a tenant-wide X lock first (T-D13/RES-19, accepted, bounded by US-016's D14 throttle — not this task's problem to fix, only to instrument).
- Forgetting to extend the lock-hold timer's tag set to include `assign` silently leaves RES-19 unmeasured, which is the one condition the threat model made non-negotiable (RC-20.2).
- `assign()`'s benign path must remain **+0** statements — verify no M10/M8/M11 call happens when `privileged` is false.
- Reusing `roles.fullyAdminEquivalentIds()` (M10-derived) instead of M12 for the canary would silently re-introduce the shared-input defect RC-17 exists to fix — the whole point of (b) is that the canary's data source is **not** in scope for reuse.
- The canary must remain strictly post-commit, non-locking, and never consulted for authorization (MC-G, T-006) — a refactor that moves this call earlier or feeds its boolean into `requireActiveTenantAdmin` would collapse the two independent mechanisms 07-security-review M-2 was written to keep apart.
- **Do not move the D23 WARN to post-commit "to avoid noise."** A-1 records the design's own ruling: pre-commit is the safe direction for a detection signal, and this is a threat-model residual explicitly left open rather than "corrected" (§9.5 item 7).
- Emitting the log companion for every `privileged_role_change_allowed` increment (both `ROLE_NAME` and `ALL_DANGEROUS_PERMISSIONS`) instead of only the newly-admitted population would put ids in logs for every admin action, which is unnecessary volume the design deliberately scopes down.
- Recording the lock-set-size metric only on `revoke()` (the naive reading of "the lockout's holder set") would halve the sample the soak needs, since `assign()`'s privileged path now acquires M11 too and is exactly the path T-D14 says makes this set large under the denial-path amplification.
- Writing the assign-side comparator assertion against natural `UUID` ordering rather than pinning the unsigned byte-wise comparator is the same trap T-002(d) exists to avoid, on the other verb.
- **If harness C still deadlocks with both additions, that is an Architect-level escalation, not a test to relax and not a licence to add a retry.** A bounded retry-on-deadlock wrapper is explicitly not pre-approved (design §7.3, §7.4).
- Adding the benign thread against a **different** set of users than the privileged threads touch would prove nothing about the privileged×benign interaction the task exists to test — it must touch the same users.
- This is US-016 RES-10's closure evidence and a **merge checklist item** (threat-model §8): if this harness is not green over ≥5 runs, the RES-10 entry reverts to an open, widened High and the story returns to Gate 2.

**Testing requirements:**
- Unit — assert `port.lockActiveAssignmentHolders(...)` is called **before** `port.hasActiveAssignmentOfAnyRole(...)` on the privileged `assign()` path (Mockito `InOrder`); assert the counter increments with the correct `callerMatchedOn` tag for both `ROLE_NAME` and `ALL_DANGEROUS_PERMISSIONS` populations.
- Unit — A-3's interaction-count assertion (`verify(port, never()).findPermissionNamesForTenantRoles(...)` inside the canary method's test).
- Unit — the D23 WARN and counter fire exactly when `callerMatchedOn == ALL_DANGEROUS_PERMISSIONS` and the target role name equals `TENANT_ADMIN`, and do **not** fire for a `ROLE_NAME`-matched caller or for an `ALL_DANGEROUS_PERMISSIONS` caller targeting a non-`TENANT_ADMIN` role (§9.5 item 3 residual). Also assert the log companion's field set and its `ALL_DANGEROUS_PERMISSIONS`-only scoping.
- Unit — assert the `DistributionSummary` receives a value equal to the locked list's size on both verbs.
- Unit — argument captor on `port.lockActiveAssignmentHolders(...)` on `assign()`, asserting the same unsigned byte-wise comparator as T-002(d).
- Integration — T-007's `AdminEquivalentLockoutIT` and canary acceptance IT exercise (a)/(b)/(c)/(d). This sub-item's own gate: ≥5 repeated Docker-up runs (mirroring RES-10's original 5/5 reproduction) with zero deadlocks, as the design's own mandatory exit gate (§7.3, §10.3 step 1/2).

**Definition of Done:**
- M11 acquired before M5b on `assign()`'s privileged path; `privileged_role_change_allowed` counter present with 4 series; lock-hold timer gains `operation` and the two new outcomes; `{operation="assign", outcome="denied"}` verified emitted in a unit test. Discharges design §7.2 (assign half), §7.3, §9.2's two new/changed metrics.
- Canary re-derived via M12; alert expressions unchanged (diffed against `monitoring.md`'s current PromQL); interaction-count test green. Discharges design §9.3, D24.
- D23 WARN + counter present with correct 2-series bounding; log companion present and correctly scoped; both unit-tested per above. Discharges design D23, RC-16.2/16.3, and the threat-model's §9.5 item 3 residual for D23's half.
- Lock-set-size metric recorded on both verbs immediately after M11; untagged; unit-tested. Discharges design §9.2's `admin_equivalent_lock_set_size` row (instrumentation half; alerting half is T-008).
- Assign-side ascending-order comparator asserted and verified as unsigned byte-wise order. Discharges the assign half of design §11.2 MC-E, RC-20.7 (ordering half).
- `assign(TENANT_ADMIN)` thread restored; benign thread added against the same users; ≥5 consecutive green runs recorded and attached to the PR as RES-10's closure evidence; stale comments/Javadoc rewritten. Discharges design §7.3, §11.1's harness-C bullet, §11.2's MC-C tie-in for cardinality, RC-20.6, and is the RES-10 merge-checklist item.

---

# Backend — Application (`RoleManagementService`)

### T-004 — `RoleManagementService`: symmetric detach gate and attach-side threshold signal

**Description:**

**(a) `detachPermission`: the new symmetric gate** (D13). Move the existing `findPermission(permissionId)` read **above** the delete (it already runs, just later — the statement count on the ordinary path is unchanged, per T-I14's verified analysis). Order becomes: `resolveRoleInTenant` (404/403) → `requireMutableRole` (409 AC7) → `findPermission` (Optional) → **if the permission exists and is dangerous** (`RbacDangerousPermissions.contains(permission.name())`, the existing single-name check, unchanged), `verifyCallerIsActiveTenantAdmin` (403, reusing M8+M5 — the shipped locking read, **not** a new one) → `detachPermission` (0 rows ⇒ 404) → post-commit audit. Add WARN `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED`, field-for-field mirroring the shipped attach-side marker. Replace (not delete) the Javadoc sentence *"No AC11 gate — detaching a permission reduces privilege, a deliberate asymmetry with attachPermission"* with the US-017 reasoning (§4.7): detaching a dangerous permission can flip a role out of admin-equivalence, which is now an input to a security guard. **One stated behavioural narrowing:** a non-admin detaching a dangerous permission that is **not** attached now receives 403 where it received 404 (§4.7, T-I14 — this removes an attachment-existence oracle rather than creating one; record it for the release notes, headline framed as "a non-admin can no longer detach a dangerous permission at all," per the threat model's Editorial 1 correction to §12.2 item 4, already landed in the design).

**(b) `attachPermission`: D22 threshold-crossing signal** (RC-15.3). On the dangerous-permission attach path only, **after** the attach commits its statement (but see risk note on transaction boundary), add **one** bounded M7 read (`findPermissionNamesForRole(role.id())`, already shipped and already used elsewhere on this same path for the holder-count signal) and evaluate `RbacAdminEquivalence.isFullyAdminEquivalent(role.name(), names)`. If it has just **become** true (i.e., was false before this attach — the third dangerous permission was the one just added), emit WARN `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` `{tenantId, roleId, roleName, holderCount, grantedBy}` and increment `nexus.rbac.role_became_fully_admin_equivalent{holders}` (bounded `holders` bucket, reusing US-016 D13's bucketing). **Ticket severity; page when `holders != "0"`** — this is the shape and justification of the already-shipped US-016 RC-8.3 holder-count signal, one query further, on the same admin-only path. This is the **scope decision the threat model escalated to the Architect and the Architect took**: it ships in this story, not as a named successor (design §0.1 RC-15, ADR-0018's amended "does not close" section).

**(c) `RoleManagementServiceTest`: D13 detach-gate matrix.** Unit coverage for D13's full response matrix (design §11.3, T-I14's verified analysis): detach of a **dangerous** permission by a non-admin ⇒ 403, with **no** `role_permissions` write; by an admin ⇒ 204; detach of an **ordinary** permission by a non-admin ⇒ 204 (the gate must not over-fire — this is the negative case that proves the gate is keyed correctly); unknown permission id ⇒ `ROLE_PERMISSION_NOT_FOUND`, **unchanged**. Also carries (b)'s own unit matrix: the WARN/counter fire exactly on the attach that makes `isFullyAdminEquivalent` transition false→true, and do **not** fire on an attach that keeps it false, keeps it true (already-ALL-three role gaining a 4th/5th permission — not applicable since the set is fixed at 3, but assert no double-fire on a role already at ALL-three receiving a benign permission), or is not dangerous at all (§9.5 item 3's D22 gap).

**Dependencies:** T-001 (uses `RbacAdminEquivalence.isFullyAdminEquivalent` from T-001(c); uses the shipped `RbacDangerousPermissions.contains` and the shipped `verifyCallerIsActiveTenantAdmin`/M8/M5 — no new domain or port surface beyond T-001).

**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleManagementServiceTest.java`

**Files created:** none

**Complexity:** L

**Risks:**
- Keying (a)'s gate on "is this the role's **last** dangerous permission" instead of "is the **detached** permission dangerous" would require a second read and still race — the design explicitly rejects the narrower condition (§4.7).
- `role_management_service_must_not_call_the_non_locking_admin_read` (the ArchUnit rule design §2 names) must stay green: this gate reuses `verifyCallerIsActiveTenantAdmin`, which is M5's locking read, not a new non-locking one.
- Moving `findPermission` up without also feeding it into the pre-existing audit-enrichment path leaves a duplicate read on the ordinary path — verify the single-read discipline against `RoleManagementService.java:255-266` before merging.
- **"Becomes true" must be computed correctly** in (b) — this requires knowing the role's admin-equivalence state immediately before the attach, not just after. The cheapest correct approach given "one bounded M7 read after the attach" is to compare against the permission set **minus** the one just attached (available in memory, since the attach method already knows which permission was attached) rather than a second read before-and-after — do this in-memory, not as a second query, to keep the "one query" cost claim true.
- Firing (b)'s signal on every dangerous-permission attach (not just the threshold-crossing one) would make it indistinguishable from the shipped holder-count signal and defeat its purpose (T-E27's "three separate WARNs do not compose into that fact for a human").
- (b) is a **new mitigation for a High-severity finding (T-E27)** — do not treat it as a minor addition; it is the single most consequential code change this delta introduces.
- Omitting the "ordinary permission, non-admin ⇒ 204" negative case in (c) would let a bug that gates on **any** `role:write`-holder detach (not just dangerous ones) pass silently — this is the case that proves the gate is scoped correctly, not just that it exists.

**Testing requirements:** Unit — (c)'s full matrix as described above, including the "no write on 403" assertion. Integration — (c)'s IT-level companion if the shipped test suite for `detachPermission` is IT-based (`RoleManagementAdminGateIT`/`RoleManagementIT`) rather than pure unit.

**Definition of Done:**
- (a) Gate present, positioned exactly as specified; `ROLE_PERMISSION_NOT_FOUND` contract preserved for unknown ids; new WARN present; Javadoc replaced (not deleted); the 404→403 narrowing documented in the task's completion note for release notes. Discharges design §4.7, D13.
- (b) Signal fires exactly on the threshold crossing; bucketed counter present; unit-tested per (c); §9.5 item 3's D22 gap closed. Discharges design D22, RC-15.3.
- (c) All four detach matrix rows covered and green, plus the D22 attach-signal matrix; the "no write on 403" assertion present. Discharges design §11.3's `RoleManagementServiceTest` bullet.

---

# Backend — Infrastructure

### T-005 — Infrastructure layer: repository queries, `ZeroAdminTenantReader`, adapter wiring, health-indicator rewrite

**Description:**

**(a) `JpaRoleRepository`: M10 query** (D4). Add `findPermissionNamesByTenantRoles(UUID tenantId)`, the comma-join JPQL constructor-expression from design §4.5:

```java
@Query("SELECT new com.example.nexus.rbac.domain.RolePermissionName(rp.id.roleId, p.name) " +
       "FROM Role r, RolePermission rp, Permission p " +
       "WHERE rp.id.roleId = r.id AND rp.id.permissionId = p.id AND r.tenantId = :tenantId")
List<RolePermissionName> findPermissionNamesByTenantRoles(@Param("tenantId") UUID tenantId);
```

No `@Lock` (MC-A), no `ORDER BY` (the caller builds sets). Comma-join JPQL, never native SQL, so `UuidV7Converter` handles the `UUID ↔ BINARY(16)` bind.

**(b) `JpaUserRoleRepository`: M11, M5b, M12; remove `lockActiveAssignmentsByRole`** (§4.6). Per design §4.6:

- **M11** `lockActiveAssignmentHoldersByRoles` — `@Lock(PESSIMISTIC_WRITE)`, JPQL constructor-expression, `WHERE ur.roleId IN :roleIds AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL` — **no `Role` join** (lock-scope discipline inherited verbatim from the removed M1).
- **M5b** `lockActiveAssignmentOfAnyRole` — native, `FORCE INDEX (fk_user_roles_role)`, `FOR SHARE`, IN-list over `byte[]` role ids.
- **M12** `findPermissionNamesForActiveAssignmentsOfUser` — non-locking JPQL, driven off `fk_user_roles_user` (D24) — a **different** statement, different index, different scoping from M10; must not reuse M10's query or delegate to it.
- Remove `lockActiveAssignmentsByRole` (M1's query) — zero remaining callers after T-001(e)/T-002/T-003.

**A named implementation risk from the design, not to be discovered later (§4.6):** a `@Lock`-annotated JPQL constructor-expression projection is legal in Hibernate, but the emitted `FOR UPDATE` on a projection needs verifying — T-006's MC-A asserts it; if it does not render, fall back to selecting the entity and mapping to `ActiveAssignmentHolder` in the adapter (the shape the removed M1 already used).

**(c) `JpaUserRoleRepository`: FR-2's two tenant-set queries; remove `findTenantsWithZeroActiveAssignmentsForRole`.** Per design §8.2, two non-locking JPQL queries, both carrying the `ur.tenantId = r.tenantId` cross-check (T-S1):

```java
List<UUID> findTenantsWithAnAdminEquivalentRole(@Param("adminRoleName") String adminRoleName, @Param("dangerousNames") Collection<String> dangerousNames);
List<UUID> findTenantsWithActiveAdminEquivalentHolders(@Param("adminRoleName") String adminRoleName, @Param("dangerousNames") Collection<String> dangerousNames);
```

Names arrive as bind parameters from `rbac.domain` via the caller (the health indicator, (f)) — **never hardcoded here** (D12). Remove `findTenantsWithZeroActiveAssignmentsForRole` (no remaining caller once (f) lands). Two flat set queries differenced in Java, not one correlated `HAVING`/`GROUP BY` statement — §8.2's stated reason: the tenant-level question ("does *some* admin-equivalent role have holders") is not equivalent to a role-level `NOT EXISTS` once a tenant can have more than one admin-equivalent role, and two flat queries are directly unit-testable with mocks.

**(d) New `ZeroAdminTenantReader` interface** (D25). A narrow, read-only interface, per A-5's package placement:

```java
public interface ZeroAdminTenantReader {
  List<UUID> findTenantsWithAnAdminEquivalentRole(String adminRoleName, Collection<String> dangerousNames);
  List<UUID> findTenantsWithActiveAdminEquivalentHolders(String adminRoleName, Collection<String> dangerousNames);
}
```

`JpaUserRoleRepository` additionally `implements ZeroAdminTenantReader` — **zero query changes, zero behaviour change** ((c)'s queries satisfy the interface as-is). This exists solely so `RbacZeroActiveAdminsHealthIndicator` (f) can depend on two read-only methods instead of the full `JpaRepository<UserRole, UUID>` surface (`save`/`delete`/`deleteAll`), eliminating T-T14/RES-22 rather than accepting it.

**(e) `JpaUserRoleAssignmentAdapter`: wire M10, M11, M5b, M12** (D3, D4). Zero new constructor dependencies (both repositories are already injected). M10 delegates to `roleRepository`; M11 and M5b and M12 delegate to `userRoleRepository`. M5b, like the shipped M5, is native, so the adapter converts `UUID → byte[]` explicitly for the IN-list using the existing `toBytes` helper — reused, not reimplemented. `JpaRolePermissionRepository` remains uninjected (ADR-0017 D2's second half, restated in this adapter's Javadoc with one added sentence per §4.4: M10 is hosted on `JpaRoleRepository` for the same reason M7 is).

**(f) `RbacZeroActiveAdminsHealthIndicator`: constructor to `ZeroAdminTenantReader`, detection logic rewrite** (D25, FR-2). **Constructor changed** to inject `ZeroAdminTenantReader` (d), not `JpaUserRoleRepository` directly — this is the fix for T-T14/RES-22 and must land in the same change as (d), not as a follow-up (the Gate-2 delta review's §9.4 item 4 finding is exactly this contradiction). Logic per §4.8:

```java
Set<UUID> tenantsWithAnAdminEquivalentRole = repo.findTenantsWithAnAdminEquivalentRole(RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES);
Set<UUID> tenantsWithAnActiveAdminEquivalentHolder = repo.findTenantsWithActiveAdminEquivalentHolders(RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES);
affected = tenantsWithAnAdminEquivalentRole minus tenantsWithAnActiveAdminEquivalentHolder;
```

The indicator does **not** go through the port (D12, unaffected by D25) and still passes `RbacRoleNames.TENANT_ADMIN`/`RbacDangerousPermissions.NAMES` directly. Rewrite the class Javadoc, the WARN message text (`tenant(s) with zero active admin-equivalent holders detected: tenantIds={}`), and the `issue` string (§8.2's exact rewritten text) — **keys unchanged** (`status`, `affectedTenantCount`, `issue` — FR-6). Retain: count-only actuator detail, full id list in the WARN only, `catch (DataAccessException) → UNKNOWN` (this posture is now **more** load-bearing, not less — two queries, four tables — and the apparent "fail-closed everywhere except here" contradiction must be stated explicitly in the class Javadoc so no reviewer has to rediscover it, per §8.2).

**Dependencies:** T-001.

**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java`, `RbacZeroActiveAdminsHealthIndicatorTest.java`

**Files created:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/ZeroAdminTenantReader.java`

**Complexity:** L

**Risks:**
- (a) The most likely naive implementation of M10 is "list the tenant's roles, then call M7 per role" — an N+1 the design explicitly names and rejects (§8.5). This query must be **one statement**.
- (b) Joining `Role` into M11 "to make the query more readable" would widen the lock beyond `user_roles` — explicitly forbidden (§4.3, §4.6). M5b and M11 both touching `fk_user_roles_role` must remain the **same** index for D8's containment proof to hold; verify via T-006's MC-C before considering this task done, not after. M12 must not accidentally share a query method with M10 "to reduce duplication" — that would silently undo D24's entire purpose.
- (c) Collapsing the two queries into one `HAVING COUNT(...) = 0` statement "to save a round trip" reproduces the fragility §8.2 explicitly rejects and makes the query much harder to unit-test. Dropping the `ur.tenantId = r.tenantId` predicate on either query (it is easy to omit since `ur.roleId = r.id` alone looks sufficient) reopens the exact cross-tenant leakage class T-S1 exists to close, now on a wider join surface than before.
- (d) Declaring this interface but leaving the health indicator's constructor untouched would repeat the exact defect the Gate 2 delta review caught in the design document itself (§9.4 item 4, "the component section contradicts the decision") — land (d) and (f) together, not as an independent, possibly-forgotten follow-up.
- (e) Injecting `JpaRolePermissionRepository` "for convenience" here would silently undo ADR-0017 D2/D4's entire point and reopen a write-capability leak the design explicitly re-verifies stays closed (§2, "zero new constructor deps"). Skipping the M12 delegation test is the exact gap the threat model's delta review flagged (§9.5 item 3, "no adapter delegation test for M12") — do not let this sub-item's completion pass without it.
- (f) Injecting `JpaUserRoleRepository` instead of `ZeroAdminTenantReader` "because it's already available" is the exact regression (d) exists to prevent — verify the constructor's declared type, not just that the two queries are callable. Changing `UNKNOWN`-on-error to `DOWN`-on-error "for consistency with the rest of the story's fail-closed posture" would page on every query timeout and train operators to ignore the one signal that means a tenant is locked out — explicitly the wrong direction (§8.2). The `issue` string is free text and unparsed by any `src/main` code, but `RbacZeroActiveAdminsHealthIndicatorTest`'s disclosure assertions check the **keys**, not the prose — do not let a rewrite accidentally add a new key.

**Testing requirements:**
- (a) Repository-level test confirming the query compiles against Hibernate metamodel and returns the expected projection shape for a fixture (unit-level with an in-memory/mocked `EntityManager`, or folded into (e)'s adapter delegation test if this repo's convention tests repositories only via the adapter).
- (b), (c) None directly beyond compilation; coverage supplied by (e) (delegation), T-006 (MC-A/MC-C/MC-E), T-007's new ITs.
- (d) Compile-time only; behaviour coverage is (c)'s and (f)'s/T-007's.
- (e) Unit — delegation tests for **all four** new methods (M10, M11, M5b, M12) including the `UUID → byte[]` IN-list conversion for M5b, in `JpaUserRoleAssignmentAdapterTest.java`. This is explicitly required, not optional, per the threat model's delta review residual.
- (f) Covered by T-007 (new dedicated IT) and by keeping `RbacZeroActiveAdminsHealthIndicatorTest`'s existing disclosure assertions (count key present, tenant ids absent, UNKNOWN-not-DOWN) green with updated mocks for the new constructor type.

**Definition of Done:**
- (a) Query present exactly as specified; no `@Lock`; roles with zero attached permissions correctly absent from the result (§4.5's stated, deliberate behaviour). Discharges design §4.5.
- (b) M11, M5b, M12 present exactly as specified; `lockActiveAssignmentsByRole` removed; `@Lock` fallback risk noted in the task completion note if triggered. Discharges design §4.6.
- (c) Both queries present with the tenant cross-check on each; old query removed; names never hardcoded in this file. Discharges design §8.2.
- (d) Interface declared with exactly two methods; `JpaUserRoleRepository implements` it with no new logic. Discharges design §4.8's D25 half, T-T14/RC-22.4.
- (e) Constructor unchanged (zero new deps); all four methods delegate correctly; M12's delegation test present (closing the §9.5 item 3 gap); `toBytes` reused, not duplicated. Discharges design §4.4, and the threat-model's residual on M12 adapter coverage.
- (f) Constructor injects `ZeroAdminTenantReader`; detection logic diffs the two tenant sets; Javadoc/WARN/`issue` rewritten per §8.2; disclosure assertions green; the fail-closed-everywhere-except-here posture stated explicitly in the class Javadoc. Discharges design §4.8, D10/D11/D12 (indicator half), and closes T-T14/RES-22.

---

# Cross-cutting (security mitigations, feature flag, observability)

### T-006 — Mechanical controls and security-property tests (MC-A, MC-C, MC-F, MC-G, MC-H, MC-I, MC-J), feature-flag confirmation, RC-19 governance

**Description:**

**(a) Feature flag confirmation: no new flag** (D19). Not an implementation — a confirmation that both verbs and `detachPermission` remain behind the two shipped default-off kill switches (`feature.nexus-us012-rbac-role-assignment.enabled`, `feature.nexus-us015-rbac-role-management.enabled`) with no new `@ConditionalOnProperty`, and that **FR-2 (the health indicator) is deliberately not flag-gated** — it takes effect in every environment on deploy, per D19's reasoning that a detection control behind a flag is one someone forgets to enable, and that this is the control that discharges "tenants already at zero" (§10.3 step 3, T-008).

**(b) MC-A: extend SQL-capture assertions to M10, M11, M5b, and FR-2's two queries.** The mechanical control preventing a `@Lock` on a `SELECT`-only-granted table from passing every superuser-connected IT and failing only in production. Capture the emitted SQL (reusing the shipped `captureHibernateSql` helper) for: M10 and FR-2's two queries — assert **neither** emits `for share` nor `for update`; M11 — assert it emits `for update` and does **not** join `roles` or `permissions`; M5b — assert it emits `for share` and `force index`.

**(c) MC-C: `EXPLAIN` plan stability for M11/M5b across IN-list cardinalities.** The re-derived MC-5. Run `EXPLAIN` via `JdbcTemplate` on M11 and M5b and assert `key = fk_user_roles_role` for **IN-list sizes 1, 2, and ≥ 20** — plan stability across cardinalities, not one fixture size (RC-20.7: D8's containment proof depends on the *plan*, not on one lucky fixture, since a 1-element and a 40-element IN-list can be costed differently by the optimizer and a full-scan fallback would acquire in primary-key order, breaking the argument).

**(d) MC-F: `requireActiveTenantAdmin` argument assertion.** Carry MC-3 forward to M5b's new arity: an assertion that `requireActiveTenantAdmin`/M5b is called with `actor.userId()` and the **caller-qualifying** set (`fullyAdminEquivalentIds ∪ namedAdminRoleId`), **never** `targetUserId` and **never** the target role id alone. The mechanical guard against both fail-open axes of T-E22, re-exposed by the widened method signature.

**(e) MC-G: canary/redaction helpers never used for authorization.** An assertion that `callerHoldsActiveTenantAdmin` (`listActive`'s D17 redaction helper) is **not** called from either verb's gate, and that the canary helper (`callerHoldsActiveAdminEquivalentRole`, T-003(b)) is **not** used for any authorization decision — asserted on **both** verbs, not at class level (three similarly-named helpers now exist: M5b the gate, the canary, and the redaction helper — MC-2 carried forward per D14/D17). Also assert M12 (T-001(e)/T-003(b)) is never called from an authorization path — the port Javadoc's "MUST NEVER be used for an authorization decision" made mechanical.

**(f) MC-H: M10 ↔ M7 equivalence IT, and canary-independence assertion.** Two related proofs, per design §11.2/§9.3: (1) **Equivalence** — over a fixture matrix of a tenant's roles (none / one / two / all three dangerous permissions; a zero-permission role; the literal `TENANT_ADMIN`; a foreign-tenant role), assert the partition computed from **one** M10 call equals the partition computed by calling the shipped, separately-tested **M7 per role**. M7 is the incumbent, already covered by US-016's tests; making the new bulk read prove itself against it is the cheapest bound on the single most load-bearing new statement in this story. (2) **Canary independence** — the canary's M12-derived answer is computed from a **distinct** port method invocation from the gate's M10-derived `callerSet`/`lockSet` — verified via A-3's interaction-count technique (`never()` assertions in each direction).

**(g) MC-I: Java ↔ SQL equivalence IT for the health indicator's predicate.** One integration test, over a fixture matrix of roles in one tenant (zero permissions; one/two/all-three dangerous; only benign; the literal `TENANT_ADMIN` with no permissions; a case-variant permission name), asserting that **the set of tenants the indicator reports** equals **the set of tenants for which no role passes `RbacAdminEquivalence.isAdminEquivalent` with an active holder**, computed independently in Java from the same fixture. This is the mechanical proof that D12's inline SQL (`r.name = :n OR EXISTS(... p.name IN :names)`) and the Java combinator have not silently drifted apart — the *set* (`NAMES`) crosses into SQL as a parameter and propagates automatically; the *combinator* does not, and this is what stands in for it (RES-23).

**(h) MC-J: health probe-group exclusion and actuator cache TTL config assertions.** Two config-level assertions, mechanizing the two "protected properties" §8.2 names: (1) `application.yml`'s `livenessState`/`readinessState` probe groups do **not** include `rbacZeroActiveAdmins` — a widened DOWN population (D11) must remain a **page**, never a container-eviction outage; (2) `management.endpoint.health.cache.time-to-live` remains configured at the M-2 value (30s) — the TTL that bounds an anonymous cross-tenant scan amplification on the `permitAll` `/actuator/health/**` path, now more load-bearing under FR-2's two-query, four-table form (RES-21).

**(i) RC-19 governance: WARN-marker retention mandate and the repeated-lockout ticket alert.** Non-code, merge-checklist-facing. Per design §9.4: mandate in writing, with the figure **named** (≥ 1 year, sourced from `docs/observability-standards.md`'s "Audit log is append-only… Retention: minimum 1 year"), that `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`, `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` (a **shipped US-016 marker** — this mandate deliberately reaches slightly outside US-017's blast radius, per §9.4's scope note) and `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED` (T-004) are retained at least as long as `auth_events`. **Ops sign-off is a merge-checklist item**, not a code gate. Add the new ticket-severity alert `increase(nexus_rbac_last_admin_lockout_blocked[10m]) > 2`, deliberately **platform-wide, not per-tenant** (a `tenantId` tag would be unbounded cardinality, which D15's bounded-series discipline forbids) — the runbook step (T-008) directs the operator to the WARN's `tenantId` field for attribution instead.

**Dependencies:** T-001, T-002, T-003, T-004, T-005 (these are fast-follow assertions on code the earlier tasks already wrote).

**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalenceEquivalenceIT.java` (name at implementer's discretion; must end in `IT`), `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/AdminEquivalenceSqlJavaEquivalenceIT.java` (name at implementer's discretion; must end in `IT`), `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/HealthProbeConfigurationIT.java` (or a `@SpringBootTest`-scoped unit test; implementer's discretion on the exact Spring type used to introspect the groups)

**Complexity:** L

**Risks:**
- (a) Adding a flag "to be safe" for FR-3's loosening specifically would create a rollback lever whose disabled state restores a state Gate 1 Resolution 2 explicitly rejected (a tenant whose last admin-equivalent holder is lockout-protected but cannot act) — D19's three-ground rejection of a new flag must not be silently revisited during implementation.
- (b) Asserting only "the query executes without error" instead of capturing and inspecting the literal SQL text would pass in every Testcontainers IT (which runs as a superuser) while still failing in production against `nexus_app`'s real, narrower grants — the exact failure mode MC-A exists to catch.
- (c) **A failing MC-C is an Architect-level escalation, not a test to relax.** If the plan is not `fk_user_roles_role` at any cardinality, D8's containment proof is false for that cardinality and the story's central safety claim (M5b's every requested lock is already held) does not hold — stop and escalate, do not adjust the assertion to match the observed plan.
- (d) A refactor that passes `targetUserId` by mistake at a call site (e.g., a copy-paste from the target-role resolution code just above) would compile cleanly and only fail this specific test — the one place this class of bug is caught before an IT with real concurrency obscures the signal.
- (e) With three similarly-named boolean-returning helpers on the same class, a future refactor swapping one for another compiles cleanly and is otherwise undetectable until an audit or an incident — this control is the only thing standing between that and production.
- (f) Skipping the fixture's foreign-tenant-role case would leave the equivalence proof silent about the one dimension M10's own tenant predicate (`r.tenantId`) is supposed to enforce.
- (g) A fixture missing the case-variant permission name would silently let the two small residual divergences named in the threat model (Java `equalsIgnoreCase` vs. `utf8mb4_0900_ai_ci`'s accent-insensitivity, T-T15) go unexercised — both are currently unreachable but should stay covered so a future schema change that makes them reachable is caught here first.
- (h) Testing this by string-matching `application.yml`'s raw text is brittle against reformatting; prefer introspecting the bound Spring configuration properties so the assertion survives an unrelated YAML reformat.
- (i) Treating this as "just a documentation edit" and skipping the actual Ops conversation is the exact failure this epic has now hit three times (US-015 RES-10, US-016 RES-6, and this story) — the code side (the counter) is already done by T-002; what remains is a real sign-off, not a sentence.

**Testing requirements:**
- (a) None (confirmation).
- (b) Integration, Docker up.
- (c) Integration, Docker up, three cardinalities minimum.
- (d) Unit — argument captor on the port call underlying `requireActiveTenantAdmin`, on both verbs.
- (e) Unit — interaction verification (never-called assertions) for the redaction helper and the canary helper from `assign()`/`revoke()`'s gate path, on both verbs; and for M12 from any authorization decision point.
- (f) Integration, Docker up, full fixture matrix.
- (g) Integration, Docker up, full fixture matrix including the case-variant case.
- (h) As described — this is itself the test.
- (i) None (governance). Verify the alert expression against the counter's actual metric name before it is committed to `monitoring.md`.

**Definition of Done:**
- (a) No new `@ConditionalOnProperty` introduced anywhere in this story's diff; both flags confirmed still gating `RoleAssignmentService`/`RoleManagementService`; the health indicator confirmed ungated. Discharges design §10.1, D19.
- (b) All five statements' SQL captured and asserted per above; control runs in the full `./mvnw verify` gate. Discharges design §11.2 MC-A (extended).
- (c) `key = fk_user_roles_role` asserted and green at all three cardinalities for both M11 and M5b. Discharges design §11.2 MC-C, RC-20.7 (plan half).
- (d) Both fail-open axes asserted against on both verbs. Discharges design §11.2 MC-F.
- (e) All three negatives asserted, both verbs. Discharges design §11.2 MC-G.
- (f) Equivalence proof green across the full matrix; canary-independence assertion green. Discharges design §11.2 MC-H, RC-17 part 2.
- (g) Equivalence proof green across the full matrix. Discharges design §11.2 MC-I, RC-18.2, RES-23.
- (h) Both properties asserted mechanically; a future PR that adds `rbacZeroActiveAdmins` to a probe group or shortens/removes the TTL fails this test rather than shipping silently. Discharges design §11.2 MC-J, RC-22.1–22.3, RES-21.
- (i) Retention figure named and sourced; all three markers covered; Ops sign-off obtained and recorded before merge; the platform-wide (not per-tenant) alert expression finalized and hand-off to T-008 for the actual doc edits. Discharges design §9.4, RC-19.

---

# Tests (load scenarios, e2e)

### T-007 — Integration test suite: `AdminEquivalentLockoutIT`, health-indicator IT, stale-JWT extension, canary acceptance IT, cross-tenant IT

**Description:**

**(a) New `AdminEquivalentLockoutIT`** (the story's central risk; largest single sub-item). Per A-4 and design §11.3: a dedicated new class. Two distinct admin-equivalent roles (one literal `TENANT_ADMIN`, one dangerous custom role) held by two distinct users; concurrent revocations of both; assert the tenant retains ≥ 1 admin-equivalent holder throughout and that no unexpected exception type surfaces. Reuse `LastAdminLockoutIT`'s `CyclicBarrier`/`Future`/outcome-counting shape and its "any unexpected exception type fails loudly" rule verbatim.

**(b) New health-indicator IT.** No IT exists today for `RbacZeroActiveAdminsHealthIndicator` — the current test is Mockito-only. Per design §11.3: DOWN when a tenant's **only** admin-equivalent role is a custom one that has been zeroed; UP when a dangerous custom role still has holders; UP when the literal `TENANT_ADMIN` has holders and a custom admin-equivalent role does not (**the tenant-level, not role-level, proof** — this is the case a role-level `NOT EXISTS` would get wrong, per §8.2's own reasoning for why two queries are differenced in Java); invisible when the tenant has no admin-equivalent role at all (D11, RES-14); count-only disclosure preserved end to end against a real database.

**(c) Extend `RoleAssignmentSecurityIT`: stale-JWT/out-of-band revocation on the new predicate** (T-S8). Extend the shipped stale-JWT + out-of-band-revocation IT to the **new caller-side predicate**: revoke the caller's **ALL-three custom role** (not the literal `TENANT_ADMIN`) out of band while the caller holds an unexpired JWT, and assert the gate still denies — proving M5b, like M5, is a fresh locking read and never derives admin status from a JWT claim. Revoking the literal role only would leave the new predicate genuinely untested (design §9.6/T-S8's own note).

**(d) Canary acceptance IT** (§9.3's mandatory acceptance test). A fully admin-equivalent, non-`TENANT_ADMIN`-named caller performs a privileged self-assignment; assert the canary series (`nexus_rbac_gate_bypass_canary`'s underlying `callerIsAdmin` tag) does **not** increment as `"false"` — i.e., the legitimate operation does not trip the page-severity alert the re-derivation exists to protect. This is explicitly **not optional** per §9.3.

**(e) Cross-tenant IT: M11's union lock never crosses a tenant boundary.** A fixture proving M11's lock set, built from a tenant-scoped M10 read plus the target role id, never locks or counts a row belonging to another tenant — more tables are in play than the shipped M1 (M10 joins `role_permissions`/`permissions`), and M11 carries no `Role` join, so tenant containment rests on the role-id set being tenant-derived by the caller plus `tenant_id` as a residual predicate (T-S1, T-I16 — recorded, not fixed, since `verifySameTenant` precedes every insert at the application layer and this is the SQL-layer confirmation of that boundary).

**Dependencies:** T-002, T-003, T-005.

**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`

**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalentLockoutIT.java` (also hosts (e)'s cross-tenant fixture, or a dedicated class, at implementer's discretion), `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorIT.java` (must end in `IT`), an integration test for (d) (added to `RoleAssignmentSecurityIT` or a new class; implementer's discretion, must end in `IT` if new)

**Complexity:** L

**Risks:**
- (a) This is explicitly named in the design as "the story's central risk and its largest single task" — under-resourcing it (e.g., testing only one admin-equivalent role, or only one user) would not exercise D5's distinct-holder correction at all, since a single-role, single-user fixture cannot distinguish row-counting from holder-counting.
- (b) Skipping the tenant-level UP case (literal `TENANT_ADMIN` has holders, custom admin-equivalent role does not) would leave §8.2's central design justification — "two flat queries, not one role-level `NOT EXISTS`" — with no executable proof that it was necessary.
- (c) Testing only the `TENANT_ADMIN`-name revocation path (the pre-existing case) and treating that as sufficient coverage would leave M5b's freshness property — the one thing this sub-item exists to prove — completely unverified for the predicate FR-3 actually adds.
- (d) Asserting this against a mocked port instead of a real self-assignment flow would not prove the property the design cares about — the acceptance test must run the real `assign()` path end to end.
- (e) A fixture that only ever creates roles within one tenant would never exercise the boundary this sub-item exists to prove — the fixture must include a same-named or similarly-shaped role in a **second** tenant.

**Testing requirements:** Integration, Docker up, real MySQL 8.4 Testcontainers, for all five sub-parts.

**Definition of Done:**
- (a) Green over the standard concurrency-IT run; tenant retains ≥ 1 holder in every outcome; zero unexpected exception types. Discharges design §11.3's `AdminEquivalentLockoutIT` item.
- (b) All four scenarios green against real MySQL. Discharges design §11.3's health-indicator IT item.
- (c) New scenario green, exercising the ALL-three custom role's revocation, not the literal role's. Discharges design §11.3's freshness item, T-S8.
- (d) Scenario green; `callerIsAdmin="true"` confirmed, `callerIsAdmin="false"` confirmed unreached. Discharges design §9.3's acceptance test, §10.3 step 2's soak-scenario prerequisite.
- (e) Cross-tenant fixture proves zero leakage across M11's lock set. Discharges design §11.3's cross-tenant item.

---

# Documentation

### T-008 — Documentation and governance close-out

**Description:**

**(a) `docs/features/US-012/monitoring.md`: three edits** (§9.5). (1) §3 `rbacZeroActiveAdmins` row — widened semantics, **and fix the pre-existing drift** (it still says the details include the `tenantIds` list, which US-012's own M-1 replaced with a count); (2) §2 `nexus_rbac_tenant_lockout_blocked` — meaning widens to "sole **admin-equivalent** holder," expression unchanged, add the new `last_admin_lockout_blocked{matchedOn}` counter and its ticket alert (T-006(i)'s expression); (3) §3 second edit — record the actuator 30s cache TTL as a named security control (T-006(h)/RES-21) and the liveness/readiness group exclusion as a protected property; (4) §5 — `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`'s widened field list, the "Zero active admins" row's widened semantics, new `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED` row.

**(b) `docs/features/US-012/runbook.md` §2: three breaks + the RC-21 forensic sweep SQL.** Fix three breaks in §2 — step 1 currently tells the operator to read `tenantIds` from the health detail (impossible since US-012's own M-1 replaced it with a count); step 2's confirmation SQL is `WHERE r.name = 'TENANT_ADMIN'` (now wrong post-widening — replace with the admin-equivalent form, `r.name = 'TENANT_ADMIN' OR EXISTS(...)` over the dangerous-permission set); step 6's O-5 speculation about "custom roles with `user:write`" is now first-class, not speculative. Add the "expect a DOWN on first deploy" note (§10.3 step 3). **Also land RC-21's forensic sweep as executable DBA SQL in this runbook** (design §10.3 step 3, per US-015 RC-6's discipline that an operator cannot invoke a Java port method): the point-in-time `auth_events` attribution query identifying who revoked which tenant to zero and when, to be run in **every environment where either feature flag was ever `true`**, with output retained as dated evidence per T-006(i)'s ≥1-year retention mandate, and a stated remediation-ticket-or-written-acceptance action per affected tenant before production deploy.

**(c) `docs/features/US-016/monitoring.md`: lock-hold timer edits + denial-marker retention row.** §1/§4 — the lock-hold timer's "a dangerous-custom-role revocation never participates" caveat becomes **false** and must be corrected; the timer gains `operation` and two outcomes (T-003(a)); the §4 baseline (still marked *PENDING* in US-016's own doc) must be **re-derived for the widened region and for `assign()`** from the staging soak (design §10.3 step 2) — this is where T-003(d)'s `admin_equivalent_lock_set_size` p99 threshold and ticket alert, and the `{operation="assign", outcome="denied"}` first-class series and its runbook entry (RES-19), land as **soak-measured figures**, not estimates. Add the **denial-marker row** (RC-19.1 scope note): record that `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` (a shipped US-016 marker) is now subject to T-006(i)'s ≥1-year retention mandate, so the two stories do not carry different retention expectations for the same marker.

**(d) `docs/features/US-016/runbook.md`: §3 deployment-prerequisite citation + §1 canary procedure update.** §3 — the `store-type=redis` instruction is **cited from US-017 §7.3 as a deployment prerequisite**, not general guidance — after T-003(a) ships, US-016's D14 denial throttle is the **only** bound on RES-19 (T-003(a)'s tenant-wide X lock acquired before the authorization decision), so RES-11(c)'s per-replica caveat becomes load-bearing for a multi-replica deployment of this design specifically, not just a nice-to-have optimisation. §1 — update the gate-bypass canary procedure to describe the re-derived `callerIsAdmin` (T-003(b), M12-sourced) and extend the "inside, not around" caveat to name the one thing still shared: the ANY/ALL combinator itself (`RbacAdminEquivalence.isFullyAdminEquivalent`), which both the gate and the canary call.

**(e) `docs/features/US-015/monitoring.md`: new `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` row.** Add the D22 signal (T-004(b)) alongside the shipped `dangerous_permission_granted{holders}` row it extends — same path (`attachPermission`'s dangerous branch), same admin-only reachability, **ticket with a page on `holders != "0"`**. Cross-reference RES-1(b) explicitly, both directions, per §9.2's instruction — the way a tenant acquires a dangerous role held by many users is RES-1(b)'s own step 3, and this signal is the moment that becomes visible.

**(f) `docs/features/US-016/03-design.md`: §6.4/§9.6/§12.3 status-flip edits** (RC-8.2 discipline). Per design §9.5, **record what closes and what survives; do not flip entries wholesale** (the exact discipline US-015's Gate 2 built and US-016's own Gate 2 applied to itself). RES-3 → **closed** by US-017 (FR-1 + FR-2, same predicate by construction). RES-9 → **closed by US-017 for the assign/revoke caller test only**, with the mint-side remainder explicitly **carried forward as US-017 RES-13** (not silently dropped, not silently marked fully closed). RES-10 → **closed by US-017 D7**, citing T-003(f)'s reshaped-and-restored harness C as the evidence, with the explicit caveat that closure is **conditional** on that harness being green over ≥5 runs (per the threat model's own "reverts to open, widened High" language). Edit §6.4/§9.6/§12.3 only — append/edit in place, do not touch anything above per this repo's append-only convention for shipped design docs.

**(g) `docs/features/US-017/03-design.md`: editorial fold-ins** (dangling anchor, heading count, npm-audit baseline). Three non-blocking residuals the threat model's delta review recorded (§9.5) and explicitly left open pending `/breakdown` rather than reopening Gate 2 for them: (1) D22 (§0.2) cites **§4.9**, which does not exist (§4 ends at §4.8) — either add a §4.9 or repoint the citation to §9.2, where D22's substance is actually specified; (2) §4.3's heading says "one method removed, **three** added" — M12 makes it **four** — correct the heading to match the body text, which already says four in the relevant sentences; (3) §12.1 does not yet carry Editorial 5's npm-audit baseline note — add one sentence recording the 27 pre-existing frontend toolchain findings (1 critical, 7 high, 16 moderate, 3 low, all in the Angular build/toolchain graph) as an **inherited baseline**, not attributable to US-017, so the Phase 7 code audit does not mis-attribute them. Note: a dependency-hygiene backlog item for those 27 findings is warranted **independently of this story** — file it if it does not already exist, but it is not this story's fix.

**(h) EPIC-002 status update, merge checklist, and Phase-8 doc placeholders.** The process items the design and threat model make merge-blocking, as explicit sub-items rather than DoD line items buried in a code task (US-016 T-023 precedent): (1) **`docs/story/2-rbac/EPIC-002.md`** — update the US-017 section to record implementation status and the Gate 2/Gate 3 outcomes, including that this story closes RES-3 end to end and RES-9 **for the assign/revoke caller test only**, with RES-13 carrying the mint-side remainder forward (mirror (f)'s discipline at the epic level). (2) **Record the merge checklist** (threat-model §8, reconfirmed at §9.7): RES-1(b)'s amplification is recorded with its inherited owner (Md Nisar Ahmed), 2026-11-27 review date and Epic-3 hard-expiry (already landed in the design per Gate 2 closure — confirm it, do not re-author it); RES-10's closure evidence (T-003(f), ≥5 green runs) is attached to the PR; RES-17/RES-18/RES-13's re-ratings are reflected in `03-design.md` §12.3 (already landed per §9.7 — confirm); RC-19's retention figure is named with Ops sign-off obtained (T-006(i)); RC-21's sweep output is retained as dated evidence with a remediation ticket or written acceptance per affected tenant before the production deploy step (b); `./mvnw dependency:tree` runs at Phase 7 (no manifest delta exists today, confirmed at Gate 2 — nothing to scan earlier). (3) **Note, do not create:** `docs/features/US-017/monitoring.md` and `docs/features/US-017/runbook.md` are **Phase 8** deliverables per this repo's convention that they document what shipped, verified against the code and the staging soak's measured figures — explicitly out of scope for `/breakdown`/Phase 4 and must not be drafted early from the design's intent (the same discipline (c) applies to the US-016 files it edits).

**Dependencies:** T-002, T-003, T-004, T-005, T-006, plus the Phase 8 staging soak for (c)'s measured baseline.

**Files impacted:** `docs/features/US-012/monitoring.md`, `docs/features/US-012/runbook.md`, `docs/features/US-016/monitoring.md`, `docs/features/US-016/runbook.md`, `docs/features/US-015/monitoring.md`, `docs/features/US-016/03-design.md`, `docs/features/US-017/03-design.md`, `docs/story/2-rbac/EPIC-002.md`

**Files created:** none (Phase 8 files explicitly deferred, not created here)

**Complexity:** L

**Risks:**
- (a) Fixing the pre-existing `tenantIds`-list drift is in scope here (the design explicitly calls it out) — do not skip it as "not this story's bug," since §9.5 makes it part of this required edit.
- (b) Writing the forensic SQL as a "suggested approach" instead of executable, copy-pasteable DBA SQL repeats the exact defect RC-21 was raised against — the population it enumerates may have been zeroed **before** US-016's gate existed, when `revoke()` had no admin check at all, so attribution is the entire point of the finding, not a nice-to-have.
- (c) Writing the lock-hold baseline and the lock-set-size threshold from the design's estimates instead of the actual staging soak numbers reproduces the design's *intent*, not the system's *behaviour* — this repo's `monitoring.md` convention exists specifically to prevent that (US-016 T-022's own precedent).
- (d) Describing the `store-type=redis` instruction as "recommended" instead of "a deployment prerequisite for this design" understates exactly what RC-20.1 corrected in the design document itself — the throttle's per-replica caveat is no longer background information once T-003(a) ships.
- (e) Omitting the RES-1(b) cross-reference would leave this signal's operational context ("why does this page, and why does it matter more than the shipped holder-count signal") undiscoverable to whoever is paged by it.
- (f) **Marking RES-9 "fully closed" instead of "closed for assign/revoke, RES-13 carries the remainder"** is the single highest-value error available in this sub-task — it is one word, it is plausible, and it deletes the register's only record of the still-open mint-side asymmetry. Treat any diff that removes RES-13's cross-reference as a defect. Editing anything above the amendment line in `03-design.md` breaks this repo's append-only precedent for shipped documents.
- (g) These are explicitly non-blocking per the threat model's own §9.7 disposition ("carry them into `/breakdown` rather than re-opening Gate 2 for them") — do not let this sub-task's small size cause it to be dropped; it is exactly the kind of low-visibility fix that a fast-moving implementation phase tends to lose.
- (h) Drafting `US-017/monitoring.md`/`runbook.md` now, from the design's estimates, would need to be rewritten wholesale once the Phase 8 soak produces real figures — better to defer entirely than produce a document that reads as authoritative but isn't.

**Testing requirements:** None (documentation/governance) throughout. Cross-check every metric name and alert expression against the code that emits it (a, c, d, e). Execute each forensic SQL statement once against a staging database and confirm it runs before considering (b) done — an unexecuted runbook query is not a control.

**Definition of Done:**
- (a) All four edits applied and cross-checked against T-002/T-004/T-005/T-006's shipped code. Discharges design §9.5's US-012/monitoring.md rows.
- (b) All three breaks fixed; the "expect a DOWN" note present; the forensic sweep's DBA SQL present, executed once, and every element of RC-21's four-part requirement (attribution, executable SQL, all-environments scope, evidence retention + stated action) present. Discharges design §9.5's US-012/runbook.md row and §10.3 step 3 / RC-21.
- (c) Timer caveat corrected; `operation`/outcome tags documented; baseline is a **measured** figure from the Phase 8 soak; `admin_equivalent_lock_set_size`'s threshold and alert present; `{operation="assign", outcome="denied"}` documented as first-class with its runbook pointer; denial-marker retention row present. Discharges design §9.5's US-016/monitoring.md rows, RC-20.4.
- (d) Both edits present; the "inside, not around" caveat names the shared combinator explicitly. Discharges design §9.5's US-016/runbook.md rows, RC-20.1.
- (e) New row present with the correct alert tiering and the bidirectional RES-1(b) cross-reference. Discharges design §9.5's US-015/monitoring.md row.
- (f) All three status flips landed with the RC-8.2 discipline (nothing flipped wholesale, RES-13 cross-referenced from RES-9's entry, RES-10's closure marked conditional on the harness evidence); nothing above the amendment section shows a diff. Discharges design §9.5's US-016/03-design.md row.
- (g) All three fold-ins landed; a dependency-hygiene backlog entry exists (filed or confirmed pre-existing) for the 27 npm-audit findings. Discharges threat-model §9.5 items 1, 2 and 4.
- (h) EPIC-002's US-017 section reflects the shipped, partial-closure scope; every merge-checklist item recorded and verifiable; both Phase-8 files explicitly noted as deferred, not drafted. Discharges design §10.3's rollout-step-4 documentation gate and the threat model's §8 merge checklist.

---

## Sequencing summary

1. **T-001** (domain + port foundation, includes the schema-confirmation gate as its first sub-item) — do first, no external dependency.
2. **T-002** (`revoke()` — the story's central risk) next, once T-001 lands; then **T-003** (`assign()` — the RES-10 fix, canary, and instrumentation), which depends on T-001 and on the lock-set/ordering primitives T-002 establishes. T-002's Javadoc and full edge-case matrix sub-items are finalized last, after T-003 lands (see T-002's sequencing note).
3. **T-004** (`RoleManagementService` gates) is independent of the T-002/T-003 chain — needs only T-001 — and can run in parallel with it.
4. **T-005** (infrastructure) needs only T-001; it must land before T-002/T-003 can be exercised against a real adapter, though unit tests against a mocked port can proceed earlier.
5. **T-006** (mechanical controls, feature-flag confirmation, RC-19 governance) follows T-001 through T-005 — these are fast-follow assertions on code the earlier tasks already wrote.
6. **T-007** (integration test suite) follows T-002, T-003 and T-005; it is this story's highest-risk, highest-value proof and should be sequenced as soon as those land, not scheduled last behind every mechanical control.
7. **T-008** (documentation and governance close-out) follows all code and test tasks, and for its lock-hold/lock-set-size baseline sub-item specifically, the Phase 8 staging soak — do not backdate a "measured" baseline from an estimate.
