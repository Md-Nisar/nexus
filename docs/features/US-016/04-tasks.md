# US-016 — Task Breakdown: Gate role assignment/revocation by actual privileges, not role name

**Phase:** 4 (Task Breakdown) — Gate 3
**Epic:** EPIC-002 (RBAC Foundation)
**Inputs (both read in full, binding):**
- `docs/features/US-016/03-design.md` — **Revision 2**, Gate 2 Step A approved. D1–D18, MC-1…MC-7, ADR-0017 verbatim in §13.2, file list in §15.
- `docs/features/US-016/03b-threat-model.md` — Gate 2 Step B, conditional pass; RC-8…RC-14 all folded into the design per its §14 traceability table.

**Verification basis for this document:** `feature/US-016` @ `76470e2`. Every file path, existing method name, test-class name and repository method named below was re-read this session, not trusted from the design. Where the design left something to "verify at implementation time", the verification result is recorded in the owning task (see T-005 on `Role`'s missing `permissions` association).

**Grain note.** Tasks are units of *implementable work*, not files and not ACs. Each is sized to be written test-first and validated in one pass. Several tasks touch the same file (notably `RoleAssignmentService.java` and `RoleAssignmentServiceTest.java`, three times each) — that is deliberate: the three passes are the gate, the lock-ordered revoke path, and the throttle, and each has a distinct proof obligation. Splitting them by file instead would produce one untestable mega-task.

**Per-task gate (per CLAUDE.md §4 and design §11.3):** from `nexus-backend/`, `./mvnw verify -DskipITs` (`mvnw.cmd` on Windows). Integration tests are *written* by the tasks that own them but the full `./mvnw verify` with Docker up runs once in Phase 8 test-validate. No frontend gate (design §2 — zero frontend change).

---

## ⚠ Ambiguities resolved by judgment (read before starting T-003/T-006/T-010)

These are places where the design and/or threat model do not fully determine the implementation. Each is resolved below so that `/implement` can proceed without a design decision, **but each resolution is flagged, not silent.** If the Architect disagrees, the affected task changes, not the story's scope.

| # | Where | The ambiguity | Resolution taken (and why) |
|---|---|---|---|
| **A-1** | Design §4.8 vs §2 diagram | §4.8 declares a **two-method** `RoleChangeThrottlePort` (`isThrottled`, `recordDenial`); the §2 architecture diagram labels the same edge **`tryConsumeDenial`** (one method). | **§4.8 governs** — it carries the normative Javadoc and the placement reasoning. The diagram's label is treated as a drafting artefact. Recorded in T-003. |
| **A-2** | Design §4.8 vs the shipped `RateLimitStore` | `RateLimitStore` exposes **only** `tryConsume(key, windowSeconds, maxAttempts)` — a *consume-and-report* operation with no non-destructive read (verified: `identity/application/port/out/RateLimitStore.java:25`, `InMemoryRateLimitStore.java:73-100`). `isThrottled()` is specified as a pure query. Implementing `isThrottled` as `tryConsume` would consume a slot **on every role-change request**, so N ordinary, successful role changes would trip a throttle that is specified to count **denials only** — a functional regression on admin bulk-assignment flows, and a silent widening of RES-11's blast radius. Design §15 lists `RateLimitStore` and both implementations as **unchanged**, so adding a `peek` to it is out of scope by the design's own file list. | **The adapter owns a bounded "throttled-until" map.** `recordDenial` calls `tryConsume(key, W, N)`; when the result is `!allowed`, the adapter records `now + retryAfterSeconds` for that key. `isThrottled` compares `now` against that entry (removing it when expired), consuming nothing. `RateLimitStore` stays unchanged. **Two consequences to accept explicitly:** the map is per-JVM (already true of the default `InMemoryRateLimitStore`, but it means the throttle does **not** become cluster-wide when `store-type=redis` — state this in the adapter Javadoc and in `monitoring.md`), and the map needs eviction-on-read plus a size bound. See T-006. |
| **A-3** | Design §4.8 / §9.2 | `RBAC_DENIAL_THROTTLE_ENGAGED` must be emitted **once, on the transition into the throttled state**, and must carry `operation` — but `operation` is known only to the service, and the transition is known only to the throttle, whose `recordDenial` is declared `void`. | **`recordDenial` returns `boolean`** ("this denial crossed the bound"), so the WARN is emitted at the service's gate throw site where `operation` and `RequestContext` are in hand, exactly once per transition. This is a one-word deviation from §4.8's verbatim signature and it is **port-visible**, so it is called out here rather than buried. The alternative (emit the WARN in the adapter, without `operation`) loses a field §9.2 mandates. |
| **A-4** | Design §4.1 vs §4.8 | §4.1 says `RoleAssignmentService`'s constructor gains **two `@Value` properties**; §4.8's port signature gives the *adapter* the only need for `maxDenials`/`windowSeconds` (they are `tryConsume`'s arguments). | **Both read the same two properties.** The adapter uses them as `tryConsume` arguments; the service uses them **only** as fields on the `RBAC_DENIAL_THROTTLE_ENGAGED` WARN (§9.2's field list requires them). One property source, two readers, no new config type — consistent with `InMemoryRateLimitStore`'s own `@Value` precedent. |
| **A-5** | Design §7.4 harness C | Harness C runs a **denied** non-admin `revoke(TENANT_ADMIN)` thread; the throttle (default `max-denials=5`) may suppress those denials mid-run and change what the harness proves. The design offers a choice ("set `max-denials` high enough, **or** assert the throttled 403 explicitly") without picking. | **Pick: raise `max-denials` for harness C via `@TestPropertySource`/`@DynamicPropertySource`, and assert the throttled 403 in a *separate*, single-threaded throttle IT (T-010's unit tests plus T-017).** Rationale: harness C exists to prove *lock* behaviour; letting the throttle suppress its denial threads would silently reduce the number of X-lock-then-403 paths exercised and make the harness pass for the wrong reason. Flagged as a **Risk on T-015**, and it is why T-010 is sequenced **before** T-015. |
| **A-6** | Design §4.5 | The M7 JPQL is given in two forms, with "verify at implementation time" whether `Role` has a mapped association to `RolePermission`. | **Verified this session: it does not.** `rbac/domain/Role.java` has five scalar fields and no collection mapping. **Use the two-entity comma-join form**: `SELECT p.name FROM RolePermission rp, Permission p WHERE rp.id.permissionId = p.id AND rp.id.roleId = :roleId`, hosted on `JpaRoleRepository` (D16). No entity change. Recorded in T-005 so the implementer does not re-derive it. |

---

## Epic: US-016 — group map

```
Epic: US-016
├─ Database (migrations / schema)          — T-001 (confirmation gate only; N/A by design §5.1)
├─ Backend
│   ├─ Domain                              — none (see note below)
│   ├─ Application                         — T-002, T-003, T-004, T-008, T-009, T-010, T-011
│   ├─ Infrastructure                      — T-005, T-006, T-007
│   └─ Interfaces (controllers)            — none (see note below)
├─ Frontend                                — none (see note below)
├─ Cross-cutting (security / flag / obs.)  — T-012, T-013
├─ Tests (concurrency, e2e, evidence)      — T-014, T-015, T-016, T-017, T-018
└─ Documentation                           — T-019, T-020, T-021, T-022, T-023
```

**Total: 23 tasks** — Database 1 · Domain 0 · Application 7 · Infrastructure 3 · Interfaces 0 · Frontend 0 · Cross-cutting 2 · Tests 5 · Documentation 5.

### Empty groups — stated, not omitted

**Database — N/A, confirmed.** Design §5.1 re-confirms zero schema change: M7 is a leftmost-prefix scan on the existing `pk_role_permissions PRIMARY KEY (role_id, permission_id)` (V5:49) bounded at 7 rows; M8 is an equality lookup on the existing `uq_roles_tenant_name` (V5:39); M9 drives off the existing `fk_user_roles_role`. No entity or mapping change, so `ddl-auto=validate` has nothing new to reject and ADR-0003's append-only migration rule is never engaged. `RoleAuditEvent`'s `holderCount` (D13) and the denial's `operation` (D17) both land inside the **existing** `auth_events.metadata` JSON column. **T-001 exists solely to make that a checked gate rather than an assumption** — the failure mode it prevents is somebody writing a `V6__*.sql` for something already shipped.

**Backend / Domain — no tasks.** Design §15's "Unchanged (verified, not assumed)" list includes `RbacDangerousPermissions`, `RbacRoleNames`, `DenialReason` and `RbacAuditEvent`. The gate reuses `RbacDangerousPermissions.contains()` and `RbacRoleNames.TENANT_ADMIN` **verbatim**, and D6/D3 explicitly reject a sixth `DenialReason` value. Adding any domain type here would be scope creep against a written decision. The `*.domain.*` ≥ 0.90 JaCoCo gate is therefore untouched, which also avoids the `common.security` coverage trap noted in design §11.3.

**Backend / Interfaces — no tasks.** `UserRoleController` and `RoleController` are unchanged: no new endpoint, no new DTO, no new status code, no versioning need (design §8.1, D11). Both verbs keep their exact request/response shapes, and the 403 body is unchanged **field for field** including for the throttled case — `GlobalExceptionHandler.handleInsufficientPermission` (159–176) already produces it, and `DenialReason` is never wire-visible (§8.3 reason 4). The throttle deliberately returns **403, not 429**, precisely so that no interfaces-layer change is required. `UserRoleControllerTest` needs no edit.

**Frontend — N/A, confirmed.** Zero files under `nexus-frontend/` change (design §2, §12.1, §15). The Tenant Admin UI that consumes these verbs is Epic 3 and is out of scope. One forward note is carried in design §2 for Epic 3's benefit (a 403 on assigning a privileged role is a *normal* outcome for a non-admin operator, so the UI must not offer such roles as assignable to them) — that note is already in the design; **no Angular, Vitest, lint or format gate runs for this story.**

---

# Database

### T-001 — Confirm zero schema change and zero migration

**Description:** A gate, not an implementation. Before any code task starts, confirm that `V5__rbac_schema.sql` already provides every table, column, index and constraint the design leans on (§5.1, §5.4), so that no `V6__*.sql` is written for something that already exists, and so that the "no migration" claim in ADR-0017 is verified rather than inherited. Specifically confirm: `pk_role_permissions PRIMARY KEY (role_id, permission_id)` (M7's access path), `uq_roles_tenant_name UNIQUE (tenant_id, name)` under `utf8mb4_0900_ai_ci` (M8's access path and D4's containment invariant), `fk_user_roles_role` (M1/M5/M9's access path), and `uq_user_role_active` over the STORED generated `active_key` column.

**Dependencies:** none — do first.
**Files impacted:** none · **Files created:** none
**Complexity:** S
**Risks:** None; it is a verification step. The risk it *removes* is a speculative migration, which under ADR-0003's append-only rule cannot be withdrawn cleanly once merged.
**Testing requirements:** Integration — run `RbacSchemaMigrationIT` unmodified and confirm green (it asserts columns with `containsExactly`, so any drift fails loudly). No new test.
**Definition of Done:** `RbacSchemaMigrationIT` passes with zero modification; `git status` shows no file under `nexus-backend/src/main/resources/db/migration/`; the four constraints above are confirmed present in `V5__rbac_schema.sql` and the line numbers recorded in the task's completion note. Discharges design §5.1.

---

# Backend — Application

### T-002 — `UserRoleAssignmentPort`: declare M7 and M8; correct M9's Javadoc

**Description:** Add the two additive read methods the gate needs (D3), with the full contract Javadoc from design §4.3 — this Javadoc is load-bearing, not decoration: it is the only thing that prevents a future `@Lock` on M7 (a production-only failure, D5) and the only place M7's missing tenant scope is stated (T-I13 / RC-12.4).

- `List<String> findPermissionNamesForRole(UUID roleId)` — M7. Copy §4.3's Javadoc verbatim, including the capitalised **PRECONDITION** that `roleId` must already be tenant-verified by the caller, the "returns NAMES, never a boolean and never a projection" rationale, and the "MUST NEVER be annotated `@Lock`" prohibition.
- `Optional<UUID> findRoleIdByName(UUID tenantId, String name)` — M8. Javadoc must state the plain `r.name = :name` predicate requirement (never `UPPER()`, which would de-sargonise `uq_roles_tenant_name`) and that **empty ⇒ the caller MUST fail closed** (R-10 / T-E18).
- M9 `findActiveUserIdsForRole` — **Javadoc correction only, no signature change.** Its current text says *"this story's own runtime flows never call it"* (verified at `UserRoleAssignmentPort.java:88-91`). D13 gives it its first runtime caller: update the sentence to name `RoleManagementService.attachPermission`, and **retain** the "read-only, no locking" contract, which is now load-bearing rather than incidental (§4.3, §5.2).

**Dependencies:** T-001
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
**Files created:** none
**Complexity:** S
**Risks:**
- **Interim non-compiling state, expected and documented.** Adding two methods to the port leaves `JpaUserRoleAssignmentAdapter` without implementations, so `nexus-backend` will not compile between T-002 and T-005. This is the direct consequence of this task's own file boundary, not a defect. **Do not** resolve it with a `default` method on the port (that would let a future adapter silently inherit a stub that returns empty — which for M8 means *fail closed on every request* and for M7 means *never privileged*, i.e. the gate silently disabled). Proceed straight to T-005.
- Writing M7's Javadoc as a summary instead of copying §4.3 verbatim loses the precondition and the `@Lock` prohibition, both of which are the *only* record of a production-only failure mode.
**Testing requirements:** None directly (an interface). Coverage is supplied by T-005 (adapter delegation unit tests) and T-008/T-009 (service unit tests against a mocked port).
**Definition of Done:** Both methods declared with §4.3's Javadoc verbatim; M9's "never called at runtime" sentence corrected per §12.2 item 8; `UserRoleQueryPort` untouched (widening it would leak a write capability to a read-only collaborator, per this port's own class Javadoc at lines 11–20); no `default` implementations; T-005 begins immediately.

---

### T-003 — Declare `RoleChangeThrottlePort` and add the two throttle configuration properties (D14 / RC-10)

**Description:** Declare the outbound port that bounds the denial path, in `rbac.application.port.out`, and add its two configuration properties. The port must not name or import any throttle *mechanism* — that is what keeps the adapter in `identity` and the dependency direction `identity → rbac` (§4.8).

Port (per §4.8, with **A-3's one deviation**):
- `boolean isThrottled(UUID tenantId, UUID actorUserId)` — Javadoc must state: keyed by `(tenantId, actorUserId)`, **never by IP** (this path is authenticated; IP is neither stable nor attributable here) and **never by target** (an attacker chooses the target freely); **MUST fail SAFE and MUST NOT throw** — an unavailable store returns "not throttled" so the gate's own authoritative decision still runs; **the throttle bounds cost, it is not an authorization control** and must never be able to *permit* anything.
- `boolean recordDenial(UUID tenantId, UUID actorUserId)` — returns `true` iff **this** denial crossed the bound (A-3). Never throws.

Properties in `application.yml` under the existing `nexus.rbac` block (which already holds `permission-cache-ttl-seconds` at line 143):
- `nexus.rbac.denial-throttle.max-denials` — default **5**
- `nexus.rbac.denial-throttle.window-seconds` — default **60** (matches `nexus.security.rate-limit.ip-window-seconds`, so operators reason about one window length platform-wide)

**No `enabled` flag** (§4.8, D10): a boolean whose "off" position removes a DoS bound repeats the mistake D10 rejects. Setting `max-denials` very high is the disable mechanism.

**Dependencies:** T-001
**Files impacted:** `nexus-backend/src/main/resources/application.yml`
**Files created:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RoleChangeThrottlePort.java`
**Complexity:** S
**Risks:**
- **A-3's `boolean` return is a deviation from §4.8's verbatim `void`.** Record it in the port Javadoc with a one-line rationale so a reviewer comparing against the design sees a decision, not a typo.
- Naming or importing `RateLimitStore`/`RateLimitResult` from this port would make `rbac` depend on `identity` and fail `HexagonalArchitectureTest.rbac_must_not_depend_on_identity`. The port's types must be `UUID` and `boolean` only.
- Both properties must have defaults in `application.yml`; a missing property fails `@Value` injection at context start, which surfaces as every full-context test failing at once.
**Testing requirements:** None directly (an interface + config). Behaviour is covered by T-006 (adapter unit tests) and T-010 (service-level throttle tests incl. MC-7).
**Definition of Done:** Port compiles in `rbac.application.port.out` with zero imports outside `java.util`; both properties present with the design's defaults; existing ArchUnit rules green. Discharges design §4.8's port half; records A-1 and A-3 in the Javadoc.

---

### T-004 — Audit contract shape changes: `RbacAuditPort` gains `operation` (D17); `RoleAuditEvent` gains `holderCount` (D13)

**Description:** The two port-shape changes that both service tasks and the audit adapter compile against. Doing them together, once, avoids two separate compile breaks across the same two consumer classes.

- `RbacAuditPort.recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason, **String operation**)` — one added parameter (§4.9). Values are `"assign"` / `"revoke"` — the **verb**, not the adapter's internal `"deny"`. Javadoc must state that this parameter and the `nexus.rbac.audit_write_failed{operation="deny"}` metric tag are **deliberately different axes** and must not be unified. Also confirm the existing class Javadoc's "Scoped to the two 403 authorization denials (`CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`)" sentence stays **true and unedited** — D6 adds no enum value, so it does (§8.3 reason 5).
- `RoleAuditEvent` gains one **trailing, nullable** component `Integer holderCount` (§4.7). Javadoc must record: populated only on the dangerous-attach path; `null` everywhere else and therefore **omitted** from metadata by the file's existing omit-when-null convention.

**Dependencies:** T-001
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RoleAuditEvent.java`
**Files created:** none
**Complexity:** S
**Risks:**
- **Interim compile break, expected:** `RbacAuthEventAdapter` (the single implementation) and `RoleAssignmentService`/`RoleManagementService` (the callers) will not compile until T-007/T-008/T-011. `RoleAuditEvent` has **three construction sites in `src/main`** (`createRole`, `attachPermission`, `detachPermission`) plus test fixtures; all must pass `null` except the dangerous attach. Do not add an overloaded compact constructor to "keep old call sites working" — that hides the three sites the design wants visited.
- Appending the component **trailing** matters: a record's canonical constructor is positional, so inserting it anywhere else silently rebinds existing arguments.
**Testing requirements:** Unit — no new test in this task; `RbacAuthEventAdapterTest`'s new assertions belong to T-007, which is where the behaviour lands. Existing tests that construct `RoleAuditEvent` are updated mechanically here (add `null`).
**Definition of Done:** Both shapes changed; `DenialReason` untouched (D3/D6 — **no sixth value; do not add one**); `RbacAuditEvent` untouched (design §15 unchanged list); every `src/main` and `src/test` construction site updated; the "different axes" sentence present in `RbacAuditPort`'s Javadoc per §12.2 item 11.

---

### T-008 — `RoleAssignmentService`: the unified privilege gate and the `assign()` path (D4, D5, D15, D17, FR-1…FR-4, FR-6)

**Description:** The security core of the story. Introduce the shared gate helpers and wire them into `assign()`. `revoke()` is T-009; the throttle is T-010.

New private members (signatures from §4.1 — no other shape):
- `private static boolean isNamedTenantAdmin(Role role)` — FR-3's half; the source of `matchedOn`.
- `private boolean carriesDangerousPermission(UUID roleId)` — FR-1's half. Calls M7, streams over `RbacDangerousPermissions::contains`. **Empty permission set ⇒ NOT privileged** (Edge Case 1).
- `private void requireActiveTenantAdmin(RoleChangeActor actor, UUID targetUserId, Role role, String requiredPermission, String operation, boolean nameMatch, RequestContext requestContext)` — **the one and only call site** of `hasActiveAdminAssignment` (D4). `void`, not `boolean`, deliberately: a caller cannot ignore a thrown exception the way it can ignore an unchecked boolean.

Control flow, exactly as §6.1's pseudocode: `nameMatch = RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())`, then `privileged = nameMatch || carriesDangerousPermission(role.getId())` — **name-first, short-circuiting**, so FR-3's existing behaviour cannot be weakened by the new read. Inside the gate: M8 `findRoleIdByName(actor.tenantId(), TENANT_ADMIN)` → **empty means deny, fail closed, without calling M5** (R-10/T-E18); then `hasActiveAdminAssignment(actor.userId(), adminRoleId, actor.tenantId())` — **both arguments from the caller, never the target.**

Denial side effects at the single throw site: `matchedOn = nameMatch ? ROLE_NAME : DANGEROUS_PERMISSION`; WARN `event=RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` with `{tenantId, targetUserId, actorUserId, roleId, roleName, operation, matchedOn}`; counter `nexus.rbac.privileged_role_change_blocked{operation, matchedOn}` (D15, bounded 2×2); `recordDenial(..., NOT_TENANT_ADMIN, operation, ...)` threading D17's new argument; `throw new InsufficientPermissionException(USER_WRITE, NOT_TENANT_ADMIN)`.

Also in this task, because the values are computed here and nowhere else:
- **FR-6 canary tags** — `nexus.rbac.self_role_assignment` gains `privileged` (`true`/`false`) **and** `callerIsAdmin` (`true`/`false`/`n_a`) at the `assign()` post-commit site (D7 + D15, §9.2). Zero new queries: both are already in hand. `n_a` is the value for a non-privileged assignment, where the gate never ran.
- **Javadoc replacement (§4.2, §12.2 item 7)** — replace the M-3 (83–109) and T-E9 (219–232) notes with §4.2's **verbatim** text. **Replace, never delete** — both notes carry that instruction in their own body. The replacement text must say T-E16 is closed **for the direct propagate path only** and that the attach-after-assign path (T-E21 / RES-1(b)) survives; a text that claims outright closure is the RC-8.3 defect this story exists to avoid re-committing.

Explicitly **not** used: `callerHoldsActiveTenantAdmin` (`RoleAssignmentService.java:342-347`), the non-locking, name-based redaction helper for `listActive`. Using it would convert an assignment check into a role-name check and drop the T-E7 freshness guarantee — MC-2 is the control.

**Dependencies:** T-002, T-004, T-005 (main must compile)
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`
**Files created:** none
**Complexity:** L
**Risks:**
- **R4 / T-E22 — the story's worst silent bug, on two axes, both of which compile and both of which fail OPEN.** Passing `role.getId()` instead of M8's `adminRoleId` asks "does the caller hold the *custom* role?" — true the moment an attacker holds it once. Passing `targetUserId` instead of `actor.userId()` asks "is the *target* an admin?" — which on `revoke()` (T-009) reopens T-E17 against the highest-value targets in the tenant. **MC-3 covers BOTH axes and is mandatory here** (see Testing requirements).
- **Self-assignment fixtures cannot distinguish the two axes** (`targetUserId == actor.userId()`), which is exactly why MC-3(b) requires non-self fixtures everywhere except deliberate FR-4 cases.
- Three existing assign-side name-match tests **cannot** pass unmodified (correcting impact §12.2 — design §11.1): generalising the call site inserts M8 ahead of M5, and an unstubbed M8 returns `Optional.empty()`, which fails closed. Each needs **one added stub**, a fixture change only. Their *assertions* must stay byte-identical — that is what the FR-3 regression contract actually requires. Without the stub, `should_throwNotTenantAdmin_when_grantingTenantAdminAndCallerNotActiveAdmin` passes **for the wrong reason** (fail-closed on empty M8, not the admin check) and `should_throwNotTenantAdmin_when_roleNameIsDifferentCaseVariantOfTenantAdmin` breaks outright.
- Emitting two denials/two audit rows when both halves of the condition are true (the seeded `TENANT_ADMIN` carries all 7 permissions, V5:130–136) — prevented structurally by the single `||` condition, not by an ordering rule (Edge Case 3).
**Testing requirements:**
- **Unit (`RoleAssignmentServiceTest`)** — the §11.3 matrix: assign × {one dangerous permission / all three / a **case-variant** dangerous name / a non-dangerous permission / empty set} × {caller is an active admin / is not} × {`targetUserId != actor.userId()` **by default**, self only for deliberate FR-4 cases}. Plus: M8 empty ⇒ fail closed **without calling M5**; M7/M8/M5 throwing ⇒ propagates (500, deny-by-abort) and nothing is written; **exactly one** denial, one audit row and one metric increment when both halves hold; `NOT_TENANT_ADMIN` asserted on every new denial; the WARN's `operation`/`matchedOn` asserted; the new counter's **tags** asserted; D17's `operation="assign"` asserted on the audit call; gate ordering asserted against the 404 and 409 branches.
- **MC-2** — `verify(port).hasActiveAdminAssignment(actorId, ADMIN_ROLE_ID, tenantId)` **and** `verify(port, never()).findActiveAssignmentViews(any(), any())`, asserted **on the privilege path specifically, never class-wide** (`listActive` legitimately calls it — a class-level assertion would be wrong and would fail confusingly).
- **MC-3 (both axes, RC-14)** — (a) an `ADMIN_ROLE_ID` stub value **deliberately different** from the target `roleId` in every privilege-path test, plus `verify(port, never()).hasActiveAdminAssignment(any(), eq(targetRoleId), any())`; (b) `targetUserId != actor.userId()` in every non-FR-4 privilege-path test, plus `verify(port, never()).hasActiveAdminAssignment(eq(targetUserId), any(), any())`.
- Fixture-only updates to the three name-match tests and to `should_proceedToInsert_when_grantingTenantAdminAndCallerIsActiveAdmin` — whose line-343 `verify(port).hasActiveAdminAssignment(actorId, role.getId(), tenantId)` **must stay literally unchanged**: it remains true because M8 returns `role.getId()` on the name-match path (§5.4), and keeping it unchanged **is** the proof that generalisation preserved the name-match argument.
**Definition of Done:** `./mvnw verify -DskipITs` green; MC-2 and MC-3(a)+(b) present and passing; the three name-match tests differ only by an added stub, with byte-identical assertions; `should_neverCallLockActiveAssignmentIds_when_adminRoleAssignmentNotFound` **byte-identical** (it is the tripwire on §6.2's "gate after the 404"); §4.2's Javadoc replacement applied verbatim and claiming only partial T-E16 closure; `rbac.application` JaCoCo ≥ 0.85 holds. Discharges design §4.1, §4.2, §6.1, §6.2 (checks 1–2, 5, 7), §9.2 (WARN + D15 counter + canary tags), §11.2 MC-2/MC-3.

---

### T-009 — `RoleAssignmentService.revoke()`: the first revoke-side admin gate, the pinned lock order (D2), the AC5 interaction (D1), and the D18 timer

**Description:** Wire the T-008 helpers into `revoke()` — the verb that has **never had an authorization gate** — with the lock order pinned. Order is the correctness property here; getting it wrong is a deadlock, not a test failure.

Exact sequence (§7.2):
1. `findAssignmentRefOrThrow` → 404. **Position unchanged; 404 stays before 403.**
2. `nameMatch = isNamedTenantAdmin(role)`; `privileged = nameMatch || carriesDangerousPermission(role.getId())` — **M7 runs before M1, outside the locked region, on every path** (§6.5, interaction with D2).
3. **Lock-ordering step, not a check:** `lockedActiveAdminIds = nameMatch ? port.lockActiveAssignmentIds(tenantId, role.getId()) : List.of()` — M1's **X** lock acquired **first**, before any S read. No decision is taken here.
4. `if (privileged) requireActiveTenantAdmin(...)` with `operation="revoke"` — M8 + M5 (**S**), contained inside the X region on the `nameMatch` path.
5. AC5 lockout (`nameMatch && size() <= 1 && contains(ref.id())`) → 409 `RBAC_002`. **Unchanged code, now always after #4.**
6. M6 revoke → 204.

**D18 timer:** `nexus.rbac.privileged_revoke_lock_hold{outcome}`, `outcome ∈ {denied, lockout, revoked, error}` (bounded, 4 values, **no tenant tag** — unbounded; the WARN carries `tenantId` for correlation). Started **immediately after M1 returns**, stopped at the throw or at commit, so it measures the **composed** interval M8 + M5 + the `REQUIRES_NEW` audit write + M6 — the whole window during which every other privileged role change in the tenant is blocked. Publishing the composed figure rather than the pieces is the substance of RC-9.5; do not instrument the halves.

**AC5 is not modified and must not be deleted.** Its reachable population narrows to self-revocation (§6.4's proof), and the ≥1-admin invariant is now enforced *more* strongly by the gate — but AC5 remains the guard of last resort if the gate is ever weakened, reordered or bypassed by a new call path.

**Dependencies:** T-008
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`
**Files created:** none
**Complexity:** L
**Risks:**
- **Reversing the lock order is a textbook InnoDB S→X upgrade deadlock** on the *legitimate* path (two admins revoking each other), and it is invisible to every single-threaded test. Promoting M5 to `PESSIMISTIC_WRITE` **does not fix it** (§7.3 option (b)) — mode is not the defect, order is. The proof only holds mechanically once MC-5 and harness A land (T-014, T-015).
- The lock is acquired **before** the authorization decision, so a caller who will be denied 403 still takes and holds the X lock over every admin row in the tenant (T-D11). This is deliberate (§6.3) and is bounded by T-010's throttle — which is why T-010 must not be deferred.
- **T-E22 axis 2 is most dangerous here:** passing `targetUserId` to `hasActiveAdminAssignment` on the revoke path lets any non-admin strip any role from an admin. MC-3(b) must cover revoke-path tests too.
- Five existing revoke-side unit tests need added stubs (§11.1 table). `should_throwLastAdminRoleException_…_differentAdminRevoking` must be **kept and renamed** to `…_differentAdminRevoking_syntheticStateSeeDesign64` with a comment citing §6.4 — it is the unit-level proof that the guard performs no actor/target comparison, even though the state is unreachable in production. Deleting it would remove the guard-shape proof.
**Testing requirements:**
- **Unit** — the full §11.3 matrix for `revoke()`, mirroring T-008's assign matrix, with `operation="revoke"` asserted on the WARN, the counter and the D17 audit call; 403-before-409 asserted explicitly (a non-admin revoking the tenant's last admin gets **403, not 409**); M1 asserted to be invoked **before** M5 on the `nameMatch` path (`InOrder`); M1 asserted **never** invoked on the dangerous-custom-role path; the timer's four `outcome` values each exercised.
- **Unit fixtures** — the five tests named in §11.1's table get their M8/`hasActiveAdminAssignment` stubs; `should_neverCallLockActiveAssignmentIds_when_adminRoleAssignmentNotFound` stays **byte-identical**.
**Definition of Done:** `./mvnw verify -DskipITs` green; `InOrder` assertion pins M1-before-M5; the renamed synthetic-state test retains its actor-agnostic assertions and cites §6.4; the D18 timer emits all four bounded outcomes with no tenant dimension. **Discharges design §6.2 (checks 3–6), §6.3, §6.4, §7.2, §7.5 / D18.** Note in the completion record that §7.2's proof is not yet *mechanically* established — MC-5 (T-014) and harness A/C (T-015) are what establish it, and this task is not the last word on D2.

---

### T-010 — `RoleAssignmentService`: the denial throttle at check 3.5 (D14 / RC-10) and MC-7

**Description:** Wire `RoleChangeThrottlePort` into both verbs at **check 3.5** and only there.

- Constructor gains one collaborator (`RoleChangeThrottlePort`) plus two `@Value`s (`nexus.rbac.denial-throttle.max-denials`, `…window-seconds`) — used **only** as WARN fields (A-4). `RoleManagementService` already takes a `@Value` in its constructor, so this is an established shape in the package.
- `private void requireNotThrottled(RoleChangeActor actor, String operation, RequestContext ctx)`: if `isThrottled` → increment `nexus.rbac.denial_throttled{operation}` and throw the **same** `InsufficientPermissionException(USER_WRITE, NOT_TENANT_ADMIN)` — **no audit row, no `permission_denied` increment, no per-request WARN.**
- Placement: **after** the 404s (checks 1–3) and **before** M1/M7/M8/M5, the audit write and the metric. Above the 404s it would break the 404-before-403 contract; below M1 it would fail to bound T-D11, which is half its purpose. This is the only position that bounds every expensive step while preserving every ordering guarantee.
- At the gate's throw site (T-008's `requireActiveTenantAdmin`): call `throttlePort.recordDenial(...)`; when it returns `true` (A-3, the transition), emit **one** WARN `RBAC_DENIAL_THROTTLE_ENGAGED` with `{tenantId, actorUserId, operation, maxDenials, windowSeconds}`.
- Behaviour on trip: **the first N denials are fully processed** — WARN, counter, durable `ROLE_ASSIGNMENT_DENIED` row — so forensics keeps the evidence. Only beyond N is everything suppressed.

**Dependencies:** T-003, T-006, T-009
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`
**Files created:** none
**Complexity:** M
**Risks:**
- **The throttle must never be able to permit anything.** It can only turn a would-be 201/204 into a 403, never the reverse. That is why it fails *safe* rather than fails *open*, and why it precedes rather than replaces the gate. MC-7 is the control.
- Hoisting the check above the 404s breaks `should_neverCallLockActiveAssignmentIds_when_adminRoleAssignmentNotFound`, which is now a tripwire on D14's placement as well as on the gate's — treat a failure of that test as an ordering bug, never as a test to update.
- **RES-11 (accepted):** a throttled actor is also denied `assign()`/`revoke()` of **benign** roles for the rest of the window. That is the price of not doing the work needed to find out whether this particular request would have been denied anyway. It must appear in the runbook (T-022) as an expected, self-clearing symptom.
- Constructor change ripples into every `RoleAssignmentServiceTest` fixture. A mock returning the `boolean` default (`false` = not throttled) keeps every existing test semantically unchanged — no stub needed unless the test asserts the throttled path.
**Testing requirements:**
- **Unit** — not throttled ⇒ normal flow; throttled ⇒ 403 **with `verifyNoInteractions(rbacAuditPort)`, no `lockActiveAssignmentIds`, and no M7/M8/M5** (this is the whole point of the control and must be asserted, not assumed); the Nth denial records against the port; the transition WARN emitted **exactly once**; `denial_throttled{operation}` incremented for both verbs.
- **MC-7 (both halves)** — (i) a `RoleChangeThrottlePort` mock that **throws** does not propagate and does not alter the authorization outcome; (ii) the throttle can only ever produce a 403, never permit an operation the gate would deny (assert that a throttled *and* would-be-denied caller still gets 403, and that `isThrottled==true` never short-circuits into a success path).
**Definition of Done:** `./mvnw verify -DskipITs` green; the throttled path proven to touch **zero** ports other than the throttle; MC-7's two tests present; the tripwire test still byte-identical; RES-11's collateral captured for T-022. Discharges design §4.8, §6.2 check 3.5, §9.2 (`denial_throttled` + `RBAC_DENIAL_THROTTLE_ENGAGED`), §11.2 MC-7.

---

### T-011 — `RoleManagementService.attachPermission`: the mint-side holder-count signal (D13 / RC-8 part 3)

**Description:** US-016 code that lives in US-015's service, shipped here by an explicit story-owner scope decision (2026-09-10) because T-E21 is rated **High** on the same basis US-015 rated T-E16 High. **Independent of T-008/T-009 — different service, different verb, no shared code path** — so it can be developed in parallel in principle; the repo's sequential convention still applies.

What it does: after the existing `roleManagementPort.attachPermission(role.id(), permissionId)` and **before** `registerPostCommitSideEffects`, on the **dangerous path only**:

```java
Integer holderCount = dangerous ? userRoleAssignmentPort.findActiveUserIdsForRole(role.id()).size() : null;
```

`userRoleAssignmentPort` is **already** a constructor dependency (verified: `RoleManagementService.java:69`, `:76`, `:81`) — no new collaborator, no new port method, no schema change. The read is inside the same transaction, after the insert, so the count is exactly the population that will hold the now-dangerous role at commit.

Then:
- Pass `holderCount` on the `ROLE_PERMISSION_GRANTED` `RoleAuditEvent` (T-004's new component); `null` ⇒ omitted from metadata.
- The existing post-commit INFO `ROLE_PERMISSION_GRANTED` line gains `holderCount` (only when non-null); its existing `dangerous` key is unchanged.
- When `dangerous && holderCount > 0`, emit a **new WARN** `RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS` with `{tenantId, roleId, roleName, permissionId, permissionName, grantedBy, holderCount}` — same level, field style and throw-site-context reasoning as US-015's `RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED`. `holderCount == 0` escalates nobody, so it is not the alertable event.
- `nexus.rbac.dangerous_permission_granted` gains a **bounded bucket** tag `holders ∈ {"0", "1", "2-10", ">10"}`. Buckets, not the raw count, because the raw count is unbounded cardinality and the alerting question is answered by four values.

**What it must NOT do:** it does not block the attach, does not add a gate, does not change any status code. `attachPermission`'s authorization behaviour (AC7 → AC11 → AC4 → insert) is untouched. Blocking was considered and rejected in the design: attaching a dangerous permission to a role that has holders is a legitimate, Epic-3-required administrative action.

**Javadoc (§12.2 item 10):** record what the holder count is for (T-E21), that it is **signal, not a gate**, and that **removing it re-opens a silent mass escalation** — this is the "do not delete without re-opening the note" discipline, applied to code.

**Dependencies:** T-004, T-007
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleManagementServiceTest.java`
**Files created:** none
**Complexity:** M
**Risks:**
- Calling `findActiveUserIdsForRole` on the **non-dangerous** path would put a query on the ordinary attach path, falsifying D13's cost claim. Assert it is never called there.
- Giving M9 a `@Lock` "to make the count consistent" would be a production-only failure of the same class as D5's (§5.2) — **the count is a signal, not a decision**, and must stay non-locking. MC-1 (T-012) covers this.
- The AC11 denial path never reaches the insert, so it must make no holder query either.
- **Story-level dependency to state explicitly:** the §12.2 item 6 documentation change (T-021) and ADR-0017's D5 (T-019) both *claim* this mitigation exists. Neither may land before T-011 is green, or the register and the ADR describe a mitigation that is not in the code.
**Testing requirements:**
- **Unit (`RoleManagementServiceTest`)** — dangerous attach with **0 / 1 / 5 / 50** holders ⇒ correct `holderCount` on the audit event and correct bucket tag (`"0"`, `"1"`, `"2-10"`, `">10"`); WARN emitted **only** when `holderCount > 0`; **non-dangerous attach makes no holder query**; AC11 denial path makes no holder query. Every existing AC7/AC11/AC4 assertion unchanged — D13 changes no authorization behaviour.
**Definition of Done:** `./mvnw verify -DskipITs` green; all four bucket boundaries covered; `verify(port, never()).findActiveUserIdsForRole(any())` on both the non-dangerous and AC11-denied paths; `RoleManagementAdminGateIT` still passes unmodified (D13 changes no authorization behaviour); Javadoc per §12.2 item 10. Discharges design §4.7 / D13 and RC-8 part 3.

---

# Backend — Infrastructure

### T-005 — `JpaRoleRepository` M7 query + `JpaUserRoleAssignmentAdapter` M7/M8 delegation (D16 / RC-12)

**Description:** Implement the two port reads with **zero new adapter constructor dependencies**.

- **`JpaRoleRepository`** gains one `@Query` method, `List<String> findPermissionNamesByRole(@Param("roleId") UUID roleId)`. **Use the two-entity comma-join form** (A-6 — verified this session: `rbac/domain/Role.java` has **no** mapped association to `RolePermission`): `SELECT p.name FROM RolePermission rp, Permission p WHERE rp.id.permissionId = p.id AND rp.id.roleId = :roleId`. **JPQL, never native SQL**, so Hibernate's auto-applied `UuidV7Converter` handles `UUID` ↔ `BINARY(16)` for both predicate and bind. **No `@Lock`** (MC-1). **No `ORDER BY`** — the caller does set membership. Spring Data does not require a `@Query` to name only the repository's own aggregate root; hosting it here is the point, not the join syntax.
- **`JpaUserRoleAssignmentAdapter`** implements both port methods by delegating to the **already-injected** `roleRepository`: M7 → the new query; M8 → the existing `findIdByTenantIdAndName` (Q3, `JpaRoleRepository.java:53`) — so M8 adds **zero** queries and there is exactly one `(tenantId, name)` index-discipline site shared with the mint side.

**`JpaRolePermissionRepository` is deliberately NOT injected** and stays out of this story's file list. It `extends JpaRepository<RolePermission, RolePermissionId>`, so injecting it would hand the *assignment* adapter `save`/`delete`/`deleteAll` over `role_permissions` — the one RBAC table with both `INSERT` and `DELETE` grants, no trigger and no soft delete, i.e. the only one where an accidental write from the wrong layer actually **executes** (T-T13).

**Javadoc (§12.2 item 9):** extend the adapter's class Javadoc (which already states the R-9 "no hardcoded `TENANT_ADMIN` literal in this layer" discipline) with two sentences: (a) the same rule now covers dangerous permission **names**; (b) **this adapter holds no write capability over `role_permissions` and must not acquire one — its permission read is hosted on `JpaRoleRepository` precisely so that it cannot.**

**Dependencies:** T-002
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`, `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
**Files created:** none
**Complexity:** M
**Risks:**
- Adding a `JpaRolePermissionRepository` constructor dependency "for cohesion" is the exact regression RC-12 exists to prevent. The adapter's constructor must gain **zero** parameters.
- Any `@Lock` on the new query is a **production-only** failure: `nexus_app` holds `SELECT` only on `permissions` (`nexus-database/mysql/init/02-grants-post-schema.sql:31-35`), and MySQL requires `SELECT` plus one of `DELETE`/`LOCK TABLES`/`UPDATE` for a locking read — so it would be rejected in production and **pass every Testcontainers IT** (which connect as superuser). MC-1 (T-012) makes this mechanical.
- Writing the query as native SQL would bypass `UuidV7Converter` and silently mis-bind the `BINARY(16)` id.
- Wrapping `r.name` in `UPPER()` on the M8 path would de-sargonise `uq_roles_tenant_name`; the existing Q3 already gets this right — **reuse it, do not write a second lookup.**
**Testing requirements:**
- **Unit (`JpaUserRoleAssignmentAdapterTest`)** — delegation tests for M7 and M8 (arguments passed through unchanged, return values passed back unchanged, empty results handled). **The test's `setUp` does NOT change** — the constructor is unchanged (D16); revision 1's note to the contrary is withdrawn.
- **Integration** — the non-locking SQL assertion is MC-1, owned by T-012.
**Definition of Done:** `./mvnw verify -DskipITs` green; adapter constructor byte-identical to its pre-story form; `JpaRolePermissionRepository` shows **no diff**; no `@Lock` anywhere on the new query; Javadoc per §12.2 item 9. Discharges design §4.4, §4.5, D16 / RC-12.

---

### T-006 — `RateLimitRoleChangeThrottleAdapter` in `identity.infrastructure.security` (D14)

**Description:** Implement `RoleChangeThrottlePort` over the shipped `RateLimitStore`. Key: `"RBAC_DENY:" + tenantId + ":" + actorUserId`.

**The adapter lives in `identity`, not `rbac`, and this is load-bearing.** `RateLimitStore` is `identity.application.port.out`; an `rbac` class importing it fails `HexagonalArchitectureTest.rbac_must_not_depend_on_identity`. Placing the adapter in `identity.infrastructure.security` against an **`rbac`-declared port** keeps the direction `identity → rbac` — the arrangement `RbacAuthEventAdapter` and `UserDirectoryPort` already establish. **No new architectural precedent, and no new dependency: Redis is not introduced** (the default store is in-memory; the Redis-backed implementation is a pre-existing, separately configured option — ADR-0016 unaffected).

**Implementation per A-2** (read A-2 before starting):
- `recordDenial(tenantId, actorUserId)` → `rateLimitStore.tryConsume(key, windowSeconds, maxDenials)`. When the result is `!allowed()`, record `now + retryAfterSeconds` in a bounded per-key "throttled-until" map and **return `true`** (the transition, A-3); otherwise return `false`.
- `isThrottled(tenantId, actorUserId)` → compare `now` against the map entry, **removing the entry when expired**. Consumes nothing.
- The map must be bounded: evict-on-read plus a periodic or size-capped sweep, following `InMemoryRateLimitStore`'s own eviction pattern (`InMemoryRateLimitStore.java:102-110`). Use the injected `Clock` bean, not `Instant.now()`, so the tests are deterministic.
- **Fail safe (MC-7's other half):** any exception from the store — or from the map — is swallowed here and treated as "not throttled". The adapter **must never throw**.
- Two `@Value`s for `nexus.rbac.denial-throttle.max-denials` / `…window-seconds` (A-4).
- **Javadoc must state the per-JVM caveat** from A-2: this adapter's throttled-until state is per-replica and does **not** become cluster-wide when `nexus.security.rate-limit.store-type=redis`, because only the *counting* delegates to the store.

**Dependencies:** T-003
**Files impacted:** none
**Files created:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/RateLimitRoleChangeThrottleAdapter.java`, `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/RateLimitRoleChangeThrottleAdapterTest.java`
**Complexity:** M
**Risks:**
- **A-2 is the live design risk in this task.** If the Architect rejects the adapter-owned map and prefers extending `RateLimitStore` with a non-consuming read, this task changes shape and design §15's "`RateLimitStore` unchanged" claim must be corrected. Do not silently pick the other option.
- Putting this class in `rbac.infrastructure` fails ArchUnit — and the failure message points at the import, not at the placement decision, so it costs more to diagnose than to get right.
- An unbounded throttled-until map is a slow memory leak on a multi-tenant system; the eviction is not optional.
- `@ConditionalOnProperty` must **not** be used here: unlike `InMemoryRateLimitStore`/`RedisRateLimitStore` (which are alternatives), this adapter is the single implementation of an `rbac` port, and a missing bean would fail `RoleAssignmentService`'s construction and take down every full-context test at once.
**Testing requirements:**
- **Unit** — not-yet-denied actor ⇒ `isThrottled == false`; N denials ⇒ the Nth `recordDenial` returns `true` (transition) and subsequent ones return `false`; `isThrottled == true` for the remainder of the window; **self-clears after the window** (advance the injected `Clock`); a throwing `RateLimitStore` ⇒ `isThrottled == false` and `recordDenial` does not throw; the key format is exactly `"RBAC_DENY:{tenantId}:{actorUserId}"`; **`isThrottled` consumes nothing** (assert `tryConsume` is never called from it — this is the assertion that pins A-2's whole point); expired entries are evicted.
**Definition of Done:** `./mvnw verify -DskipITs` green; `HexagonalArchitectureTest.rbac_must_not_depend_on_identity` green; `RateLimitStore`, `InMemoryRateLimitStore` and `RedisRateLimitStore` all show **no diff** (design §15); the "`isThrottled` never calls `tryConsume`" assertion present; per-JVM caveat in the Javadoc. Discharges design §4.8's adapter half.

---

### T-007 — `RbacAuthEventAdapter`: persist `operation` (D17) and `holderCount` (D13) in metadata

**Description:** The durable-record half of D13 and D17, both landing in `buildMetadataJson`'s two overloads following the file's existing **omit-when-null** convention.

- `recordRoleAssignmentDenied(RbacAuditEvent, DenialReason, String operation)` — thread `operation` into the existing private `record(...)`'s `operation` slot and add one clause to `buildMetadataJson(RbacAuditEvent, String, String)`, emitted **after `reason`**: `if (operation != null) { metadata.put("operation", operation); }`. So `ROLE_ASSIGNMENT_DENIED`'s durable metadata becomes `{traceId, roleId, roleName, reason, operation?, attemptedBy}`.
- `buildMetadataJson(RoleAuditEvent, String)` — one clause after `permissionName`: `if (event.holderCount() != null) { metadata.put("holderCount", event.holderCount()); }`. So `ROLE_PERMISSION_GRANTED`'s metadata becomes `{traceId, roleId, roleName, permissionId, permissionName, holderCount?, grantedBy}`.
- **The `nexus.rbac.audit_write_failed{operation}` metric tag keeps its existing `"deny"` value** so no dashboard breaks. The metric tag and the metadata field are **deliberately different axes** and the adapter Javadoc must say so (§12.2 item 11).

Why persisted rather than log-only: `auth_events` is append-only and never pruned by this application, while log retention is an Ops decision nobody has cited a figure for. US-015 RES-10 refused the same gap; this follows that precedent (§4.9).

**Dependencies:** T-004
**Files impacted:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`, `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapterTest.java`
**Files created:** none
**Complexity:** S
**Risks:**
- Unifying the metadata `operation` with the metric's `"deny"` tag would break every existing `audit_write_failed` dashboard **and** destroy the discriminator RC-13 exists to add. Keep them separate and say why in the Javadoc.
- Emitting `holderCount: null` instead of omitting it breaks the file's omit-when-null convention and every existing metadata-shape assertion.
- `AuthEventType` is **unchanged** (design §15) — do not add an event type for either signal.
**Testing requirements:**
- **Unit (`RbacAuthEventAdapterTest`)** — `operation="assign"` and `operation="revoke"` each present in denial metadata, positioned after `reason`; **omitted when null**; `holderCount` present on a dangerous `ROLE_PERMISSION_GRANTED` and **omitted when null**; `audit_write_failed{operation="deny"}` unchanged on the failure path; the omit-when-null convention for every other field unchanged.
**Definition of Done:** `./mvnw verify -DskipITs` green; both metadata fields asserted present-and-omitted; the metric tag's `"deny"` value proven unchanged; Javadoc per §12.2 item 11. Discharges design §4.9 / D17 and D13's durable-audit half. (The end-to-end metadata proof is `RoleAssignmentAuditIT`, owned by T-016.)

---

# Cross-cutting (security mitigations, feature flag, observability)

### T-012 — MC-1: mechanical proof that M7, M8 and M9's new call site are non-locking

**Description:** The single control standing between this story and a **production-only** authorization outage. `nexus_app` holds `SELECT` only on `permissions`; MySQL requires `SELECT` plus one of `DELETE`/`LOCK TABLES`/`UPDATE` to execute a locking read. A `@Lock` added to M7 (or to M9 "to make the count consistent") would therefore be **rejected in production and pass every Testcontainers IT**, because every IT connects as the container superuser. Code review is not a sufficient control for a failure mode that no test can see.

Implement as a SQL-capture assertion reusing `LastAdminLockoutIT`'s `captureHibernateSql` harness (verified present at `LastAdminLockoutIT.java:403`): execute a flow that triggers **M7** (a non-name-match privileged assign), **M8** (any privileged path) and **M9's new call site** (a dangerous `attachPermission`), and assert the captured statements contain **neither `for share` nor `for update`**.

Also confirm and record: **no new privilege-level IT** in the `RolePermissionsPrivilegeIT` / `UserRolesPrivilegeIT` family is required, because no new *locking* read is proposed on any new path (design §5.2). Recording this is part of the task — an unexplained absence looks like an oversight to the Phase 7 auditor.

**Dependencies:** T-005, T-011
**Files impacted:** an existing IT in `nexus-backend/src/test/java/com/example/nexus/rbac/` (co-locate with the harness rather than creating a fourth SQL-capture site — `LastAdminLockoutIT` or `RolePermissionsPrivilegeIT`, implementer's choice, recorded in the task note)
**Files created:** possibly none
**Complexity:** M
**Risks:**
- Asserting only on M7 and forgetting M9's new call site leaves half the control missing — D13 introduced a second non-locking-mandatory read and the design extends MC-1 to it explicitly.
- A brittle assertion on the full SQL string will fail on unrelated Hibernate formatting changes; assert on the **absence of the two lock clauses**, case-insensitively, not on statement equality.
- This is an IT, so it does not run under the per-task `-DskipITs` gate. It must be run at least once locally with Docker up before the task is called done — a control nobody has executed is not a control.
**Testing requirements:** Integration — as described. Manually verify the assertion **fails** when a `@Lock` is temporarily added to the M7 query (mutation check), then revert. A control that cannot fail is not a control.
**Definition of Done:** The assertion covers all three statements; the deliberate-failure mutation check performed and recorded; the "no new privilege IT required" finding written into the task note with its §5.2 citation. Discharges design §11.2 MC-1 and D5's mechanical half.

---

### T-013 — Feature flag: confirm no new flag, and that the existing two cover every changed path (D10)

**Description:** A gate, not an implementation. **No new feature flag is created** — a dedicated flag's "off" position would *be* the vulnerability, making it the only flag in the codebase that must default `true` to be safe (D10, confirmed by the threat model as "the best reasoning in the document"). Confirm instead that every code path this story changes is already behind one of the two shipped, default-off kill switches:

- `feature.nexus-us012-rbac-role-assignment.enabled` — gates `UserRoleController`, i.e. **both** changed verbs;
- `feature.nexus-us015-rbac-role-management.enabled` — gates the role/permission API, including the `attachPermission` path D13 extends.

Both are `false` in `application.yml` (verified: lines ~210–219) and `true` only in `dev`/`test`. Confirm D14's two throttle properties are **configuration, not a flag**: both defaults are safe and neither has an "off" position that removes a security control.

**Dependencies:** T-010, T-011
**Files impacted:** none · **Files created:** none
**Complexity:** S
**Risks:**
- The temptation to add `@ConditionalOnProperty` to `RoleAssignmentService` or the throttle adapter. Do not: the flag is pinned to the controllers (US-015 §11.1 precedent), and a conditional service bean fails full-context startup when the flag is off.
- **Recorded, not fixed:** flag-off is an **availability** lever, not a security one — disabling the flag re-opens the escalation path rather than closing it. That sentence belongs in the rollback section of T-022, and this task's completion note should hand it over.
**Testing requirements:** No new test. Confirm the existing flag-off tests for both controllers still pass unmodified.
**Definition of Done:** No new `feature.*` key exists in any `application*.yml`; both existing flags confirmed `false` in the base profile; the throttle properties confirmed to sit under `nexus.rbac`, not `feature`; the availability-vs-security sentence handed to T-022. Discharges design §10.1 / D10.

---

# Tests

### T-014 — MC-5 (`EXPLAIN` access path) and MC-6 (isolation level) (RC-9 parts 1–2)

**Description:** The two assertions that convert D2's proof from an argument into a check. **Sequence these before the harnesses** (T-015): if MC-5 fails, harness C would be testing an unproven premise.

- **MC-5** — an IT that captures the statements for **M1** and **M5** (reusing `captureHibernateSql`) and runs `EXPLAIN` on each via `JdbcTemplate`, **asserting the chosen index**. InnoDB locks **index records, not logical rows**, so §7.2 step 1's containment claim is a property of the *execution plan*, not of the predicates. M1 drives off `role_id` via `fk_user_roles_role` by its own Javadoc; M5's predicate (`userId AND roleId AND tenantId AND revokedAt IS NULL`) lets the optimiser choose `fk_user_roles_role`, `fk_user_roles_user`, or `uq_user_role_active`. **Only in the `fk_user_roles_role` case is every lock M5 requests already held by M1.**
  **If M5's plan is not `fk_user_roles_role`, the implementer MUST NOT silently proceed.** Either reorder the predicate / add an index hint so it is, **or** write the non-contained-acquisition analysis into design §7.2 and re-run harness C against it. **A failing MC-5 is a design question, not a test to relax** — escalate to the Architect.
- **MC-6** — `assertThat(jdbc.queryForObject("SELECT @@transaction_isolation", String.class)).isEqualTo("REPEATABLE-READ")` in the concurrency IT. Both D2's serialization claim (M1's range lock must block *inserts* into the `role_id = adminRoleId` gap) and §6.4's "structurally unreachable" AC5 proof depend on gap/next-key locking. Under READ COMMITTED both weaken. **Nothing in the codebase pins the isolation level today** — it works because MySQL's default is `REPEATABLE-READ`, which is exactly why this must be asserted rather than assumed.

**Dependencies:** T-009
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java`
**Files created:** none
**Complexity:** M
**Risks:**
- **MC-5 may legitimately fail**, and the correct response is analysis, not relaxation. Budget for that: it is the one place in this story where a test failure is expected to change the design document.
- `EXPLAIN` output format differs between MySQL versions; assert on the `key` column's value, not on the whole row, and pin the assertion to the MySQL 8.4 Testcontainers image the repo already uses.
- MC-6 is a one-line assertion whose value is entirely in its permanence — do not move it into a `@BeforeAll` where a future refactor can drop it silently; keep it inside the concurrency test body it protects.
**Testing requirements:** Integration only (both need a real MySQL). Run with Docker up before calling this done — like T-012, an unexecuted control is not a control.
**Definition of Done:** Both assertions present and executed at least once against Testcontainers; MC-5's observed access path for M1 **and** M5 recorded in the task note (and, if M5 is not `fk_user_roles_role`, the design escalation raised before T-015 starts). **Discharges design §7.2 step 1 + §11.2 MC-5, and §7.2 step 2 / §6.4 + §11.2 MC-6 — i.e. the two unstated dependencies RC-9 identified in D2's proof.**

---

### T-015 — `LastAdminLockoutIT`: reshape harnesses A and B, add harness C, and rewrite the 409→403 scenario (MC-4, RC-9.3)

**Description:** The proof that D2's deadlock fix and D4's fail-closed argument hold under real concurrency. **Not polish** — §7 calls itself "the load-bearing section of this document", and single-threaded tests cannot see any of it.

`should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins` (189–255) **cannot keep its fixture**: its `caller` (lines 194, 200) holds **no** admin assignment, so after this story all 8 threads would 403 and the test would prove nothing. Split into three deterministic harnesses, all keeping the 8-thread + `CyclicBarrier` + `Future` shape and the rule that **any unexpected exception type** (raw `DataAccessException`, `CannotAcquireLockException`, `PessimisticLockingFailureException`) **fails the test loudly**:

| Harness | Fixture | Expected outcomes | Proves |
|---|---|---|---|
| **A** `should_completeWithoutDeadlock_when_eightConcurrentRevokesRaceWithAnActiveAdminCaller` | Fresh tenant; 3 active `TENANT_ADMIN` assignments (`R_caller` = actor, `R_a1`, `R_a2`); 8 threads split 4/4 on `a1`/`a2` | `SUCCESS == 2`, `LOST_RACE == 6`, `LOCKOUT == 0`, zero unexpected exceptions; tenant retains ≥1 active admin | D2 directly, 8-way. **Deadlocks under the rejected ordering** |
| **B** `should_blockEveryThread_when_eightConcurrentSelfRevokesRaceForTheLastAdmin` | Fresh tenant; exactly 1 active `TENANT_ADMIN`, held by the actor; all 8 threads revoke **self** | `LOCKOUT == 8`, `SUCCESS == 0`, row still active | AC5 fires under a real race, in the only population §6.4 leaves reachable |
| **C (new)** `should_completeWithoutDeadlock_when_mixedPrivilegedRoleChangesRaceAcrossBothVerbs` | Fresh tenant; ≥3 active admins; one dangerous custom role; one non-admin `user:write` principal. 8 threads split across `revoke(TENANT_ADMIN)`, `assign(TENANT_ADMIN)`, `revoke(dangerousCustomRole)`, `assign(dangerousCustomRole)`, and a **denied** non-admin `revoke(TENANT_ADMIN)` (the X-lock-then-403 path of T-D11) | Every thread terminates with one of the **expected** outcomes for its role (204 / 201 / 409 / 403); **zero** unexpected exception types; tenant still has ≥1 active admin | §7.2 property 3's cross-method claim, which A and B (homogeneous, single-verb) structurally **cannot** exercise |

Also in this task: `should_blockRevocation_when_differentAdminAttemptsTheRevocation` (137–163) becomes a **semantic rewrite** — rename to `should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin`, assert `InsufficientPermissionException` / `NOT_TENANT_ADMIN`, **keep the "row must remain active" assertion** (still the load-bearing invariant), and cite §6.4 in a comment so the next reader learns *why* the 409 became a 403. Against a real database this caller genuinely holds no admin assignment, so the IT tells the operational truth while T-009's renamed unit test keeps the guard-shape proof.

**Harness C's Javadoc must carry the RES-10 diagnostic instruction:** if C surfaces a deadlock, the first question is whether it is the **pre-existing** `assign(TENANT_ADMIN)` × `revoke(TENANT_ADMIN)` cycle (S on the caller's row + insert-intention in the `role_id` gap, versus M1's next-key range lock) — check whether the cycle involves an insert-intention lock from `assign`. That cycle is real **today**, unchanged by this story, and must not be recorded as a US-016 regression. The point of naming RES-10 is that this diagnosis is available to whoever sees the failure at 3 a.m.

**Dependencies:** T-010, T-014
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java`
**Files created:** none
**Complexity:** L
**Risks:**
- **A-5 / throttle interference — flagged here because this task is the exposed one.** Harness C runs a **denied** non-admin thread; with `max-denials=5` the throttle may suppress denials mid-run, silently reducing the number of X-lock-then-403 paths exercised and making the harness pass for the wrong reason. **Resolution: raise `max-denials` for this IT via `@DynamicPropertySource`/`@TestPropertySource`** and assert the throttled 403 separately (T-010 unit tests, T-017). Note the Spring Boot 4 property-precedence gotcha: `DynamicPropertyRegistrar` runs after component scan, so a property consumed by a `@Component`'s `@ConditionalOnProperty` cannot see it — the throttle properties are plain `@Value`s, not conditionals, so this is safe, but verify rather than assume.
- Scenarios 1, 4 and 5 pass **genuinely unmodified** (in all three the actor *is* the admin being revoked, so the gate passes; scenario 5's `anyMatch(contains("for update"))` also survives the added `for share`). If any of them needs editing, that is a signal the gate is wrong — investigate before editing the test.
- Flakiness is the enemy of a concurrency proof. Use the existing `CyclicBarrier` + `Future` shape and outcome-counting assertions; do not introduce sleeps.
**Testing requirements:** Integration — the three harnesses plus the rewritten scenario. Run the whole class with Docker up before calling this done.
**Definition of Done:** A, B and C all green with zero unexpected exception types; the 409→403 scenario renamed, asserting `NOT_TENANT_ADMIN`, retaining the row-still-active assertion, citing §6.4; harness C's Javadoc carries the RES-10 diagnostic; scenarios 1/4/5 show **no diff**. **Discharges design §7.4 and §11.2 MC-4 — i.e. the mechanical proof of D2's deadlock fix.**

---

### T-016 — Invert `RoleAssignmentEscalationIT` and add the `operation` metadata assertion to `RoleAssignmentAuditIT`

**Description:** Two durable-evidence tests. The first is the **highest-signal change in the story**.

**`RoleAssignmentEscalationIT`** currently contains `should_incrementBothCountersAndSucceed_when_adminAttachesDangerousPermissionAndNonAdminSelfAssigns` — a test that **asserts the vulnerability**. It must be **inverted, not deleted**:
- rename to `should_denyAndAudit_when_nonAdminSelfAssignsANowDangerousRole`;
- **keep** the `dangerous_permission_granted` assertion (the mint side is unchanged and still legitimate);
- assert **403 / `NOT_TENANT_ADMIN`**;
- assert the `ROLE_ASSIGNMENT_DENIED` row exists **with `operation="assign"` in its metadata** (D17's end-to-end proof);
- assert `self_role_assignment` did **not** increment.
- **This must not land as a silent diff.** The test's own Javadoc/comment must be rewritten to say that it now proves **closure** rather than exposure, and must name what it is evidence *for*: **the T-E16-direct-path and T-E17 closure — explicitly NOT T-E21's**, which survives and has its own test (T-018). The design's instruction is to replace the historical assertion with a closure reference, never to delete it; a reviewer reading the diff must be able to see the inversion was deliberate.

**`RoleAssignmentAuditIT`** gains a metadata assertion for `operation` on the denial row (both `"assign"` and `"revoke"` shapes), completing D17's chain from the service call through the adapter to `auth_events`.

**Dependencies:** T-007, T-009, T-011
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentEscalationIT.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java`
**Files created:** none
**Complexity:** M
**Risks:**
- Deleting the old test instead of inverting it destroys the epic's only executable record of what the vulnerability was — the exact failure mode US-015's "replace, never delete" discipline exists to prevent, applied to tests rather than Javadoc.
- Over-claiming in the renamed test's Javadoc (e.g. "closes RES-1") would re-commit the RC-8.3 defect at the test layer, where it is even harder to spot than in prose.
- The new counter tags mean tests asserting on `self_role_assignment` must now match **two** tags (`privileged` **and** `callerIsAdmin`); `Search.counter()` still resolves unambiguously because these tests scope by a per-test `tenantId` and each exercises one tag value (§9.2), but a two-tag match is required.
**Testing requirements:** Integration — as described, plus confirmation that the `dangerous_permission_granted` assertion still passes unchanged.
**Definition of Done:** The escalation IT asserts denial, the durable row with `operation="assign"`, and the absent canary increment; its Javadoc names T-E16-direct/T-E17 closure and **explicitly disclaims T-E21**; `RoleAssignmentAuditIT` asserts `operation` for both verbs. Discharges design §11.3's escalation-closure and D17 end-to-end items.

---

### T-017 — New revoke-symmetry IT, the stale-JWT extension, and the canary IT

**Description:** Three integration proofs that no existing test covers.

- **Revoke symmetry (new IT).** A non-admin holding `user:write` **cannot** strip a dangerous custom role, nor a `TENANT_ADMIN` assignment (T-E17 closure); an active admin still can. This is the first revoke-side authorization denial in the platform's history and needs its own end-to-end evidence.
- **Freshness on the new path.** Extend `RoleAssignmentSecurityIT`'s out-of-band-revocation + stale-JWT pattern (lines 267–305) to a **dangerous custom role**, proving the privilege path also uses the live locking read and never a JWT claim (T-S7 / T-E7). Lines 234–251 and 267–305 pass genuinely unmodified; this is an **addition**, not an edit.
- **Canary (FR-6 / D7 / D15).** An active admin self-assigning a dangerous custom role succeeds and increments `self_role_assignment{privileged="true", callerIsAdmin="true"}`; a permission-less self-assignment increments `{privileged="false", callerIsAdmin="n_a"}`. **Assert that the `callerIsAdmin="false"` series is unreachable on the success path** — that unreachability is precisely what makes it a bypass canary, and asserting it is what stops a future change from quietly making the page alert fire on the happy path.
- Optionally co-locate a single-threaded **throttle** IT here (per A-5): N+1 denials in a window ⇒ the last returns 403 with **no** new `auth_events` row and **no** `permission_denied` increment, and the state self-clears.

**Dependencies:** T-010
**Files impacted:** `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`
**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/RoleRevocationSymmetryIT.java` (name at implementer's discretion; must end in `IT` for Failsafe)
**Complexity:** M
**Risks:**
- The canary's `callerIsAdmin="false"`-is-unreachable assertion is easy to write as a tautology. Assert it against a real successful privileged self-assignment by an admin, not against an empty registry.
- A new IT class must end in `IT` or Failsafe will not pick it up (repo convention).
- The throttle IT must not run before the other assertions in a shared-class ordering, or it will poison their buckets — use a distinct tenant/actor per test.
**Testing requirements:** Integration — as described.
**Definition of Done:** All three proofs green; `RoleAssignmentSecurityIT` 234–251 and 267–305 show **no diff** (additions only); the unreachable-series assertion present. Discharges design §11.3's revoke-symmetry, freshness and canary items.

---

### T-018 — T-E21 visibility IT: the residual, made visible — not closed (D13)

**Description:** The standing evidence for RES-1(b). Exercise the pre-positioning sequence end to end:

1. A **non-admin** self-assigns a **benign** role → **201. This must still succeed.** It is legitimate, correctly ungated, and the gate must **not** fire. A test that asserts a denial here would be asserting a behaviour the design explicitly rejects.
2. An **admin** attaches `user:write` to that same role → 201.
3. Assert `holderCount == 1` in the `ROLE_PERMISSION_GRANTED` metadata, the `holders="1"` bucket tag on `nexus.rbac.dangerous_permission_granted`, and the `RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS` WARN.

**Javadoc must say, in these terms:** *this is the residual, made visible — not closed.* **This test must never be rewritten to assert a denial.** If a future story closes T-E21 by re-validating assignments at attach time, this test is rewritten **with** that story and its Javadoc rewritten with it — not before.

**Dependencies:** T-011
**Files impacted:** none
**Files created:** `nexus-backend/src/test/java/com/example/nexus/rbac/DangerousPermissionHolderSignalIT.java` (name at implementer's discretion; must end in `IT`)
**Complexity:** M
**Risks:**
- A well-meaning future reader "fixing" step 1 to assert a 403 would break the story's own design and remove the residual's only executable record. The Javadoc is the mitigation and is not optional.
- Asserting on the raw holder count instead of the bucket tag would couple the test to an unbounded-cardinality value the design deliberately does not emit.
**Testing requirements:** Integration — as described.
**Definition of Done:** Step 1 asserts **201**; steps 2–3 assert the metadata field, the bucket tag and the WARN; the Javadoc carries the "residual, made visible — not closed" statement and the do-not-rewrite instruction. Discharges design §11.3's T-E21-visibility item and is RES-1(b)'s standing evidence.

---

# Documentation

### T-019 — File ADR-0017

**Description:** Create `docs/adr/0017-privilege-based-role-assignment-gate.md` using the **verbatim** content in design §13.2. `docs/adr/` currently holds 0001–0016, so 0017 is the next free number and ADR-0001's append-only rule is satisfied. **ADR-0013 is NOT edited** and gets no second amendment section (D9): US-016 does not correct ADR-0013's D1–D6, it adds a new decision at a different layer; the two have independent lifecycles, and a standalone ADR can be superseded later (if "is this role privileged?" becomes a computed property, or if RES-3/RES-9 are taken up) without touching an ADR four stories depend on. Cross-reference 0013 from 0017 only.

`Status: Accepted`; the date is the merge date. Committed **with the implementation PR**, not before and not after.

The ADR's five decisions (D1–D5 in the ADR's own numbering, which consolidates the design body's D1–D18) must include, verbatim, the follow-on rules — in particular the one recording that the **caller**-side admin test remains **name-based by decision** while the target-side test becomes privilege-based (RES-9 / T-E26), and the one stating that a control which closes an escalation path must record, in the same change, what it does **not** close.

**Dependencies:** T-008, T-009, T-010, T-011 (the ADR asserts these behaviours exist)
**Files impacted:** none
**Files created:** `docs/adr/0017-privilege-based-role-assignment-gate.md`
**Complexity:** S
**Risks:**
- Paraphrasing instead of copying §13.2 loses the rejected-alternatives records, which are the part of an ADR that has value in two years.
- Filing it before T-011 lands would make ADR D5's "mitigation shipped here" claim false at the moment it is written.
- Editing ADR-0013 violates D9 and ADR-0001's append-only rule.
**Testing requirements:** None (documentation). Verify no markdown-lint/link-check gate in `/pre-pr-check` fails on the new file.
**Definition of Done:** File exists at the exact path with §13.2's content verbatim; `Status: Accepted` with the merge date; ADR-0013 shows **no diff**; both named follow-on rules present. Discharges design §13 / D9.

---

### T-020 — US-012 documentation: five `monitoring.md` edits and the AC5 dated amendment

**Description:** Per design §9.3 and §12.2 items 3–4.

`docs/features/US-012/monitoring.md`:
1. §1 `nexus.rbac.permission_denied` — the `NOT_TENANT_ADMIN` population widens from "AC8 assign-side grant of `TENANT_ADMIN`" to "assign **or revoke** of any privileged role (name-matched or dangerous-permission-carrying)"; note that `operation` is now in the audit metadata (D17).
2. §2 `nexus_rbac_self_escalation_attempt` — **rename to `nexus_rbac_role_change_denied_not_admin`**; **severity page → ticket**; **state explicitly that the expression is byte-identical and unchanged, and why (D6)** — it remains the zero-PromQL-edit detection *floor*, so no denial can go unobserved through a forgotten edit; add a pointer to the new page alert.
3. §2 `nexus_rbac_tenant_lockout_blocked` — meaning updated: `RBAC_002` on `TENANT_ADMIN` now means "the tenant's **sole admin** tried to remove their own admin role" (§6.4), which changes the first runbook question from "which process revoked it?" to "is this an offboarding gap for the last admin?".
4. §5 — new log rows for `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` and `RBAC_DENIAL_THROTTLE_ENGAGED`, with full field lists.
5. §1/§2 — new counter `nexus.rbac.privileged_role_change_blocked` and its **two** alerts (`…_dangerous`, page; `…_byname`, ticket); new `nexus.rbac.denial_throttled` and its ticket alert; new timer `nexus.rbac.privileged_revoke_lock_hold` with §7.5's thresholds (p99 < 50 ms expected; ticket at p99 > 250 ms over 10 m).

`docs/features/US-012/03-design.md` — an **appended, dated amendment** (following ADR-0013's "nothing above this line is edited" precedent) recording that AC5's reachable population narrows to self-revocation **and** that the ≥1-admin invariant is now enforced *more* strongly by the gate, citing US-016 and ADR-0017. US-012's Gate 1 Resolution 5 carries the same amendment.

**Dependencies:** T-009, T-010, T-019
**Files impacted:** `docs/features/US-012/monitoring.md`, `docs/features/US-012/03-design.md`
**Files created:** none
**Complexity:** M
**Risks:**
- **Editing the `nexus_rbac_self_escalation_attempt` expression** would destroy D6's entire point. The rename and the demotion are the only permitted changes; the PromQL is byte-identical.
- Recording the AC5 change as a pure narrowing (a loss) invites a future reader to delete the guard as dead code. The amendment **must** state the strengthening as well (RC editorial 3 / T-E24).
- Editing above the amendment line breaks the append-only precedent this repo uses for shipped design docs.
**Testing requirements:** None (documentation). Cross-check every alert name and expression against the code that emits the metric — a monitoring doc that names a metric the code does not emit is worse than no doc.
**Definition of Done:** All five monitoring edits applied; the demoted alert's expression proven unchanged by diff; the AC5 amendment dated, appended (nothing above the line edited) and stating both the narrowing and the strengthening. Discharges design §9.3's US-012 edits and §12.2 items 3–4.

---

### T-021 — US-015 documentation: five `monitoring.md` edits and the **correct** RES-1 / T-E16 / T-E17 register update

**Description:** Per design §9.3 and §12.2 items 5–6. **Item 6 is the most consequential documentation change in this story and the easiest to get wrong.**

`docs/features/US-015/monitoring.md`:
6. §1 `nexus.rbac.self_role_assignment` — add the `privileged` **and `callerIsAdmin`** tags and their emission rules.
7. §2 `nexus_rbac_self_role_assignment` — split into the two alerts: `nexus_rbac_gate_bypass_canary` (`{privileged="true", callerIsAdmin="false"}`, **page**) and `nexus_rbac_admin_privileged_self_assignment` (`{privileged="true", callerIsAdmin="true"}`, ticket). Replace the meaning/action text with the canary semantics **including the mandatory caveat**: this canary can only ever detect a bypass **inside** the gate's own logic (M5 answering the wrong question — T-E22's two fail-open axes, or an M8 resolution bug), **not a bypass around it**, because on the success path `privileged="true"` implies the gate ran and passed. First response step: confirm against `auth_events` whether the actor held an active `TENANT_ADMIN` assignment at that instant; if not, flip `feature.nexus-us012-rbac-role-assignment.enabled` to `false` and page Security.
8. §1 `nexus.rbac.dangerous_permission_granted` — add the `holders` bucket tag and D13's emission rule; add the `nexus_rbac_dangerous_permission_granted_to_holders` ticket alert (`{holders!="0"}` over 15 m).
9. §5 — new log row `RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS`; `ROLE_PERMISSION_GRANTED` gains `holderCount`.
10. §3 "Self-role-assignment rate (RC-7)" panel — group by `(tenantId, privileged, callerIsAdmin)`.

`docs/features/US-015/03b-threat-model.md` §4.5 and §5 — **do NOT flip RES-1 wholesale to "closed"** (RC-8.2). Record exactly:
- **T-E17 → closed**, citing US-016 (no surviving variant was constructible).
- **T-E16 → closed for the direct propagate path only**; the attach-after-assign path is **carried forward as US-016 T-E21 / RES-1(b)**, **mitigated (not closed)** by US-016 D13.
- **RES-1 → partially closed**, with **the existing owner (Md Nisar Ahmed), the 2026-11-27 review date and the Epic-3 kickoff hard expiry all transferring to the surviving component.**

Flipping the register wholesale would delete its only record of the surviving path, three weeks before the Epic 3 kickoff that RES-1's own hard-expiry clause names — the precise failure mode US-015's "replace, never delete" discipline exists to prevent.

**Dependencies:** T-008 (canary tags), T-011 (D13 must be in the code before the register claims its mitigation), T-019
**Files impacted:** `docs/features/US-015/monitoring.md`, `docs/features/US-015/03b-threat-model.md`
**Files created:** none
**Complexity:** M
**Risks:**
- **The single highest-value error available in this story is marking RES-1 "closed".** It is one word, it is plausible, and it deletes the register's only record of a live escalation primitive. Treat any diff that removes RES-1's owner, review date or expiry as a defect.
- Writing the canary edits before T-008 lands would document tags the code does not emit.
- Omitting the "inside, not around" caveat oversells the canary to whoever is paged by it at 3 a.m.
**Testing requirements:** None (documentation). Cross-check tag names character-for-character against the emitting code.
**Definition of Done:** All five monitoring edits applied and cross-checked against the code; the threat-model register records T-E17 closed, T-E16 partially closed, RES-1 **partially** closed with owner/date/expiry intact and transferred to component (b); the "inside, not around" caveat present. Discharges design §9.3's US-015 edits and §12.2 items 5–6 as corrected by RC-8.2.

---

### T-022 — Create `docs/features/US-016/monitoring.md` and `runbook.md`; draft the release-note sentences

**Description:** Per design §9.3 and §12.2 items 12–13. Repo convention is that `monitoring.md` documents **what shipped, verified against the code**, so this is scheduled for **Phase 8** — after the staging soak produces the numbers, not before.

`docs/features/US-016/monitoring.md` — required content is fixed by the design and is not at the author's discretion: every §9.2 signal (the WARN, the D15 counter, the canary's two tags, `denial_throttled`, the throttle WARN, the D18 timer, the `holders` bucket, both new metadata fields); the retargeted canary and its caveat; D14's `max-denials`/`window-seconds` **values**; §7.5's lock-hold ceiling **and its staging-measured baseline** (p50/p95/p99 captured in rollout step 2); the `ROLE_ASSIGNMENT_DENIED` **PRIORITY-lane exclusion** note from §9.1 — including the standing instruction that **any future story moving that event into the PRIORITY lane must re-open T-D10 first**; A-2's per-JVM throttle caveat; and pointers to the US-012/US-015 edits.

`docs/features/US-016/runbook.md` — must contain: the gate-bypass canary procedure with its "inside, not around" caveat; the D13 holder-count review procedure (for `holders != "0"`, list the holders with §10.4's step-2 SQL and confirm each is expected); the throttle procedure **including RES-11** (a throttled actor is also denied benign role changes for the rest of the window — expected and self-clearing); the kill-switch procedure (§10.2) **with the sentence that flag-off is an availability lever, not a security one** (handed over from T-013); RES-5's "slow 403 + `RBAC_AUDIT_WRITE_LOST` under pool pressure" note; and §10.4's **complete exposure-audit SQL** (all four statements) together with the two paragraphs explaining why the point-in-time check replaced the current-admin comparison, and the three accepted blind spots.

**Release notes** — both §10.4 sentences, **both** of them: the forward-only sentence *and* the attach-after-assign sentence. Shipping only the first would let "the escalation gap is closed" be read as "existing escalated assignments were revoked".

**Dependencies:** T-020, T-021 (so the pointers resolve), plus the Phase 8 staging soak for the timer baseline
**Files impacted:** none
**Files created:** `docs/features/US-016/monitoring.md`, `docs/features/US-016/runbook.md`
**Complexity:** M
**Risks:**
- Writing `monitoring.md` from the design instead of from the shipped code reproduces the design's intent, not the system's behaviour — the one thing this repo's convention exists to prevent.
- Copying §10.4's SQL partially (e.g. dropping the fourth statement, the admin-status-at-that-time query) silently restores the false-negative behaviour RC-13 removed.
- Omitting the second release-note sentence is the documentation-layer version of over-claiming closure.
**Testing requirements:** None (documentation). Every metric name and tag must be grepped against the code that emits it; every SQL statement must be executed once against a staging database and confirmed to run.
**Definition of Done:** Both files exist with the required content; the lock-hold baseline is a **measured** figure, not an estimate; all four exposure-audit statements present and each executed once; both release-note sentences drafted; the PRIORITY-lane re-open instruction present. Discharges design §9.3's US-016 deliverables and §12.2 items 12–13.

---

### T-023 — EPIC-002 status update, backlog filings, and the merge checklist

**Description:** The process items the design and threat model make **merge-blocking**. Explicit tasks, not afterthoughts folded into a code task's DoD.

1. **`docs/story/2-rbac/EPIC-002.md`** — the US-016 section (currently at line ~753, carrying a "Gate 1 note" and `_(unestimated — pending Gate 1)_` / `_(unscheduled)_` placeholders) is updated to record implementation status, the Gate 2/Gate 3 outcomes, and — importantly — that the story closes **T-E9 and T-E17 outright and T-E16's direct propagate path only**, with T-E21 / RES-1(b) surviving. The epic's Risks table row about RES-1/R-3 must be updated in the same way, not deleted.
2. **File the RES-3 backlog story** — "extend last-admin lockout protection to admin-equivalent custom roles" (Gate 1 #8; explicitly out of scope here). **This story must exist with an id before US-016 merges** (threat-model merge checklist, following the US-015 §4.5 precedent). One line of scope: AC5's lockout and `RbacZeroActiveAdminsHealthIndicator` are both name-based, so a tenant can be zeroed out of an admin-equivalent custom role invisibly; US-016 strengthens the case (§6.4 corollary) and pairs it with RES-9 as one Epic-3 question.
3. **File the RES-10 backlog observation** — "pre-existing `assign(TENANT_ADMIN)` × `revoke(TENANT_ADMIN)` lock cycle", **as an observation, not a US-016 fix**, so that a harness-C failure is attributed correctly.
4. **Record the merge checklist** (design §14): RES-1(b) has a named owner (Md Nisar Ahmed), the inherited **2026-11-27** review date and the **Epic-3 kickoff hard expiry**; RES-3's backlog id exists; RC-8 part 3's outcome (**shipped in this story as D13**) is recorded in design §12.3; `./mvnw dependency:tree` and `npm audit` are run at **Phase 7** (no manifest delta exists today — verified, so there is nothing to scan earlier, but they are not to be skipped).

**Dependencies:** T-019, T-020, T-021, T-022
**Files impacted:** `docs/story/2-rbac/EPIC-002.md`, `docs/features/US-016/03-design.md` (§12.3 merge-checklist annotations only)
**Files created:** backlog entries (tracker or `docs/story/`, per the repo's filing convention for RES-3 and RES-10)
**Complexity:** S
**Risks:**
- These are the items most likely to be dropped under merge pressure, and two of them (**RES-3's id, RES-1(b)'s owner/expiry**) are explicit **merge blockers** in the threat model's own checklist. Dropping them repeats the exact pattern US-015's Gate 2 built this discipline to prevent.
- Updating the epic to say "closed" rather than "partially closed" would contradict T-021 and ADR-0017's D5 in the same repository.
**Testing requirements:** None (process/documentation).
**Definition of Done:** EPIC-002's US-016 section reflects the shipped scope and the **partial** closure; RES-3's backlog entry exists **with an id**; RES-10 filed as an observation; all four merge-checklist items recorded and verifiable. Discharges design §12.2 item 14 and §14's merge checklist.

---

## Sequencing summary

```
T-001 (gate)
  └─> T-002 ──> T-005 ──┐
  └─> T-003 ──> T-006 ──┤
  └─> T-004 ──> T-007 ──┤
                        ├─> T-008 ──> T-009 ──> T-010 ──> T-014 ──> T-015
                        └─> T-011 (parallelisable with T-008/T-009 in principle)
                                     │
                        T-012 <──────┤ (needs T-005 + T-011)
                        T-013 <──────┤ (needs T-010 + T-011)
                        T-016 <──────┤ (needs T-007 + T-009 + T-011)
                        T-017 <──────┤ (needs T-010)
                        T-018 <──────┘ (needs T-011)

Docs (late, explicit, not folded into code tasks):
  T-019 (ADR) ──> T-020 (US-012) ──> T-021 (US-015) ──> T-022 (US-016 mon/runbook) ──> T-023 (epic + backlog + merge checklist)
```

**Critical path:** `T-001 → T-002 → T-005 → T-008 → T-009 → T-010 → T-014 → T-015 → T-022 → T-023`.

**Hard ordering constraints that are not negotiable:**
- **T-002/T-005 before T-008.** The gate cannot be written, let alone unit-tested against a mocked port, before M7/M8 exist; and `main` does not compile between the port declaration and the adapter implementation.
- **T-014 before T-015.** MC-5 may legitimately fail and change the design; harness C run against an unproven access-path premise would pass for the wrong reason.
- **T-010 before T-015.** The throttle changes what harness C's denial threads do (A-5).
- **T-011 before T-019 and T-021.** ADR-0017's D5 and US-015's corrected register both *claim* the D13 mitigation exists; neither may be written before it does.
- **T-008/T-009/T-011 all before T-023.** The story's threat-model closure claims (§12.2 item 6) are only true once all three have landed.
