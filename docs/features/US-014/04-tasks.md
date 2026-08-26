# Task Breakdown — US-014: Audit role assignment and revocation events

**Epic:** EPIC-002 (RBAC Foundation) · **Story points:** 3 · **Phase:** 4 (task breakdown)
**Branch:** `feature/US-014` · **Repo root:** `C:\entomo\AI\nexus`

**Inputs (all read in full for this breakdown, not paraphrased from summaries):**
`docs/features/US-014/03-design.md` (Gate 2 APPROVED — authoritative) · `docs/features/US-014/03b-threat-model.md` (Gate 2 APPROVED, all 8 "required before `/breakdown` closes" items folded in below) · `docs/features/US-014/02-impact.md` (F1-F4) · `docs/features/US-014/01-requirements.md` (§7 Decisions 1-5, binding)

**Code re-read to ground every path, signature, and line number below (no path or method name in this document is inferred):**
`rbac/application/RoleAssignmentService.java` · `rbac/application/port/out/RbacAuditPort.java` · `identity/infrastructure/audit/RbacAuthEventAdapter.java` · `identity/domain/AuthEventType.java` · `rbac/application/RoleAssignmentServiceTest.java` · `identity/infrastructure/audit/RbacAuthEventAdapterTest.java` · `identity/domain/AuthEventTypeTest.java` · `rbac/RoleAssignmentAuditIT.java` · `identity/infrastructure/persistence/AuthEventsAppendOnlyIT.java` · `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md`

**Shape of the story:** 4 production files modified (0 new), 4 test files modified (0 new), 1 ADR amended. **Zero DB migration, zero API/controller diff, zero frontend diff, zero new dependency, zero new class, zero new ArchUnit rule.** ~40-55 production lines, 9 new test methods, ~8 mechanical assertion updates.

**Note on structure:** this breakdown was originally sequenced as 10 fine-grained tasks (T-001…T-010); at the user's request they are grouped here into **2 implementation tasks** — Task 1 (production code) and Task 2 (tests, hardening, observability, docs). Every original task survives as a lettered subtask so dependency order, risk, and Definition-of-Done detail are not lost — only the top-level grouping changed.

---

## 0. Scope resolution — which denial throw sites are in scope (resolved, not deferred)

An earlier scope summary characterised AC4's scope as "**T1 and T2 only, T3 explicitly excluded**". **That characterisation is incorrect** and is not adopted here. Resolved against the two sources of truth: the design's decision register and the real code.

| Source | What it says about T3 (`NOT_TENANT_ADMIN`, `RoleAssignmentService.java:110`) |
|---|---|
| `01-requirements.md` §7 Decision 2 (binding) | "**Scope — 403s only (`CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`).** The two 409 conflicts … are excluded" — T3 named **in** scope by its reason |
| `03-design.md` §0 decision 3 | "one `try/catch` … around the two tenant checks in each of `assign`/`revoke`, **plus one inline call immediately before the T3 throw (`:110`)**" |
| `03-design.md` §2.2 | A dedicated sequence diagram titled "T3 — `NOT_TENANT_ADMIN` denial on `assign` (inline, no try/catch needed)" |
| `03-design.md` §3.3 | Shows the literal T3 emission block (`recordDenial(actor, targetUserId, roleId, role.getName(), DenialReason.NOT_TENANT_ADMIN, requestContext); // T3`) |
| `03-design.md` §8.1 | Row "Granting `TENANT_ADMIN` without being one (T3) … Denial audit row? **Yes**" |
| `03-design.md` §12.1 rows 3-4, §12.4 item 2 | Four T3 unit-test updates and a dedicated T3 integration test (`should_writeRoleAssignmentDeniedRow_when_assignFailsWithNotTenantAdmin`) |
| `03b-threat-model.md` §0.1 row 1, T-R5 table row 3 | T3 confirmed in scope; called "high-signal … reachable today *only* by a revoked admin re-attempting escalation inside their stale token window" |

**No internal ambiguity or contradiction exists in the design on this point** — all seven references agree.

### 0.1 The authoritative in-scope set (binding for Task 1d and all test subtasks)

**In scope — 5 audited denial paths across 3 emission call sites, all `InsufficientPermissionException` / HTTP 403:**

| # | Throw site (verified line) | Reason | Reached from | Emission mechanism | `roleName` in the row |
|---|---|---|---|---|---|
| T1 | `verifySameTenant` → `throw` at `RoleAssignmentService.java:304` | `CROSS_TENANT_TARGET` | `assign` `:95` | call-site `try/catch` #1 | **null** (role not yet resolved) |
| T2 | `resolveRoleInTenant` → `throw` at `:319` | `CROSS_TENANT_TARGET` | `assign` `:96` | call-site `try/catch` #1 | **null** (helper throws without returning the `Role`) |
| T3 | inline in `assign`, `throw` at `:110` (AC8 block `:98-112`) | `NOT_TENANT_ADMIN` | `assign` only | inline statement immediately before the throw | **present** — a case variant of `TENANT_ADMIN` |
| T1 | same helper, `:304` | `CROSS_TENANT_TARGET` | `revoke` `:181` | call-site `try/catch` #2 | **null** |
| T2 | same helper, `:319` | `CROSS_TENANT_TARGET` | `revoke` `:182` | call-site `try/catch` #2 | **null** |

**Explicitly out of scope (each is a decision with a named enforcement mechanism, not an omission):**

| Excluded path | Enforced by |
|---|---|
| `listActive`'s T1 403 (`:257` → `:304`) — the read path | **Convention plus one build-blocking test**, *not* structure (threat model T-E14 corrected the design's original "structurally impossible" claim). The binding control is the new `verifyNoInteractions(rbacAuditPort)` in Task 2a / protected by Task 2d |
| 409 `DuplicateRoleAssignmentException` (`:124`) | **Structural** — the `catch` *type* is `InsufficientPermissionException`; this is an unrelated type |
| 409 `LastAdminRoleException` (`:204`) | **Structural** — same |
| 404 `ResourceNotFoundException` (`:302`, `:317`, `:330-333`) | **Structural** — same |

---

## 1. Task tree

```
Epic: US-014
├─ Database (migrations / schema) ....................... NO TASKS — see §2
├─ Backend
│   ├─ Domain ......................................... Task 1b
│   ├─ Application .................................... Task 1a, Task 1d
│   ├─ Infrastructure .................................. Task 1c
│   └─ Interfaces (controllers) ....................... NO TASKS — see §2
├─ Frontend ................................................ NO TASKS — see §2
├─ Cross-cutting (security, flags, observability) ....... Task 2d, Task 2e
├─ Tests .................................................... Task 2a, Task 2b, Task 2c
└─ Documentation ............................................ Task 2f
```

**Two tasks, in dependency order:**

```
┌─────────────────────────────── TASK 1 ───────────────────────────────┐
│  1a (port) ──┬──► 1c (adapter) ──► [1a+1b+1c done] ──► 1d (service)  │
│  1b (enum) ──┘                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼  (Task 2 depends on Task 1 in full)
┌─────────────────────────────── TASK 2 ───────────────────────────────┐
│  2a (service unit tests) ◄── 1d          2b (adapter unit tests) ◄── 1c │
│  2c (integration tests)  ◄── 1c + 1d                                  │
│  2a + 2b + 2c ──► 2d (protect load-bearing tests)                     │
│  1c ──► 2e (observability / rollout)                                  │
│  1b ──► 2f (ADR 0011 amendment)                                       │
└────────────────────────────────────────────────────────────────────────┘
```

Task 1 must be implemented and green before Task 2's test subtasks are written against it (2a/2b/2c reference the exact production shapes Task 1 produces). In practice 1a/1b can be authored together, then 1c, then 1d — that internal order is unchanged from the original breakdown, just no longer exposed as separate top-level tasks.

---

## 2. Groups with zero tasks (stated explicitly, not silently omitted)

| Group | Why empty — verified, not assumed |
|---|---|
| **Database (migrations / schema)** | **No task.** `ROLE_ASSIGNMENT_DENIED` (22 chars) is a *data value* in `event_type VARCHAR(64)` and `"DENIED"` (6 chars) a data value in `outcome VARCHAR(20)`, neither under a CHECK constraint (`V2__identity_schema.sql:80-81`). No new `V<N>__*.sql`, no index, no constraint, no grant change. `ddl-auto=validate` cannot fail as a result of this story; ADR 0003's additive-migration rule is not engaged. **No data migration, no backfill, no expand/contract.** AC5 deliberately adds **no** composite `(tenant_id, user_id, event_type)` index (accepted per requirements R-5; served by the three existing single-column-paired indexes `V2:88-90`). |
| **Backend / Interfaces (controllers)** | **No task.** `rbac/interfaces/rest/UserRoleController.java` and every DTO have a **verified zero diff** — guaranteed by the `listActive` exclusion (design §0 decision 2, §13). No new endpoint, no changed endpoint, no DTO change, no status-code change, no OpenAPI diff. `common/web/GlobalExceptionHandler.java` is likewise untouched (requirements §7 Decision 5, Risk R-3 resolved structurally). |
| **Frontend (both sub-groups)** | **No task.** Zero files under `nexus-frontend/` change: no component, route, guard, service, store, Vitest spec, Playwright spec, or `package.json`/lockfile touch. The HTTP contract is bit-identical before and after (design §5); the audit-log UI is Epic 7. |
| **Caching** | **No task, deliberately.** `PermissionCachePort.evict` is **not** called on a denial: no permission state changed, and evicting would hand a denial-triggering caller a free cache-invalidation lever. Pinned by the retained `verifyNoInteractions(permissionCachePort)` assertions in Task 2a. |
| **Feature flag** | **No task.** `UserRoleController` already carries `@ConditionalOnProperty(name = "feature.nexus-us012-rbac-role-assignment.enabled")`, which switches off the only two paths that can reach the new emission. A second flag would be redundant over the same surface. |

---

## 3. Prerequisite NOT owned by this story

**P-0 — the documented verification gate does not currently run on this branch (threat model T-T9, Low-Medium).** Per the user, the staged `.mvn/*`/`pom.xml` changes on this branch are the user's own in-progress work, not an US-014 task — recorded here only as a standing awareness note, since it **gates the evidence this story exists to produce**: wherever a Definition of Done below says "gate green", run with the build cache disabled (`-Dmaven.build.cache.enabled=false`) or `mvn clean verify`, so cached success is never mistaken for evidence.

---

## TASK 1 — Implement `ROLE_ASSIGNMENT_DENIED` audit emission (production code)

**Combines original T-001, T-002, T-003, T-004.** **Complexity: M-L** (sum of S + S + S-M + M). **Files:** 2 production files modified in the port/domain layer, 2 more in infrastructure/application — 4 total, 0 new.

**Dependencies:** none (first task). **Task 2 depends on this task in full.**

### 1a. Add `recordRoleAssignmentDenied` to `RbacAuditPort`

Add one method to the outbound audit port:

```java
void recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason);
```

plus one import (`com.example.nexus.common.security.DenialReason`) and the Javadoc verbatim from design §3.1, stating four load-bearing points: (a) same "MUST NEVER throw or block" contract as the two existing success methods; (b) called **inline, before the caller throws, from a transaction about to roll back** — durability rests entirely on the implementation committing via an independent `REQUIRES_NEW` transaction; (c) scoped to the two 403 reasons (`CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`), never the 409s or 404s; (d) **never called from a read path** — a read-path "denied" event is a semantic mislabel and would widen the emitting population from `user:write` holders to every `user:read` holder, i.e. every self-registered `MEMBER` (threat model T-E14 mitigation 3).

**`RbacAuditEvent` is NOT modified — zero diff, deliberately** (design decision 1, impact F1). For a denial its 6 existing components read: `tenantId` = **actor's** tenant, `targetUserId` = target, `roleId` = requested role id (always present), `roleName` = resolved role name **or null**, `actorUserId` = attempting actor, `requestContext` = the request's context. Widening the record would break 17 positional construction sites across 4 files, 14 of them test-only.

**Files:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java` (+1 import, +1 method, +Javadoc; currently 22 lines).

**Risks.** Interface addition breaking other implementers — **verified none**: `RbacAuthEventAdapter` (`identity/infrastructure/audit/RbacAuthEventAdapter.java:45`) is the sole `implements RbacAuditPort`; `RoleAssignmentServiceTest:59` mocks the interface and `RoleAssignmentCacheIT:75` autowires it — neither breaks. The build will not compile between 1a and 1c landing — expected. ArchUnit risk: none — `DenialReason` lives in `..common.security..`, already imported by `RoleAssignmentService:5`; no new class crosses the port, so all three existing rules (`domain_and_application_must_not_depend_on_spring_security`, `rbac_application_methods_must_not_accept_principal_or_map`, `rbac_must_not_depend_on_identity`) stay green with **no new ArchUnit rule**.

**Definition of Done (1a).** Method + import present; `RbacAuditEvent.java` zero diff; Javadoc states all 4 points; `HexagonalArchitectureTest` green.

### 1b. Add `AuthEventType.ROLE_ASSIGNMENT_DENIED`, deliberately NOT in `PRIORITY`

Two changes to `identity/domain/AuthEventType.java` plus two mechanical follow-ons in its test:

1. Add the constant after `ROLE_REVOKED` (`:45`) — enum goes from **22 to 23** constants: `ROLE_ASSIGNMENT_DENIED("ROLE_ASSIGNMENT_DENIED")`, with a comment pointing at the `PRIORITY` comment for the exclusion rationale.
2. Add one paragraph to the comment above `PRIORITY` (`:47-50`) recording the exclusion, verbatim from design §3.2. **The `EnumSet` body (`:51-58`) and `isPriority()` (`:79-81`) are UNCHANGED.**
3. `AuthEventTypeTest.java`: `should_defineAllTwentyTwoConstants_when_valuesCalled` (`:102`) → `hasSize(23)` + add `"ROLE_ASSIGNMENT_DENIED"` to the list, rename to `should_defineAllTwentyThreeConstants_when_valuesCalled`. Add `should_returnFalse_when_isPriorityCheckedOnRoleAssignmentDenied` — a test named after the decision itself, so a future "for consistency with `ROLE_ASSIGNED`" edit fails a test whose name states why it shouldn't.

**Why the exclusion (do not paraphrase as "attacker-triggerable" — found factually wrong at Gate 2, corrected everywhere):** the priority lane is capacity **200**, drop-newest per lane, depth-warn at any depth ≥ 1 sustained 1 min → ticket, ≥ 180 → **page**. A denial row is *far cheaper per row* than a success row — no mutation, no lock, and for the cross-tenant path only a published low-entropy bootstrap-tenant role id (`V5__rbac_schema.sql:11`) — whereas `ROLE_ASSIGNED` requires an actual state mutation with guards in the way. Admitting the cheaper type into a 200-slot drop-newest lane would let a probing loop crowd out genuine `LOCKOUT`/`TOKEN_REFRESH_REUSE` arrivals and hand that caller a direct pager trigger. **Membership turns on cost-and-uniqueness per row, not mere triggerability** (read as "triggerability" the rule would also disqualify `ROLE_ASSIGNED`/`ROLE_REVOKED`, since an admin can loop assign-revoke indefinitely).

**Files:** `identity/domain/AuthEventType.java` (+1 constant, +1 comment paragraph); `identity/domain/AuthEventTypeTest.java` (1 method modified+renamed, 1 new test).

**Risks.** Someone adds the constant to `PRIORITY` "for consistency" — the single most likely regression in the story, and a security regression (lane eviction + pager DoS); mitigated by the named test plus the ADR amendment (Task 2f). Forgetting the test-count update is build-blocking, so self-reporting. **Zero edits needed** to `EXPECTED_PRIORITY` (`:18-25`), `should_containExactlySixTypes_when_priorityTrueSetCollected` (`:91-99`), or the `EXCLUDE`-mode parameterised test (`:83-89`) — if any of those three need editing, the constant was wrongly added to `PRIORITY`.

**Definition of Done (1b).** `AuthEventType.values()` has 23 entries; `PRIORITY`/`isPriority()` bodies zero diff; `should_containExactlySixTypes...` still `hasSize(6)`, untouched; new negative test passes; `AuthEventTypeTest` green (executed, not cached).

### 1c. Implement `recordRoleAssignmentDenied` in `RbacAuthEventAdapter`; parameterise `outcome`; add the `reason` metadata key

Four minimal, behaviour-preserving changes to `identity/infrastructure/audit/RbacAuthEventAdapter.java`:

1. **New override** (design §3.4) delegating to the private `record(...)` helper with `AuthEventType.ROLE_ASSIGNMENT_DENIED`, outcome `"DENIED"`, actor field `"attemptedBy"`, operation tag `"deny"`, and `reason != null ? reason.name() : null`.
2. **`record(...)` (`:76-77`) gains exactly two parameters** — `String outcome` (replacing the hardcoded `"SUCCESS"` at `:85`) and `String reasonName` — 6 params total, under Sonar S107's threshold of 7; existing `@SuppressWarnings("java:S6213")` stays.
3. **The two existing call sites become** `record(event, AuthEventType.ROLE_ASSIGNED, "SUCCESS", "assignedBy", "assign", null)` (`:67`) and the `ROLE_REVOKED` equivalent (`:72`). **This is the only change to the success paths and it must be exactly behaviour-preserving.**
4. **`buildMetadataJson` (`:115`) gains a `reasonName` parameter and one block**, positioned **after** the `roleName` block (`:124-126`) and **before** the actor block (`:127-129`) — emission order `traceId, roleId, roleName, reason, attemptedBy`.

**Everything else in `record(...)` is untouched:** pre-transaction metadata serialisation, `withUserId(event.targetUserId())` (target user is the subject, matching the `LOCKOUT` convention), `withTenantId`/`withIpAddress`/`withUserAgent`, `secureEventService.recordEvent`, and the catch-all → ERROR `RBAC_AUDIT_WRITE_LOST` + `nexus.rbac.audit_write_failed{operation}` counter.

**Why the key order is what it is (state correctly — overstated at Gate 2, corrected):** the **primary** control against metadata JSON injection is Jackson 3's RFC-8259 escaping, unchanged. Key ordering is **secondary, defense-in-depth**: MySQL's binary JSON keeps the **last** duplicate key, so emitting code-derived keys after the only attacker-influenceable value (`roleName`) means a forged key from a broken escaper lands before the real one and loses. In this story the injection surface is empty anyway — `roleName` is either absent (T1/T2) or a case variant of the literal `tenant_admin` (T3).

**Files:** `identity/infrastructure/audit/RbacAuthEventAdapter.java` (+1 override, `record(...)` +2 params, `buildMetadataJson(...)` +1 param +1 block, +1 Javadoc sentence, +1 import).

**Dependencies:** 1a, 1b.

**Risks.** **[Highest risk in the story]** Parameterising the hardcoded `"SUCCESS"` could mislabel *every* successful role assignment and revocation. Threat model T-T8 item 5: `RbacAuthEventAdapterTest:77`/`:101` (`getOutcome()=="SUCCESS"`) and `RoleAssignmentAuditIT:131`/`:160` (persisted `outcome=="SUCCESS"`) are **load-bearing — do not touch** (protected by Task 2d). Positional transposition across the four adjacent `String` parameters compiles cleanly but produces a silently mislabelled row (threat model T-S5) — caught by Task 2b's literal field assertions and Task 2a's value-equal matcher; author against the design §3.4 snippet, not from memory.

**Definition of Done (1c).** New override delegates with exactly `("DENIED", "attemptedBy", "deny", reason.name())` semantics; `reason` block sits between `roleName` and actor blocks; **every pre-existing test in `RbacAuthEventAdapterTest`/`RoleAssignmentAuditIT` passes with zero edits to assertions**; `HexagonalArchitectureTest` green.

### 1d. Emit the denial from `RoleAssignmentService` at the three in-scope call sites

The only judgement-bearing change in the story. Four edits to `rbac/application/RoleAssignmentService.java`, per design §3.3 and §0.1 above:

1. **One new private helper**, next to `registerPostCommitSideEffects` (`:343`): `recordDenial(RoleChangeActor actor, UUID targetUserId, UUID roleId, String roleName, DenialReason reason, RequestContext requestContext)`, body: `rbacAuditPort.recordRoleAssignmentDenied(new RbacAuditEvent(actor.tenantId(), targetUserId, roleId, roleName, actor.userId(), requestContext), reason);`. **`actor.tenantId()`** — the row is always written under the **actor's** tenant, never the target's.
2. **`assign()` — `try/catch` around the two tenant checks (`:95-96`).** `Role role;` declared before the `try`; `catch (InsufficientPermissionException e) { recordDenial(actor, targetUserId, roleId, null, e.getReason(), requestContext); throw e; }`. `roleName` is `null` by construction here.
3. **`assign()` — inline T3 emission** immediately before the throw at `:110`, with `role.getName()` and `DenialReason.NOT_TENANT_ADMIN`.
4. **`revoke()` — the same `try/catch` around `:181-182`**, `roleName` `null`.

**`listActive()` — zero diff.** No `try`, no `recordDenial`.

**Invariants the implementer must not "improve":** rethrow the *same* exception instance (`throw e`); read the reason from the exception (`e.getReason()`), never a duplicated literal; **do not use `registerPostCommitSideEffects`** — `afterCommit` never fires on a doomed transaction, so the call must be inline/synchronous/pre-throw, relying entirely on `SecureEventService.recordEvent`'s `REQUIRES_NEW` (design §2.3, the story's central correctness claim); **no new log statement** (`GlobalExceptionHandler:161-166` already WARNs these 403s — a symmetric service-side WARN would double the log line); **do not move the emission into `verifySameTenant`/`resolveRoleInTenant`** (the single most likely future regression — it would pull `listActive` in, which is what Task 2a's `verifyNoInteractions` exists to block); **catch `InsufficientPermissionException` only**, never widen — the catch *type* is what structurally excludes the 409s/404s.

**Files:** `rbac/application/RoleAssignmentService.java` (+1 private helper; `assign` restructured `:95-96`/`:109-111`; `revoke` restructured `:181-182`). No new import needed.

**Dependencies:** 1a. Independent of 1b/1c at compile time, but the story doesn't build end-to-end until 1c lands.

**Risks.** A denial row rolled back with the denial — the exact failure AC4 exists to prevent; only provable by Task 2c's post-throw DB read (a Mockito `verify` proves nothing about durability). `Role role;` definite-assignment gives a genuine compile-time guarantee that swallowing the denial silently is impossible. **T3 emits while TX1 holds a `FOR SHARE` lock** (`hasActiveAdminAssignment` → `@Lock(PESSIMISTIC_READ)`); no deadlock is possible (disjoint tables), but with HikariCP unconfigured (`maximumPoolSize=10`, `connectionTimeout=30s`) and `REQUIRES_NEW` suspending-not-releasing TX1's connection, a request holds **two** connections — **~5 concurrent denials saturate the pool** (threat model T-D6, Medium, accepted; watch-listed by Task 2e). New branches land in `*.application.*`, the tightest JaCoCo LINE gate — must be unit-covered by Task 2a, not only IT-covered.

**Definition of Done (1d).** Exactly **three** `recordDenial` call sites (`assign` catch, `assign` T3 inline, `revoke` catch). `listActive`, `verifySameTenant`, `resolveRoleInTenant`, `findAssignmentRefOrThrow`, `registerPostCommitSideEffects` zero diff. Same exception instance rethrown; `e.getReason()` used; no new log statement; no new import. Every pre-existing RBAC IT unmodified and green.

### Task 1 — overall Definition of Done
1. All four subtasks' individual DoDs satisfied.
2. `./mvnw verify` (Docker up, `-Dmaven.build.cache.enabled=false`) green end-to-end.
3. `HexagonalArchitectureTest` green; JaCoCo `*.application.*` and `*.infrastructure.*` LINE gates green.
4. `RbacAuditEvent.java`, `UserRoleController.java`, `GlobalExceptionHandler.java`, `JpaAuthEventRepository.java` all show zero diff.

---

## TASK 2 — Test coverage, load-bearing test hardening, observability, and ADR amendment

**Combines original T-005, T-006, T-007, T-008, T-009, T-010.** **Complexity: L** (sum of M + S-M + M-L + S + S + S). **Files:** 4 test files modified, 1 ADR doc amended, plus ops-side dashboard/alert config outside this repo. **No new test class anywhere** (requirements §7 Decisions 3 and 4) — **9 new test methods, ~8 mechanical assertion updates, 1 new private test helper.**

**Dependencies:** Task 1 in full (2a needs 1d; 2b needs 1c; 2c needs 1c+1d; 2e needs 1c; 2f needs 1b). 2d depends on 2a+2b+2c.

### 2a. `RoleAssignmentServiceTest`: 6 assertions flipped, 1 hardened (build-blocking, same commit as Task 1d)

Impact finding **F3**: seven existing methods assert `verifyNoInteractions(permissionCachePort, rbacAuditPort)` on branches Task 1d changes — six must flip to a positive assertion, one must gain a new negative assertion it currently lacks.

| Method (verified line) | Change | Proves |
|---|---|---|
| `should_throwCrossTenantTarget_when_assignTargetTenantMismatch` (`:142`) | replace `verifyNoInteractions(permissionCachePort, rbacAuditPort)` (`:153`) with `verify(rbacAuditPort).recordRoleAssignmentDenied(new RbacAuditEvent(tenantId, targetUserId, roleId, null, actorId, ctx), DenialReason.CROSS_TENANT_TARGET)` **+ `verifyNoInteractions(permissionCachePort)`** | AC4 / T1 via `assign`; `roleName` null |
| `should_throwCrossTenantTarget_when_assignRoleTenantMismatch` (`:169`) | same, `roleName` null (`:182`) | AC4 / T2 |
| `should_throwNotTenantAdmin_when_grantingTenantAdminAndCallerNotActiveAdmin` (`:186`) | same, `roleName = "TENANT_ADMIN"`, reason `NOT_TENANT_ADMIN` (`:202`) | AC4 / T3 |
| `should_throwNotTenantAdmin_when_roleNameIsDifferentCaseVariantOfTenantAdmin` (`:213`) | same, `roleName = "tenant_admin"` — the **stored** case (`:228`) | AC4 / T3 + records the role's actual name |
| `should_throwCrossTenantTarget_when_revokeTargetTenantMismatch` (`:386`) | same, `roleName` null (`:396`) | AC4 / T1 via `revoke` |
| `should_throwCrossTenantTarget_when_revokeRoleTenantMismatch` (`:412`) | same, `roleName` null (`:425`) | AC4 / T2 via `revoke` |
| `should_throwCrossTenantTarget_andNeverCallFindActiveAssignmentViews_when_listActiveTargetTenantMismatch` (`:650-661`) | **ADD** `verifyNoInteractions(rbacAuditPort);` after the existing `verify(userRoleAssignmentPort, never())...` (`:660`) | **F2 / decision 2 / T-E14** — *the* binding control on the `listActive` exclusion |

**Must NOT change** — now load-bearing negative assertions proving the 403-only scope: `should_throwDuplicateRoleAssignment_when_activeAssignmentAlreadyExists` (`:266`/`:277`), both `should_throwLastAdminRoleException_*` (`:476`/`:492`, `:500`/`:515`), all `should_throwResourceNotFound_when_*` (`:130`/`:138`, `:157`/`:165`, `:375`/`:382`, `:400`/`:408`, `:565`/`:578`), both `should_neverCallLockActiveAssignmentIds_*` (`:435`/`:448`, `:458`/`:471`), both side-effect/happy-path tests (`:100`, `:287`, `:318`/`:335`, `:354`). Formalised by Task 2d.

**Risks.** Taking the lazy fix (deleting the mock reference without adding a positive `verify`) leaves AC4 unit-untested while green — guarded by the value-equal argument. Blanket-editing all 17 `verifyNoInteractions(permissionCachePort, rbacAuditPort)` occurrences instead of only the 6 named — edit by method name, never search-and-replace. Deleting the `:650` addition later would let a read-path denial mislabel a `GET`, widening the emitting population from `TENANT_ADMIN` to every `user:read` holder (every `MEMBER`) — turning accepted-Low T-D6/T-D7 into a near-unauthenticated DoS.

**Definition of Done (2a).** Exactly 6 methods flipped with correct `roleName`/reason; `verifyNoInteractions(rbacAuditPort)` added at `:650` with a comment naming T-E14; the 12 must-not-change methods show zero diff; green, executed not cached.

### 2b. `RbacAuthEventAdapterTest`: 5 new methods for the denial path

Five new tests mirroring existing pairs (design §12.2):

| New method | Proves |
|---|---|
| `should_mapAllFieldsCorrectly_when_recordRoleAssignmentDeniedCalled` | `eventType`/`outcome`/`userId`/`tenantId`/ip/userAgent + metadata `traceId`/`roleId`/`roleName`/`reason`/`attemptedBy`; `assignedBy`/`revokedBy` both absent |
| `should_omitRoleNameKey_when_deniedEventHasNullRoleName` | T1/T2 row shape — `roleName` key **absent**, never JSON `null` |
| `should_keepRealReason_when_roleNameAttemptsDuplicateKeyInjectionOfReason` | design §4.2's ordering property: forged `reason` via `roleName` loses to the real one |
| `should_notPropagateException_when_secureEventServiceThrowsOnDenied` | port contract — never throws |
| `should_incrementAuditWriteFailedCounterWithDenyTag_when_recordRoleAssignmentDeniedFails` | design decision 9's third tag value `operation="deny"` |

**Be honest in the third test's comment** (threat model T-T8 item 3): it's a **characterisation test for key ordering**, not an escaper-failure detector — it passes under both a working and a broken escaper. **The actual escaper-failure detector already exists**: the pre-existing `duplicateKeyInjection` case targeting **`traceId`** (`:129-145`/`:147-164`), where a forged key lands *after* the real one and would **win** if escaping broke. Must not be retired as redundant — protected by Task 2d.

**Files:** `identity/infrastructure/audit/RbacAuthEventAdapterTest.java` (+5 methods; existing helpers reused unchanged).

**Risks.** This file has an embedded NUL byte (`:134`) — **ripgrep classifies it as binary and silently omits it**, so `rg` will miss all 10 `new RbacAuditEvent` sites here. **Do not size or verify edits by grep — open and read the file.** Zero `new RbacAuditEvent(...)` construction sites should change; if a diff shows one, `RbacAuditEvent` was wrongly widened — stop.

**Definition of Done (2b).** Five new methods green; `getOutcome()` assertions at `:77`/`:101` zero diff; the `traceId` injection case zero diff; JaCoCo `*.infrastructure.*` LINE gate green.

### 2c. `RoleAssignmentAuditIT`: 5 new methods + 1 new helper (AC3, AC4, AC5)

**AC4 (×2)**, beside the existing Scenario 4 block (`:221-287`):
1. `should_writeRoleAssignmentDeniedRow_when_assignFailsWithCrossTenantTarget` — after `assertThatThrownBy(...)` completes, assert `countAuditRows(target, "ROLE_ASSIGNMENT_DENIED")==1` and `countAuditRows(target, "ROLE_ASSIGNED")==0`; `outcome=="DENIED"`, `user_id==target`, `tenant_id==actorTenantId`, `reason=="CROSS_TENANT_TARGET"`, `attemptedBy==actorUser.getId()`, `roleId` present, `roleName` **null**, `traceId` matches.
2. `should_writeRoleAssignmentDeniedRow_when_assignFailsWithNotTenantAdmin` — **no existing IT covers T3.** Build the `Role` **directly** (`new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", null, false)`) — **`seedRole` cannot be reused**, it prefixes names so the literal `TENANT_ADMIN` match (`equalsIgnoreCase`) never fires. Asserts `reason=="NOT_TENANT_ADMIN"`, `roleName=="TENANT_ADMIN"`, `outcome=="DENIED"`.

> **Non-negotiable:** the row must be read **after** `assertThatThrownBy(...)` completes — the only assertion proving the `REQUIRES_NEW` write survived TX1's rollback. A Mockito `verify` proves nothing about durability.

**AC3 (×2)**, mirroring `AuthEventsAppendOnlyIT`:
3. `should_rejectUpdate_when_roleAssignedAuditRowModified` — raw insert of a `ROLE_ASSIGNED`/`SUCCESS` row, then assert `UPDATE` throws `DataAccessException` containing "append-only" with `SQLSTATE=="45000"`.
4. `should_leaveRoleAssignedAuditRowUnchanged_when_updateRejected` — same insert, swallow the exception, assert `outcome` still `"SUCCESS"`.

**AC5 (×1):**
5. `should_returnAssignThenRevokeInCreatedAtOrder_when_queryingRoleHistoryForUserInTenant` — drive a real `assign()` then `revoke()` through the autowired service (two committed transactions → two distinct `created_at` values); seed an unrelated tenant-B decoy; query the literal AC5 predicate (`tenant_id`, `user_id`, `event_type IN ('ROLE_ASSIGNED','ROLE_REVOKED')`, `ORDER BY created_at`); assert exactly 2 rows, `containsExactly("ROLE_ASSIGNED","ROLE_REVOKED")`, decoy absent, and the two `created_at` values strictly increasing (flake control for the `DATETIME(6)` tie risk). **Forbidden:** a raw-JDBC insert loop to fake the history, and any `event_type` tie-break sort key (would mask a genuine ordering regression). **No production query code** — `JpaAuthEventRepository.java` stays a bare `JpaRepository`.

**New helper:** `findLatestDenialAuditRow(UUID targetUserId)` — sibling of `findLatestAuditRow`, adds `reason`/`attempted_by` JSON extraction, filters `event_type='ROLE_ASSIGNMENT_DENIED'`. All other existing helpers reused unchanged.

**Files:** `rbac/RoleAssignmentAuditIT.java` (+5 methods, +1 helper; currently 438 lines).

**Risks.** Asserting via a port `verify` instead of a post-throw DB read leaves the entire F4 durability claim untested — the one mistake that makes this story's compliance evidence hollow. Reusing `seedRole` for the T3 fixture silently produces a non-matching role name, so T3 never fires and the test passes for the wrong reason. Requires Docker — `./mvnw verify -DskipITs` is **not** sufficient evidence for this story. **Cached-build hazard (P-0):** run with the build cache disabled and attach the Failsafe summary showing these five methods **executed**.

**Definition of Done (2c).** Five new methods + helper present; pre-existing methods (including `outcome=="SUCCESS"` at `:131`/`:160`) unmodified; both AC4 tests read post-throw; T3 test builds its `Role` directly; AC5 test matches the exact predicate/ordering/flake-control described; `JpaAuthEventRepository.java` zero diff; `./mvnw verify` (Docker up, cache disabled) green with Failsafe showing the new methods executed.

### 2d. Mark the load-bearing tests as do-not-delete / do-not-weaken

Comment-only task (no assertion changes) naming what each control protects, since each is at real risk of being "tidied away":

| # | Site | Comment must say | If removed |
|---|---|---|---|
| 1 | `RoleAssignmentServiceTest:650-661` (`verifyNoInteractions(rbacAuditPort)` from 2a) | Load-bearing — binding control on the `listActive` exclusion (decision 2 / T-E14); not compiler-enforced, this assertion is what fails | Read-path denial mislabels a `GET`, widens emitting population from `TENANT_ADMIN` to every `MEMBER` |
| 2 | `RbacAuthEventAdapterTest:129-145`/`:147-164` (`traceId` duplicate-key case) | Load-bearing — the *only* escaper-failure detector; not made redundant by the newer `reason`-ordering test (T-T8 item 3) | Metadata-injection primary control (Jackson 3 escaping) loses its only regression detector |
| 3 | `RbacAuthEventAdapterTest:77`/`:101` + `RoleAssignmentAuditIT:131`/`:160` (`outcome=="SUCCESS"`) | Load-bearing — only guard that both success call sites still pass `"SUCCESS"` after the `record(...)` parameterisation (T-T8 item 5) | Transposition at either success call site silently mislabels every successful assignment/revocation |
| 4 | The 12 negative-assertion methods listed in 2a | One block comment: now load-bearing proof of the 403-only scope (requirements §7 Decision 2), not incidental | 409/404 exclusion loses its regression guard (defense-in-depth only — the `catch` type is the structural control) |

**Files:** `RoleAssignmentServiceTest.java`, `RbacAuthEventAdapterTest.java`, `RoleAssignmentAuditIT.java` — comments only.

**Risks.** Comment-only protection is weaker than a mechanical control — accepted; threat model T-E14 rated the build-blocking test as sufficient and documentation as the right cost for a 3-point story. Reference behaviours and finding IDs in the comments, never line numbers (they drift).

**Definition of Done (2d).** All four comment sites present; `git diff` for this subtask is comment lines only; `./mvnw verify -DskipITs` green.

### 2e. Observability delta and 24-hour rollout watch list

**Code-adjacent (delivered by 1c, verify only):** `nexus.rbac.audit_write_failed{operation="deny"}` — a third tag value alongside `assign`/`revoke`.

**Explicitly NOT added:** no new counter duplicating `nexus.rbac.permission_denied`; no second WARN (the `GlobalExceptionHandler` WARN is incumbent); no new dashboard panel/trace span/denial-volume alert.

**Dashboard/alert delta:** add `operation=deny` as a legend entry to the existing `audit_write_failed` panel; extend the `RbacAuditWriteLost` alert to the new tag value (ticket severity). ADR 0011 lane alerts unchanged (STANDARD lane, so a flood trips the standard-lane depth-warn, never the priority-lane pager).

**24-hour watch list (5 signals):** (1) `audit_write_failed{operation="deny"}` stays 0; (2) `audit.buffer.depth{lane="standard"}` shows no new baseline; (3) `permission_denied` rate unchanged; (4) no new `RBAC_AUDIT_WRITE_LOST`; (5) **`hikaricp_connections_pending`/`hikaricp_connections_acquire_seconds` stay at baseline** — the signal distinguishing "the pool-pressure estimate held" from "T-D6 is live" (context: no `hikari` block in `application.yml` → `maximumPoolSize=10`/`connectionTimeout=30s`; `REQUIRES_NEW` holds 2 connections per denial; ~5 concurrent denials saturate the pool).

**Rollback triggers:** sustained `audit_write_failed{operation="deny"}`; a standard-lane depth-warn attributable to `ROLE_ASSIGNMENT_DENIED`; or sustained non-zero `hikaricp_connections_pending` correlated with `permission_denied` volume. **Mechanism:** code revert (no data rollback — `auth_events` is append-only). **Rollout:** instant/with-deploy, no canary. **Release note:** "Denied role-assignment attempts are now audited. This is forward-only: denials that occurred before this release were never recorded and cannot be reconstructed."

**Forwarded to US-015 as entry criteria:** rate limiting on the role-assignment endpoints — joining pre-existing T-E9, now also T-D6 (pool pressure) and T-D7 (volume amplification).

**Files:** dashboard/alert config outside this repository; runbook/PR description. **No `application.yml` change** — do not add a `hikari` block as part of this story.

**Definition of Done (2e).** Panel shows 3 series; alert covers `deny`; 5 watch-list signals have a captured pre-deploy baseline; 3 rollback triggers + release note in the PR description; US-015 entry-criterion line recorded.

### 2f. Append the ADR 0011 amendment (§8)

Append one new section to `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md`, verbatim from design §14, **after §7** (line 76) and **before `## Consequences`** (line 88): `### 8. Amendment (2026-08-22, US-014) — current PRIORITY membership, and one deliberate exclusion`. Amendment, not a new ADR.

Must carry: (1) a correction of pre-existing drift — ADR 0011 §1 still says the priority lane carries "exactly the four" types; it has been **six** since US-012 added `ROLE_ASSIGNED`/`ROLE_REVOKED` without amending the ADR; (2) US-014's own exclusion decision with the cost-and-uniqueness rationale and a rule of thumb for future event types (priority requires high forensic value **and** costly/non-repeatable generation, not mere triggerability); (3) the two Gate-2 factual corrections — **never** write "attacker-triggerable"/"any authenticated caller" (false: `user:write` is `TENANT_ADMIN`-only per `V5__rbac_schema.sql:130-136`), and explicitly record the coverage boundary that EPIC-002's T-E1 (self-registered `MEMBER` reaching for `TENANT_ADMIN`) is stopped at `@RequiresPermission` **before** reaching this code and is therefore **not** captured by `ROLE_ASSIGNMENT_DENIED` — forwarded to Epic 7 / the audit-coverage backlog under finding T-R5.

**Files:** `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md` (+1 section). No other ADR touched.

**Risks.** Copying the pre-Gate-2 draft wording (still present in `02-impact.md` §1.3) instead of the corrected design §14 text — this was the security review's **#1 required item before `/breakdown` closes**. Amending §1 in place instead of appending §8 — the original decision record must stay intact.

**Definition of Done (2f).** §8 appended in the right place; §1 unmodified; six-member `PRIORITY` list matches code; both Gate-2 corrections present; forwarded obligation names T-R5 and Epic 7; no new ADR file.

### Task 2 — overall Definition of Done
1. All six subtasks' individual DoDs satisfied.
2. `./mvnw verify` (Docker up, `-Dmaven.build.cache.enabled=false`) green, including every pre-existing test in all four touched files passing unmodified.
3. JaCoCo `*.application.*` and `*.infrastructure.*` LINE gates green.
4. Dashboard/alert/watch-list/ADR deliverables recorded in the PR description.

---

## 4. Traceability — every AC and every required Gate-2 mitigation lands on a task

| Requirement / finding | Task |
|---|---|
| **AC1 / FR1** (`ROLE_ASSIGNED` fields) — already DONE by US-012 | — (regression-guarded by untouched `RoleAssignmentAuditIT:116-143` and Task 2d item 3) |
| **AC2 / FR2** (`ROLE_REVOKED` + `revokedBy`) — already DONE by US-012 | — (regression-guarded by `RoleAssignmentAuditIT:148-167` and Task 2d item 3) |
| **AC3 / FR3** (append-only, RBAC-literal proof) | **Task 2c** methods 3-4 |
| **AC4 / FR4** (`ROLE_ASSIGNMENT_DENIED`, 403s only) | **Task 1** (1a-1d); proven by **Task 2a** (unit, all 5 paths) and **Task 2c** methods 1-2 (durability) |
| **AC5 / FR5** (ordered tenant+user+event_type history) | **Task 2c** method 5 (test-only; no production query code) |
| Impact **F1** (17-site fan-out avoided) | **Task 1a** — 2-param port method, `RbacAuditEvent` zero diff |
| Impact **F2** (`listActive` exclusion) | **Task 1d** (no call site) + **Task 2a** row 7 + **Task 2d** item 1 |
| Impact **F3** (build-blocking existing assertions) | **Task 2a** |
| Impact **F4** (no post-commit hook; `REQUIRES_NEW` durability) | **Task 1d** (inline pre-throw) + **Task 2c** methods 1-2 (post-throw DB read) |
| **T-R5** (coverage-boundary documentation; corrected population) | **Task 2f** |
| **T-D6** (pool pressure) | **Task 2e** watch-list item 5 + rollback trigger; risk priced in **Task 1d** |
| **T-I6** (cross-tenant subject placement) | Accepted as designed; Epic 7 forward note in **Task 2f** / **Task 2d** |
| **T-D7** (audit-volume amplification) | Accepted; US-015 entry criterion in **Task 2e** |
| **T-E14** (`listActive` control is a test, not structure) | **Task 2a** row 7 + **Task 2d** item 1 + **Task 1a** Javadoc point (d) |
| **T-I7** (403 latency leaks audit-pipeline health) | Accepted residual; no task |
| **T-T8 / T-S5** (ordering is defense-in-depth; `traceId` test is the real detector; `outcome` parameterisation) | **Task 1c** (correct framing) + **Task 2b** (honest test comment) + **Task 2d** items 2-3 |
| **T-T9** (broken wrapper, build cache, CVSS 9→9.5) | Acknowledged as the user's own in-progress branch work, out of scope for this story (see §3) |
| ADR 0011 amendment | **Task 2f** |

---

## 5. Absolute paths for the files this breakdown touches

**Production (4 modified, 0 new) — Task 1**
- `C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\port\out\RbacAuditPort.java`
- `C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\identity\domain\AuthEventType.java`
- `C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\identity\infrastructure\audit\RbacAuthEventAdapter.java`
- `C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\rbac\application\RoleAssignmentService.java`

**Tests (4 modified, 0 new) — Task 2**
- `C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\rbac\application\RoleAssignmentServiceTest.java`
- `C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\identity\infrastructure\audit\RbacAuthEventAdapterTest.java`
- `C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\identity\domain\AuthEventTypeTest.java`
- `C:\entomo\AI\nexus\nexus-backend\src\test\java\com\example\nexus\rbac\RoleAssignmentAuditIT.java`

**Docs (1 modified) — Task 2**
- `C:\entomo\AI\nexus\docs\adr\0011-in-process-bounded-retry-buffer-for-audit-writes.md`

**Referenced read-only (must show zero diff)**
- `RbacAuditEvent.java`, `UserRoleController.java`, `GlobalExceptionHandler.java`, `DenialReason.java`, `SecureEventService.java`, `JpaAuthEventRepository.java`, `AuthEventsAppendOnlyIT.java`, `HexagonalArchitectureTest.java`

---

## 6. Approval gate

**Total: 2 tasks** (Task 1 — production code, 4 subtasks; Task 2 — tests/hardening/observability/docs, 6 subtasks).
**Groups with zero tasks, stated explicitly:** Database, Backend/Interfaces, Frontend — see §2 for the verified reason in each case.

**Approval needed on:**
1. **The §0 scope resolution** — T3 (`NOT_TENANT_ADMIN`) **is** in scope, and `revoke()` is in scope, per all seven cross-checked design/requirements/threat-model references. If a narrower scope is actually wanted, that is a **design-doc amendment**, not a task-breakdown adjustment, and Gate 2 should be re-opened rather than trimmed here.

**Atlassian MCP is not connected in this session**, so no Jira sub-tasks were created or offered.
