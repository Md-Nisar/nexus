# US-014 — Impact Analysis

**Feature:** Audit role assignment and revocation events
**Epic:** EPIC-002 (RBAC Foundation) | **Story points:** 3 | **Phase:** 2 (Impact Analysis)
**Input:** `docs/features/US-014/01-requirements.md` (Gate 1 approved; §7 Decisions binding)
**Author:** Principal Architect | **Status:** Draft for Gate 2 entry

> Read-only analysis. §7 Decisions are treated as settled and are **not** re-litigated. FR1/FR2/FR3/FR4-negative are DONE (US-012 forward work) and are mapped here only where a US-014 change ripples into their existing tests.
>
> **Files read for this analysis:** `nexus-backend/src/main/java/com/example/nexus/{rbac/application/RoleAssignmentService.java, rbac/application/port/out/RbacAuditPort.java, rbac/application/port/out/RbacAuditEvent.java, rbac/interfaces/rest/UserRoleController.java, identity/domain/AuthEventType.java, identity/infrastructure/audit/RbacAuthEventAdapter.java, common/security/DenialReason.java, common/web/GlobalExceptionHandler.java}`, `nexus-backend/src/main/resources/db/migration/V2__identity_schema.sql`, `nexus-backend/src/test/java/com/example/nexus/{rbac/RoleAssignmentAuditIT.java, rbac/application/RoleAssignmentServiceTest.java, identity/infrastructure/audit/RbacAuthEventAdapterTest.java, identity/infrastructure/persistence/AuthEventsAppendOnlyIT.java, identity/domain/AuthEventTypeTest.java, architecture/HexagonalArchitectureTest.java}`, `nexus-backend/pom.xml`, `docs/adr/{0011,0013}`, `docs/features/US-012/02-impact.md`, `docs/features/US-013/02-impact.md`, `docs/story/2-rbac/US-014.md`.

---

## 0. Executive summary

Three deliverables, all additive: **AC4** (`ROLE_ASSIGNMENT_DENIED`, the only production code in the story), **AC3** (two trigger tests), **AC5** (one query test). No schema change, no API change, no frontend change, no new dependency, no new bounded context.

Four findings dominate the shape of the work:

| # | Finding | Severity |
|---|---|---|
| **F1** | Adding a 7th component to the `RbacAuditEvent` record is a **positional compile-break at 17 construction sites across 4 files**. A two-arg port signature or a sibling record breaks **zero**. This one Gate 2 choice is the difference between a ~5-file diff and a ~17-site diff. | **High** (cost, not correctness) |
| **F2** | The two in-scope 403s have **3 throw sites reachable from 5 call paths**, and one of those paths (`listActive`, the GET) has **no `RequestContext` parameter** and no `RequestContext` built in the controller. Scoping the emission to `assign`/`revoke` only is what keeps `interfaces/rest` at zero diff. | **High** (scope boundary) |
| **F3** | Seven existing `RoleAssignmentServiceTest` methods assert `verifyNoInteractions(permissionCachePort, rbacAuditPort)` on exactly the denial branches that must now interact with `rbacAuditPort`. These are **build-blocking** and must land in the same commit. | **Medium** |
| **F4** | The denial is emitted from a transaction that is **about to roll back**. `registerPostCommitSideEffects` (`RoleAssignmentService.java:343-355`) cannot be reused — there is no commit. Durability rests entirely on `SecureEventService`'s `REQUIRES_NEW` suspending the doomed outer transaction. | **Medium** (correctness, Gate 2 must state it) |

---

## 1. Modules affected

### 1.1 Backend — `rbac.application.port.out` (2 files modified)

| File | Change |
|---|---|
| `rbac/application/port/out/RbacAuditPort.java` | +1 method: `recordRoleAssignmentDenied(...)`, third sibling of `recordRoleAssigned` (`:18`) / `recordRoleRevoked` (`:21`). The interface Javadoc's "MUST NEVER throw and MUST NOT block" contract (`:9-13`) applies unchanged and must be restated for the new method. |
| `rbac/application/port/out/RbacAuditEvent.java` | **Possibly modified** — see F1 below. A denial event needs one field the current 6-component record (`:13-19`) cannot express: the denial reason. |

**F1 — the `RbacAuditEvent` fan-out (the single largest cost lever in the story).**
`RbacAuditEvent` is a `record`, so construction is positional. Adding a 7th component breaks **every** existing construction site:

| File | Sites |
|---|---|
| `rbac/application/RoleAssignmentService.java` | 2 (`:143`, `:226`) |
| `rbac/application/RoleAssignmentServiceTest.java` | 4 (`:126`, `:262`, `:371`, `:537`) |
| `rbac/RoleAssignmentAuditIT.java` | 1 (`:309`) |
| `identity/infrastructure/audit/RbacAuthEventAdapterTest.java` | **10** (`:70`, `:95`, `:114`, `:152`, `:178`, `:192`, `:202`, `:229`, `:243`, `:257`) |
| **Total** | **17** |

Three Gate 2 options, with materially different blast radii — this is a **design decision, not an impact finding**, but the impact numbers must inform it:
- **(a)** `recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason)` — 0 existing sites break. `common.security.DenialReason` is already imported by `RoleAssignmentService` (`:5`) and is not in a package banned by any ArchUnit rule (see §12).
- **(b)** A sibling `RbacDenialAuditEvent` record — 0 existing sites break; adds one file; avoids carrying a nullable-`roleName` semantic into the success record.
- **(c)** Add a 7th component to `RbacAuditEvent` — 17 mechanical edits in 4 files, of which 14 are test-only noise.

> **Tooling gotcha for whoever does the fan-out:** `RbacAuthEventAdapterTest.java` contains an embedded NUL byte (from its `controlChar` adversarial `roleName` literal at `:134`), so **ripgrep classifies it as binary and silently omits it from `rg 'new RbacAuditEvent'` counts**. Do not size this change by grep alone.

### 1.2 Backend — `rbac.application` (1 file modified)

`rbac/application/RoleAssignmentService.java` — the emission point (§7 Decision 5). **F2, the throw-site map (read, not assumed):**

| # | Throw site | Reason | Reached from | `RequestContext` in scope? | `roleName` known? |
|---|---|---|---|---|---|
| **T1** | `verifySameTenant`, throw at **`:304`** (method `:297-306`) | `CROSS_TENANT_TARGET` | `assign` `:95`, `revoke` `:181`, **`listActive` `:257`** | assign/revoke: yes. **`listActive`: NO** | **No** — this check runs *before* `resolveRoleInTenant` |
| **T2** | `resolveRoleInTenant`, throw at **`:319`** (method `:312-322`) | `CROSS_TENANT_TARGET` | `assign` `:96`, `revoke` `:182` | yes | yes — but it is a **foreign tenant's** role name (§5) |
| **T3** | inline in `assign`, throw at **`:110`** (AC8 block `:98-112`) | `NOT_TENANT_ADMIN` | `assign` only | yes | yes |

Concrete consequences to carry into Gate 2:

1. **T1 and T2 are `private` helpers that take `(targetUserId, actor, requiredPermission)` — no `RequestContext`, no `roleId`.** Emitting from inside them requires threading `RequestContext` (and, for T1, `roleId`) through both helper signatures, touching all 5 call sites. Emitting at the *call* sites instead duplicates the call 4-5 times. Either shape is small; neither is free.
2. **`listActive` (`:252`) has no `RequestContext` parameter, and `UserRoleController.listRoles` never builds one** — the controller's `requestContext(HttpServletRequest)` helper (`UserRoleController.java:242-243`) is called only from `assignRole` (`:112`) and `revokeRole` (`:169`). Including the GET's 403 in AC4 would therefore force a `listActive` signature change **plus a controller change plus a `UserRoleControllerTest` change**, i.e. it is the only thing in this story that would put `interfaces/rest` in the diff. It is also semantically wrong: a denied *read* is not a "role assignment denied". **Recommend Gate 2 scope AC4 to `assign` + `revoke` only** and record the GET's 403 as a deliberate exclusion (it keeps its existing WARN + `nexus.rbac.permission_denied` signal).
3. **T1's `roleName` is structurally unavailable.** `verifySameTenant` runs before the role is resolved. Any denial event from T1 carries `roleId` but a null `roleName`. This is benign — `RbacAuthEventAdapter.buildMetadataJson` (`:115-131`) already omits null-valued keys entirely rather than emitting JSON `null` — but Gate 2 must state that a `ROLE_ASSIGNMENT_DENIED` row's metadata is **not** field-identical to a `ROLE_ASSIGNED` row's.
4. **F4 — no post-commit hook is available.** `registerPostCommitSideEffects` (`:343-355`) is the success-path mechanism and is unusable here: the denial throws, the `@Transactional` boundary rolls back, and `afterCommit` never fires. The call must be **inline, immediately before the throw**, and its durability depends entirely on `SecureEventService`'s `REQUIRES_NEW` committing on a suspended, independent transaction. Gate 2 must assert this explicitly; getting it wrong yields a denial event that is silently rolled back with the denial itself — the exact failure the AC exists to prevent.
5. **Log-level convention to match:** the file already distinguishes WARN (security-relevant, `:197`) from DEBUG (benign client bug, `:118`). A denial is WARN-class. Note `GlobalExceptionHandler` **already** WARN-logs these same 403s (`GlobalExceptionHandler.java:166`) — see §11 for the double-signal tension.

### 1.3 Backend — `identity.domain` (1 file modified)

`identity/domain/AuthEventType.java` — add `ROLE_ASSIGNMENT_DENIED("ROLE_ASSIGNMENT_DENIED")` after `ROLE_REVOKED` (`:45`).

- **Priority-lane question (flagged, not resolved — Gate 2 call).** The enum's own comment at `:47-50` records that US-012 **already reversed** its original D10 decision and put `ROLE_ASSIGNED`/`ROLE_REVOKED` in `PRIORITY` (`:51-58`) on T-R4 grounds: "a lost `ROLE_ASSIGNED` record is exactly the repudiation risk AC7 exists to prevent." The same reasoning reads across to a denial record (forensic value on an attempted escalation). **Counter-consideration Gate 2 must weigh:** the priority lane is capacity-**200** (ADR 0011 §1) and a denial event is, unlike the success events, **attacker-triggerable at will** — a probing client can generate denials in a loop. Putting an attacker-reachable event type in the protected lane is structurally the same hazard ADR 0011 created the two-lane split to avoid for `LOGIN_FAILURE`. This is a genuine tradeoff, not a foregone "yes".
- `event_type` is `VARCHAR(64)` (`V2__identity_schema.sql:80`); the 22-character wire name fits. No migration.
- **`outcome` is hardcoded `"SUCCESS"`** in the adapter (`RbacAuthEventAdapter.java:85`). A denial row must not claim `SUCCESS`. `outcome` is `VARCHAR(20) NOT NULL` with **no CHECK constraint** (`V2:81`); existing literals in use include `"SUCCESS"`, `"FAILURE"`, `"INFO"` (`AuthEventsAppendOnlyIT.java:34,46,118`). Gate 2 picks the literal; `"DENIED"` (6 chars) and `"FAILURE"` both fit.

### 1.4 Backend — `identity.infrastructure.audit` (1 file modified)

`identity/infrastructure/audit/RbacAuthEventAdapter.java` — implement the new port method.

- Reuses the existing private `record(...)` helper (`:76-109`) verbatim in intent: pre-serialise metadata before any transaction (T-R3 mitigation #3, `:79-82`), `SecureEventService.recordEvent` (`:92`), catch-all → ERROR `RBAC_AUDIT_WRITE_LOST` + `nexus.rbac.audit_write_failed{operation}` (`:93-108`).
- **Two mechanical signature changes to that helper:** it currently hardcodes `"SUCCESS"` (`:85`) and takes `(event, eventType, actorFieldName, operation)`. It needs an `outcome` parameter, and the metadata builder (`:115-131`) needs to emit the denial reason key. `operation` becomes a third tag value (`"assign"` / `"revoke"` / `"deny"` or similar) on the existing counter — no new metric.
- `actorFieldName` for a denial: the existing convention is `assignedBy` / `revokedBy` (`:67`, `:72`). A denial has an *attempted* actor. Gate 2 picks the key name (`attemptedBy` is the obvious candidate).
- **`user_id` subject convention is a real AC5-affecting decision, not cosmetic.** The adapter sets `withUserId(event.targetUserId())` (`:86`, commented "the subject, matching the LOCKOUT convention"). For a denial, the forensically interesting party is the **actor**, but AC5's query is keyed on `user_id`. Whichever Gate 2 picks, the choice must be documented, because it determines whether a denial row is discoverable by "show me this user's access history" or by "show me what this user tried".
- The `record(...)` helper's `@SuppressWarnings("java:S6213")` (`:75`) and the Jackson-3 `ObjectMapper` note (`:27-33`) apply unchanged.
- **ArchUnit constraint (mechanically enforced, not advisory):** `rbac_must_not_depend_on_identity` (`HexagonalArchitectureTest.java:107-118`) means the **`AuthEventType` constant must be selected inside this adapter**, never passed in from `rbac`. The port signature may carry a `DenialReason` (a `common.security` type) or a plain `String`, never an `AuthEventType`.

### 1.5 Backend — `interfaces/rest`: **zero diff (verified, not assumed)**

- AC5 is test-only (§7 Decision 3): no new endpoint, no `JpaAuthEventRepository` method (it remains a bare `extends JpaRepository`), no controller.
- `UserRoleController` is untouched **provided** AC4 excludes `listActive` (F2.2). If Gate 2 includes the GET, this section becomes non-zero. State the decision explicitly in `03-design.md`.
- `common/web/GlobalExceptionHandler.java` is untouched by construction — that is the whole point of §7 Decision 5 (Risk R-3 resolved structurally).
- `config/SecurityConfig`, `config/MethodSecurityConfig`, `common/security/*` — no change.

### 1.6 Tests

**Modified — build-blocking (F3).** `rbac/application/RoleAssignmentServiceTest.java`. Seven methods assert `verifyNoInteractions(permissionCachePort, rbacAuditPort)` on branches that must now call `rbacAuditPort`:

| Method | Line | Reason | New expectation |
|---|---|---|---|
| `should_throwCrossTenantTarget_when_assignTargetTenantMismatch` | `:142-154` | T1 via `assign` | `verify(rbacAuditPort).recordRoleAssignmentDenied(...)` + `verifyNoInteractions(permissionCachePort)` |
| `should_throwCrossTenantTarget_when_assignRoleTenantMismatch` | `:169-183` | T2 via `assign` | same |
| `should_throwNotTenantAdmin_when_grantingTenantAdminAndCallerNotActiveAdmin` | `:186-203` | T3 | same |
| `should_throwNotTenantAdmin_when_roleNameIsDifferentCaseVariantOfTenantAdmin` | `:213-229` | T3 | same |
| `should_throwCrossTenantTarget_when_revokeTargetTenantMismatch` | `:386-397` | T1 via `revoke` | same |
| `should_throwCrossTenantTarget_when_revokeRoleTenantMismatch` | `:412-426` | T2 via `revoke` | same |
| `should_throwCrossTenantTarget_andNeverCall...Views_when_listActiveTargetTenantMismatch` | `:650-661` | T1 via `listActive` | **No change if AC4 excludes the GET** — this method happens not to assert on `rbacAuditPort`. It is the cheap regression sentinel for the F2.2 exclusion; consider *adding* `verifyNoInteractions(rbacAuditPort)` here to pin the exclusion deliberately. |

Methods that must stay exactly as they are (they encode the §7 Decision 2 exclusion of the 409s and the 404s):
`should_throwDuplicateRoleAssignment_when_activeAssignmentAlreadyExists` (`:266-278`), both `should_throwLastAdminRoleException_*` (`:476`, `:500`), `should_throwResourceNotFound_when_*` (`:130`, `:157`, `:375`, `:400`, `:565`), both `should_neverCallLockActiveAssignmentIds_*` (`:435`, `:458`). Their existing `verifyNoInteractions(..., rbacAuditPort)` is now a **load-bearing negative assertion** proving the 403-only scope, not incidental. Say so in `04-tasks.md` so nobody "fixes" them.

**Modified — `identity/domain/AuthEventTypeTest.java`.** `should_defineAllTwentyTwoConstants_when_valuesCalled` (`:102-128`) asserts `hasSize(22)` + an exhaustive name list → **23** + one name. If `ROLE_ASSIGNMENT_DENIED` goes into `PRIORITY`, also: `EXPECTED_PRIORITY` (`:18-25`), the `hasSize(6)` assertion (`:98`) → 7, the `@EnumSource(..., mode = EXCLUDE)` name list (`:84-86`), and one new `isPriority()`-is-true test to match the existing per-constant pattern (`:74-81`). If it stays non-priority, the `EXCLUDE`-mode parameterised test auto-covers it correctly with zero edits — a small, real argument for the non-priority option.

**Modified — `identity/infrastructure/audit/RbacAuthEventAdapterTest.java`.** New tests for the third method mirroring the existing pair (`:66-108`): field mapping (event type, `outcome`, `user_id` subject, denial-reason metadata key), the `attemptedBy`-vs-`assignedBy`/`revokedBy` key exclusivity assertion, and the T-R3 never-throws/ERROR-log/counter trio (`:187-260`) with the new `operation` tag. Plus the F1 fan-out if Gate 2 picks option (c). **This file carries the JaCoCo weight** — `*.infrastructure.*` has its own line-coverage gate (`pom.xml:402-422`).

**Modified — `rbac/RoleAssignmentAuditIT.java`.** Three groups of additions:

1. **AC4 — two new tests** proving a `ROLE_ASSIGNMENT_DENIED` row **IS** written, sitting directly beside the existing Scenario 4 block (`:221-287`) whose tests prove the *opposite* for `ROLE_ASSIGNED`. They pair naturally:
   - beside `should_writeNoAuditRow_when_assignFailsWithCrossTenantTarget` (`:224-246`) — same fixture, same `DenialReason.CROSS_TENANT_TARGET` assertion, then `countAuditRows(..., "ROLE_ASSIGNMENT_DENIED") == 1` instead of `ROLE_ASSIGNED == 0`. The existing test's own `isZero()` assertion becomes **more** valuable next to it: together they prove the denial did not get miscategorised.
   - a second for `NOT_TENANT_ADMIN` (T3) — **no existing test covers this path at IT level**; the fixture must seed a caller *without* an active `TENANT_ADMIN` assignment and a role literally named `TENANT_ADMIN` in the caller's own tenant.
   - `findLatestAuditRow` (`:378-389`) is reusable as-is for the metadata assertions but its `SELECT` list has no denial-reason column — one `JSON_EXTRACT` line to add, or a sibling helper.
   - **These two tests are also the only place F4 gets proven.** They must assert the row exists *after* the service call threw — i.e. that the `REQUIRES_NEW` write survived the outer rollback. Without that assertion the design's central correctness claim is untested.
2. **AC3 / Test Scenario 4 — two lightweight additions** (§7 Decision 4, explicitly *not* a new IT class): insert a literal `ROLE_ASSIGNED` row via `JdbcTemplate`, assert `UPDATE` is blocked with `SQLSTATE '45000'`. Mirrors `AuthEventsAppendOnlyIT.should_rejectUpdate_when_authEventModified` (`:39-62`) and `should_leaveRowUnchanged_when_updateRejected` (`:64-82`) exactly, differing only in the `event_type` literal. Both prerequisites already exist in this file: the raw `INSERT INTO auth_events (id, event_type, outcome)` idiom (`:299-301`) and the `toBytes(UUID)` helper (`:427-432`). The only genuinely new code is the ~12-line `SQLException`/SQLSTATE cause-walk copied from `AuthEventsAppendOnlyIT:53-61`. **Flag:** that cause-walk will now exist in two files. Extracting a shared assertion helper is *not* proportionate for 3 points — accept the duplication, note it.
3. **AC5 — one JDBC query test** (§7 Decision 3): the literal `WHERE tenant_id = ? AND user_id = ? AND event_type IN ('ROLE_ASSIGNED','ROLE_REVOKED')` shape, over a mixed history (≥1 assign + ≥1 revoke for the same user) plus a decoy row under a different tenant/user to prove filtering, asserting `created_at`-**ascending** order (Decision 3 fixes ascending/oldest-first). **Placement is a Gate-2/task-level call, flagged not resolved:** `RoleAssignmentAuditIT` already owns every `auth_events`-querying helper (`findLatestAuditRow`, `countAuditRows`, `toBytes`, `seedUser`, `seedRole`) and the assign+revoke history is produced by the same autowired service — reuse argues for keeping it here. Against: this class's Javadoc (`:46-97`) scopes it tightly to adapter round-trip + T-R3, and AC5 is a schema/query guarantee, not an adapter concern. Either is defensible; the file is already ~440 lines.
   - **Minor flake risk to note:** `created_at` is `DATETIME(6)` with a DB-side `CURRENT_TIMESTAMP(6)` default (`V2:84`) and there is no tie-break column. Rows produced by two separate service calls will differ; rows inserted by a raw-JDBC loop in the same microsecond could tie. Prefer driving the history through `assign`/`revoke` (distinct transactions) over a tight `jdbc.update` loop, or set `created_at` explicitly for decoys.

**New test files: none.** Every addition lands in an existing class (Decisions 3 and 4).

**Coverage gates** (`nexus-backend/pom.xml:340-422`): BUNDLE LINE, `*.domain.*`, `*.application.*`, `*.interfaces.rest.*`, `*.infrastructure.*` each carry their own LINE ratio. The new service branches are in `*.application.*` (the tightest of the package gates) and the new adapter method in `*.infrastructure.*`; both are covered by the unit-test additions above, but the denial branches must be unit-covered, not only IT-covered.

### 1.7 Verified NOT affected

- **All of `nexus-frontend/`** — see §4.
- `nexus-backend/src/main/resources/db/migration/**` — no new `V<N>__*.sql` (§2).
- `identity/domain/AuthEvent.java` — `withUserId`/`withTenantId`/`withIpAddress`/`withUserAgent`/`withMetadata` already sufficient; `event_type` and `outcome` are plain `String` columns.
- `identity/application/service/SecureEventService.java`, `AuthEventPort`, `JpaAuthEventAdapter`, `AuthEventRetryBuffer`, `LoggingAuditAlertAdapter` — reused verbatim, zero signature change.
- `identity/infrastructure/persistence/JpaAuthEventRepository.java` — stays a bare `JpaRepository` (Decision 3).
- `rbac/domain/**`, `rbac/infrastructure/**`, `UserRoleAssignmentPort`, `UserDirectoryPort`, `PermissionCachePort`, `RoleResolutionService` — untouched.
- `common/web/GlobalExceptionHandler.java`, `common/security/InsufficientPermissionException.java`, `common/domain/RequestContext.java` — untouched.
- `common/security/DenialReason.java` — **no new constant.** Verified: `CROSS_TENANT_TARGET` (`:13`) and `NOT_TENANT_ADMIN` (`:15`) already exist, added by US-012. AC4 reuses them.
- `nexus-database/mysql/init/02-grants-post-schema.sql` and `nexus-backend/src/test/resources/nexus-app-grants.sql` — `GRANT INSERT, SELECT ON nexus.auth_events` already covers the new row. **No grant change, no ADR 0012/0014 touch.**
- `architecture/HexagonalArchitectureTest.java` — no new rule needed (§12).
- `RoleAssignmentIT`, `RoleAssignmentSecurityIT`, `RoleAssignmentCacheIT`, `LastAdminLockoutIT`, `UserRolesPrivilegeIT`, `RbacSchemaMigrationIT`, `UserRoleControllerTest` — no diff. `RbacSchemaMigrationIT`'s `containsExactly` column assertions are safe because no column is added.

---

## 2. Database changes

**None. Zero.** No Flyway migration; `ddl-auto=validate` cannot fail as a result of this story; ADR 0003's append-only migration rule is not engaged.

Verified against `V2__identity_schema.sql:76-110`:

| Requirement | Already satisfied by |
|---|---|
| Denial-event storage | `metadata JSON NULL` (`:83`) — the story's own Risks table already records this as RESOLVED |
| New `event_type` value | `event_type VARCHAR(64) NOT NULL` (`:80`) — **not** a DB `ENUM`; `ROLE_ASSIGNMENT_DENIED` is 22 chars |
| Non-`SUCCESS` outcome | `outcome VARCHAR(20) NOT NULL` (`:81`) — no CHECK constraint |
| AC3 append-only | `trg_auth_events_no_update` (`:98-103`), `trg_auth_events_no_delete` (`:105-110`) — event-type-agnostic by construction |
| AC5 query support | `idx_auth_events_user_id_created_at`, `idx_auth_events_tenant_id_created_at`, `idx_auth_events_event_type_created_at` (`:88-90`) |

**`AuthEventType.ROLE_ASSIGNMENT_DENIED` is a data-value addition (a new `event_type` string), not a schema change.** No composite `(tenant_id, user_id, event_type)` index is added — requirements R-5 accepts this explicitly, consistent with the story's own "no schema changes" Technical Note.

---

## 3. API changes

**None. Zero.** No new endpoint, no changed endpoint, no request/response shape change, no status-code change, no versioning event, no OpenAPI diff.

The two in-scope denials continue to return exactly what they return today: **403 `RBAC_001`** with a `requiredPermission` property, via `GlobalExceptionHandler.handleInsufficientPermission` (`:159-176`), unchanged. **The wire contract is bit-identical before and after this story** — the only observable difference is a row in `auth_events`. AC5 ships no query surface (Decision 3); Epic 7 is its eventual consumer.

---

## 4. UI changes

**None. Zero — confirmed explicitly.** This is a backend-only, audit-infrastructure story. No AC in `docs/story/2-rbac/US-014.md` has a user-facing surface; the story's own Out of Scope names "Audit log UI (Epic 7)". Since §3 establishes the HTTP contract is unchanged, there is nothing for a client to consume differently.

**No file under `nexus-frontend/` changes** — no Angular component, route, guard, service, or store; no Vitest spec, no Playwright spec, no `package.json`/lockfile touch. (Which also sidesteps the known npm-Windows `@emnapi` lockfile-prune trap entirely.)

---

## 5. Security impact

- **New attack surface: none.** No new endpoint, no new authn/authz decision point, no change to any existing authorization outcome. Every request that was denied before is denied identically now; the story adds a **record** of the denial, not a new code path a caller can reach.
- **AuthN/AuthZ changes: none.** `@RequiresPermission`, `TenantAwarePermissionEvaluator`, `SecurityConfig`, `JwtAuthenticationFilter` all untouched. AC4 emits *after* the authorization decision, never influencing it.
- **Net security posture: positive.** This is the story's whole point — an immutable, tenant/user-queryable trail of *attempted* privilege escalation, against EPIC-002's T-E1 (self-registered bootstrap-tenant users one denied check away from `TENANT_ADMIN`).
- **New attacker-controlled write path (the one genuinely new item).** An unprivileged authenticated caller can now, by design, cause `auth_events` rows to be written by repeatedly probing the two 403 paths. Consequences to weigh at Gate 2:
  - **Audit-volume amplification.** Unbounded row growth driven by an attacker, into a table with no retention/partitioning policy (requirements §8 gap). No rate limiter covers these endpoints (US-012 Res. 10).
  - **Retry-buffer lane contention** — the priority-lane concern in §1.3. This is the concrete reason the "obviously yes, make it PRIORITY" answer is not obvious.
- **Metadata JSON injection (T-T1/T-T5): unchanged and already covered.** A denial event reuses `buildMetadataJson` (`RbacAuthEventAdapter.java:115-131`) and the Jackson-3 `ObjectMapper`; the existing adversarial `roleName` matrix (`RbacAuthEventAdapterTest.java:129-164`) and the MySQL round-trip proof (`RoleAssignmentAuditIT.java:171-219`) apply as-is. Any **new** metadata key (the denial reason) is enum- or code-derived, not user-supplied.
- **Cross-tenant information in an audit row (new, minor).** At throw site T2 the role was resolved and belongs to *another* tenant, so a denial row written under the actor's `tenant_id` would carry a foreign tenant's `roleName` in its metadata. Low severity (visible only to platform operators / a future `audit:read` holder), but it is a genuine cross-tenant data placement and belongs in the Gate 2 threat-model refresh, alongside the `user_id`-subject choice (§1.4) and the amplification item above.
- **Append-only guarantees inherited unchanged**: DB triggers (`V2:98-110`) plus `GRANT INSERT, SELECT` only. AC3's two new tests make that inheritance explicit for a real `ROLE_ASSIGNED` row rather than only for the non-RBAC literals `AuthEventsAppendOnlyIT` uses.

---

## 6. Performance impact

| Path | Analysis |
|---|---|
| **Denied `assign`/`revoke` (403)** | One extra `INSERT` into `auth_events` on a formerly write-free path, in a `REQUIRES_NEW` transaction. Cost = one extra pooled connection held concurrently with the outer (doomed) transaction + one round trip. Same well-characterised cost as the success path (`AuthEventLoadIT` / `AuthEventLoadSmokeIT` already benchmark it). |
| **Successful `assign`/`revoke`** | **Unchanged.** No new work on the happy path. |
| **`listActive` (GET)** | Unchanged (given the F2.2 exclusion). |
| **Connection-pool note** | The 403 path now borrows a second connection while the first is still held — the established `identity` pattern, but new on this path. Unlike US-012's revoke path there is **no row lock** in scope here, so the window is short. |
| **N+1 risk** | None. No new query, no collection iteration, no lazy association. |
| **Cache touches** | **None.** `PermissionCachePort.evict` is deliberately *not* called on a denial — no permission state changed. Redis is untouched by this story. |
| **AC5 query plan** | Not a production hot path (test-only, no consumer until Epic 7). Served by the three existing single-column-paired indexes (`V2:88-90`); no composite index, accepted per R-5. |
| **Hot-path risk** | The only load concern is attacker-driven denial volume (§5), which is an availability/volume question for the retry buffer, not a latency question. |

---

## 7. Integration impact & cross-context boundary

| Integration | Impact |
|---|---|
| **MySQL** | One additional `INSERT` shape on an existing, unchanged table. No DDL, no grant change. |
| **Audit pipeline (US-008)** | Reused end-to-end, unchanged: `SecureEventService` → `AuthEventPort` → `JpaAuthEventAdapter` → `AuthEventRetryBuffer`. The **only** possible change is lane routing (§1.3). |
| **Redis** | Untouched. No cache key, no eviction, no new Redis dependency (ADR 0016 unaffected). |
| **JWT / token issuance** | Untouched. No claim change, no `token_version` bump, no `JwtClaimsContractTest` change. |
| **Upstream/downstream services** | **None.** Nexus is a modular monolith; no external boundary is crossed, no broker, no contract test. |
| **Epic 7 (Audit Log UI)** | Inherits a third queryable `event_type`. AC5's query shape is confirmed but not exposed. Non-gating. |
| **US-015 / Epic 3** | Inherit the same emission pattern for any future denial type. Requirements §4 notes a fifth denial type on an adjacent endpoint is unaddressed — deliberately out of scope. |

**Cross-context boundary: same US-012 pattern, mechanically enforced.** `rbac.application.port.out` **declares** the new port method; `identity.infrastructure.audit` **implements** it. Dependency direction stays `identity → rbac`, never the reverse. This is no longer documentation-only: `HexagonalArchitectureTest.rbac_must_not_depend_on_identity` (`:107-118`) — which did not exist when US-012's impact analysis was written — now fails the build on any `rbac → identity` import. Its practical bite here is §1.4's constraint: the `AuthEventType` constant is chosen inside the adapter, never crossing the port. No cycle introduced; no new ArchUnit rule required.

---

## 8. Dependency changes

**None.** No new library, no version bump, no license review.

Everything needed is already on the classpath and already used by the exact files being modified: Spring Data JPA + `@Transactional`, Micrometer `Counter`, Jackson 3 (`tools.jackson.databind.ObjectMapper`), SLF4J fluent API, JUnit 5 + `@ParameterizedTest`, Mockito, AssertJ, Logback `ListAppender`, Testcontainers MySQL 8.4, `JdbcTemplate`, ArchUnit.

---

## 9. Backward compatibility

| Dimension | Verdict |
|---|---|
| HTTP API | ✅ Bit-identical. No path, method, request, response, or status change. |
| JWT / `JwtClaims` | ✅ Unchanged → no `token_version` bump. |
| Frontend contract | ✅ Untouched. |
| Database schema | ✅ No DDL. Existing rows unaffected. |
| `auth_events` **data** | ✅ One new `event_type` string value in a `VARCHAR(64)` column. Any existing consumer filtering on `IN ('ROLE_ASSIGNED','ROLE_REVOKED')` — including AC5's own query — is **unaffected by construction**, because the new value is outside that set. |
| `nexus_app` grants | ✅ No change. |
| Java port interfaces | ⚠️ `RbacAuditPort` gains a method — a **source-incompatible change for any other implementor**. Verified: `RbacAuthEventAdapter` is the sole implementation in `src/main`, and `RoleAssignmentServiceTest` uses a Mockito `@Mock` (`:59`), which auto-satisfies new methods. Internal interface, single implementor, zero external consumers ⇒ not a real break. |
| `RbacAuditEvent` record | ⚠️ Breaking **only** under F1 option (c), and only at compile time within this repo (17 sites). Options (a)/(b) are fully compatible. |
| Rollback | ✅ Trivially reversible: no migration, no data reshaping. Reverting the code reverts the feature; `ROLE_ASSIGNMENT_DENIED` rows written while live remain valid, readable, append-only audit data that no query depends on. |

**Overall: non-breaking.**

---

## 10. Data migration strategy

**Not applicable — no shape change.** No existing row is reshaped, backfilled, reinterpreted, or re-keyed; no column is added, widened, or retyped. No expand/contract phasing is required, and there is no backfill: `ROLE_ASSIGNMENT_DENIED` is forward-only by nature (past denials were never recorded and cannot be reconstructed — worth one line in the release notes so Security & Compliance does not expect retroactive history).

---

## 11. Observability impact

**The one unresolved tension Gate 2 must settle (flagged, deliberately not resolved here).**

The two in-scope 403s **already** produce two operational signals today, both from `GlobalExceptionHandler.handleInsufficientPermission` (`:159-176`):
- a WARN log with `reason`, `requiredPermission`, `userId`, `tenantId` (`:161-166`);
- `nexus.rbac.permission_denied{permission, reason}` (`:167-171`) — already tagged with exactly the two `DenialReason` values in AC4's scope, so **the metric AC4 might otherwise ask for already exists and is already alertable**.

So a `ROLE_ASSIGNMENT_DENIED` audit row is a **third** signal for the same event. That is not automatically wrong — the counter is an aggregate operational signal, the audit row is a permanent, per-event, tenant/user-queryable forensic record (precisely §7 Decision 1's argument) — but it does mean:

1. **Do not add a second denial counter.** Reuse `nexus.rbac.permission_denied{reason}`; a new `nexus.rbac.role_assignment_denied` counter would be a redundant, drift-prone duplicate of an existing series. *(Recommendation, for Gate 2 to accept or reject explicitly.)*
2. **The existing `nexus.rbac.audit_write_failed{operation}` counter must gain a third tag value** so a *lost denial record* is separately visible from a lost assign/revoke record. This is free — the counter is already tag-driven (`RbacAuthEventAdapter.java:104-107`).
3. **Log-volume question.** `GlobalExceptionHandler` already WARNs these 403s. A second WARN from `RoleAssignmentService` at the throw site would double the log lines for one event. Gate 2 should pick one (the existing `GlobalExceptionHandler` WARN is the incumbent and needs no change) rather than adding a symmetric WARN "for consistency" with the success path's INFO.
4. **Trace correlation is already handled** — `CorrelationIdFilter` + MDC, surfacing as `traceId` in the metadata JSON (`buildMetadataJson`, `:118-120`), matching AC1/AC2's `correlation_id`.
5. **No new dashboard is required**, but requirements §10's success metric ("`nexus.rbac.audit_write_failed` stays at zero unexplained increments") should be extended to the new tag value in `docs/features/US-012/monitoring.md`-style follow-up, not in this story.

---

## 12. ADR check

No accepted ADR is contradicted. Two touchpoints, one of them a real (pre-existing) drift:

| ADR | Verdict |
|---|---|
| **0003** — Flyway schema migrations | ✅ Not engaged. No migration. |
| **0011** — In-process bounded retry buffer for audit writes | ⚠️ **Pre-existing documentation drift, which this story would compound.** §1 states the priority lane "carries **exactly the four** highest-value forensic/security-incident event types: `LOCKOUT`, `TOKEN_REFRESH_REUSE`, `PASSWORD_CHANGED`, `ACCOUNT_LOCKED_WRITE_FAILED`." US-012 subsequently added `ROLE_ASSIGNED`/`ROLE_REVOKED` to that `EnumSet` (`AuthEventType.java:47-58`) and **the ADR was never amended** — verified: the file has no amendment, supersession, or post-2026-07-01 entry. The code says six, the ADR says four. Adding a seventh makes it worse. **Fix is cheap and belongs to whichever option Gate 2 picks:** one amendment note on ADR 0011 recording the current membership and the T-R4 rationale, plus the §5 attacker-reachability caveat. **No new ADR required** — this is recording an already-taken decision, not making one. |
| **0012 / 0014** — least-privilege `nexus_app` grants | ✅ Unaffected. `GRANT INSERT, SELECT ON nexus.auth_events` already covers the new row; no grant widening, so `RbacDbPrivilegeHealthIndicator` and `AuthEventDbPrivilegeHealthIndicator` are untouched. |
| **0013** — RBAC data model & enforcement contract | ✅ Nothing contradicted. Read in full: it governs `roles`/`permissions`/`user_roles`, the `resource:action` naming convention, and the enforcement contract; it says nothing about `auth_events` or audit event types. The `audit:read` permission it seeds is Epic 7's, not this story's. |
| **0002** — Hexagonal architecture | ✅ Honoured: port declared in `rbac.application.port.out`, adapter in `identity.infrastructure.audit`, no domain involvement. Mechanically enforced (§7). |

**ADR Required: No.** One **ADR 0011 amendment note** is recommended (cost: a short paragraph) if `ROLE_ASSIGNMENT_DENIED` joins the priority lane — and is arguably worth writing either way, since the four-vs-six drift already exists.

---

## 13. Effort / complexity signal (input to `04-tasks.md`)

| Area | Blast radius | Files | Complexity | Notes |
|---|---|---|---|---|
| `RbacAuditPort` +1 method | Small | 1 mod | Trivial | Restate the never-throws contract |
| `RbacAuditEvent` | Small **or Medium** | 0-1 mod | Trivial **or mechanical-wide** | **F1**: option (a)/(b) = 0 breaks; option (c) = 17 edit sites |
| `AuthEventType` +1 constant | Small | 1 mod | Trivial | Priority-lane decision is the only content |
| `RbacAuthEventAdapter` +1 method | Small | 1 mod | Low | Reuses `record(...)`; needs an `outcome` param + one metadata key |
| `RoleAssignmentService` emission | Small | 1 mod | **Low-Medium** | Highest-judgement item: 3 throw sites, private-helper threading, F4's no-post-commit constraint |
| `RoleAssignmentServiceTest` | Small | 1 mod | Trivial-Low | **Build-blocking**; 6 methods change, 1 optionally hardened, ~9 must deliberately not change |
| `AuthEventTypeTest` | Small | 1 mod | Trivial | 1 edit if non-priority; ~5 if priority |
| `RbacAuthEventAdapterTest` | Small | 1 mod | Low | Mirror the existing pair + T-R3 trio; carries the JaCoCo weight |
| `RoleAssignmentAuditIT` (AC4 ×2, AC3 ×2, AC5 ×1) | Medium | 1 mod | Low-Medium | 5 new methods; AC4's must also prove F4 (row survives rollback) |
| ADR 0011 amendment note | Small | 1 mod | Trivial | Optional but recommended |
| Frontend / DB / API / grants / migrations | None | 0 | — | Verified zero diff |

**Overall: SMALL, and proportionate to 3 points.** ~4-5 production files, all additive, ~30-60 production lines; 4 test files, ~7-8 new test methods plus ~7 mechanical assertion updates. No new bounded context, no new class of any kind except (optionally) one sibling record, no schema change, no new dependency, no new convention. Roughly **half the blast radius of US-013** (also 3 points), which created 8 new files and established 8 new conventions.

**Nothing looks disproportionately large — with one conditional.** If Gate 2 picks F1 option (c), the diff grows by 14 purely mechanical test-file edits, which will *look* like a much bigger story in review than it is. That is a cost worth avoiding for presentational as well as practical reasons. The genuinely non-mechanical work is confined to two decisions (§1.3 priority lane, §1.4 subject/outcome/key naming) and one correctness constraint (F4).

**Disproportion flag, opposite direction:** if Gate 2 were to extend AC4 to `listActive`, the story would acquire a service signature change, a controller change, a controller-test change, and an `interfaces/rest` diff for a semantically wrong event name — that *would* be disproportionate. §1.5's zero-diff claim depends on excluding it.

---

## 14. Open items `03-design.md` (Phase 3) must close

1. **F1** — port signature vs. `RbacAuditEvent` shape: two-arg method, sibling record, or 7th component (§1.1). Decides a 17-site fan-out.
2. **F2** — confirm AC4 excludes `listActive`'s 403 in writing, and pin it with an assertion in `RoleAssignmentServiceTest:650-661` (§1.2, §1.5).
3. **Throw-site mechanics** — emit inside the two private helpers (threading `RequestContext`/`roleId`) or at their 4 call sites (§1.2).
4. **F4** — state explicitly that emission is inline pre-throw and that durability rests on `SecureEventService`'s `REQUIRES_NEW` surviving the outer rollback; require the AC4 ITs to assert it (§1.2).
5. **Priority lane** — `ROLE_ASSIGNMENT_DENIED` in `PRIORITY` or not, weighing T-R4's forensic argument against the event's attacker-reachability and the 200-slot lane (§1.3, §5).
6. **`outcome` literal** — `"DENIED"` vs `"FAILURE"` (§1.3).
7. **`user_id` subject** — target user or actor, and its effect on AC5-shaped discoverability (§1.4).
8. **Metadata keys** — the actor key name (`attemptedBy`?) and the denial-reason key; whether the raw `DenialReason.name()` is the stored value (§1.4).
9. **Observability** — reuse `nexus.rbac.permission_denied` (recommended) vs. a new counter; add the third `audit_write_failed{operation}` tag value; avoid a duplicate WARN (§11).
10. **AC5 test placement** — extend `RoleAssignmentAuditIT` or add a small dedicated class (§1.6.3).
11. **ADR 0011 amendment** — whether to correct the four-vs-six priority-lane drift now (§12).
12. **Threat-model refresh items** — audit-volume amplification, foreign-tenant `roleName` at throw site T2, subject-field choice (§5).

No caching is involved (no Redis touch). **No feature flag is proposed:** the story states "Feature flag required: No", the change is inert to every wire contract, and `UserRoleController`'s existing `feature.nexus-us012-rbac-role-assignment.enabled` gate (`UserRoleController.java:61`) already switches off the only paths that can reach the new emission — a second flag would be redundant. Rollout is instant/with-deploy; the rollback criterion is any unexplained `nexus.rbac.audit_write_failed{operation=<denial>}` increment or priority-lane depth alert.

---

## Summary

### Modules affected

**Modified — production (4-5):**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java` — `+recordRoleAssignmentDenied(...)`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditEvent.java` — **conditional** (F1)
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java` — emission at `:304` (T1), `:319` (T2), `:110` (T3)
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java` — `+ROLE_ASSIGNMENT_DENIED` (after `:45`); `PRIORITY` set (`:51-58`) TBD
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java` — `+recordRoleAssignmentDenied`; `record(...)` (`:76`) gains `outcome`; `buildMetadataJson` (`:115`) gains a key

**Modified — tests (4):** `rbac/application/RoleAssignmentServiceTest.java` (6 methods, build-blocking); `rbac/RoleAssignmentAuditIT.java` (+5 methods: AC4 ×2, AC3 ×2, AC5 ×1); `identity/infrastructure/audit/RbacAuthEventAdapterTest.java`; `identity/domain/AuthEventTypeTest.java` (`:102`, and `:18`/`:84`/`:98` if priority).

**Optional docs:** `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md` (amendment note).

**New files: none.**

**Verified zero diff:** all of `nexus-frontend/`; `db/migration/**`; `interfaces/rest/**` incl. `UserRoleController`; `GlobalExceptionHandler`; `DenialReason`; `SecureEventService`/`AuthEventPort`/`AuthEventRetryBuffer`/`JpaAuthEventAdapter`/`JpaAuthEventRepository`; `nexus_app` grant files; `HexagonalArchitectureTest`; all other `rbac` ITs.

### DB changes

**None.** No migration, no column/index/constraint/grant change; `ddl-auto=validate` unaffected. `ROLE_ASSIGNMENT_DENIED` is a **data-value** addition to `event_type VARCHAR(64)`; the `metadata JSON` column already exists (`V2:83`).

### Breaking changes found

- **No** wire, schema, JWT, or frontend break. HTTP responses are bit-identical.
- **One compile-time break, conditional:** F1 option (c) breaks 17 `RbacAuditEvent` construction sites in 4 files. Options (a)/(b) break none.
- **One unavoidable in-repo test break:** 6 `RoleAssignmentServiceTest` methods assert `verifyNoInteractions(rbacAuditPort)` on the very branches that must now interact with it — build-blocking, must land in the same commit.
- `RbacAuditPort` gains a method — single implementor, Mockito-mocked in tests; not a real break.

### Top 3 risks (implementation-impact lens)

1. **No post-commit hook exists on the denial path (Medium, correctness).** `registerPostCommitSideEffects` (`:343-355`) is unusable — the transaction rolls back. Durability depends entirely on `SecureEventService`'s `REQUIRES_NEW`. Get this wrong and the denial record is rolled back together with the denial: the exact failure AC4 exists to prevent, and invisible unless the new IT asserts the row survives the throw.
2. **Scope creep into `listActive` (Medium-High, blast radius).** `verifySameTenant` is shared by all three service methods; a naive emission inside it fires on the GET's 403 too, forcing a service signature change (`listActive` has no `RequestContext`, `:252`), a controller change (`listRoles` never builds one), and a controller-test change — turning a zero-diff `interfaces/rest` into a non-zero one, for a semantically wrong event name.
3. **`RbacAuditEvent` fan-out amplified by a grep blind spot (Medium, cost).** 17 positional construction sites, 10 of them in `RbacAuthEventAdapterTest.java` — a file ripgrep reports as **binary** (embedded NUL from its `controlChar` test literal at `:134`) and therefore omits from `rg 'new RbacAuditEvent'` counts. Anyone sizing option (c) by grep will under-estimate it by ~60%.

Runner-up worth surfacing at Gate 2: **ADR 0011 already says "exactly four" priority event types while the code has six** — US-012's `PRIORITY` change was never recorded. Adding a seventh compounds a live doc/code contradiction that a compliance reader will hit first.
