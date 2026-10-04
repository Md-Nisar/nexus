# US-018 — Impact Analysis (Phase 2)

**Story:** Harden RBAC for production readiness (principal-architect review remediation)
**Epic:** EPIC-002 — RBAC Foundation
**Gate 1 basis:** `docs/features/US-018/01-requirements.md`, in particular §14 "Gate 1 Decisions (approved 2026-09-26)". Those decisions are binding here and are not reopened. They are: one story delivered as milestones 1–9 and 11 (milestone 10 / C4 is out); Group A only is the GA blocker; A9 uses a per-user epoch and time-boxed fail-open with an alert; A6 uses a same-transaction insert; A7 is an operator CLI; C5 means no role at registration; B4 is ADR-only; B1 returns 404; no new feature flags for Group A.
**Method:** every claim below was checked against the code on `main` at `3d8ec5f`. Line numbers refer to the files at that commit. **[VERIFIED]** marks a claim re-read in code for this document. Where this document contradicts the requirements doc or the story, it says so and cites the code.
**Precedent followed:** `docs/features/US-017/02-impact.md`, for structure and for keeping verified findings separate from assumptions.
**No PII.** People are referred to by role only.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Backend modules | `rbac` (all four layers), `identity.infrastructure.security` (`JwtRs256Service`), `identity.infrastructure.web` (`JwtAuthenticationFilter`), `identity.infrastructure.audit` (`RbacAuthEventAdapter`), `identity.application.service.SecureEventService`, `identity.domain` (`JwtClaims`, `AuthEventType`), `common.security` (`RequiresPermission`, new `@PublicEndpoint`, `DenialReason`, new permission constants), `common.web.GlobalExceptionHandler`, `config.SecurityConfig` |
| Frontend | Milestone 8 (B5: `Permission` type) and milestone 9 (C6: 403 redirect) only. A9's stale-epoch 401 is already absorbed by the reactive-refresh path in `auth.interceptor.ts:138-156`, so it needs no code change |
| Flyway | Next version is **V6**; the highest today is `V5__rbac_schema.sql`. Up to three migrations: **V6** (M2, A1 seed, additive), **V7** (M8, B2 constraints, additive tightening that fails if existing data is inconsistent), **V8** (M9, C1 soft-delete, **expand/contract**). See §12 |
| `nexus_app` grants | Changed **only by C1** (M9). A1 and B2 need none. The three ADR-0014 D6 artifacts are listed in §12.2 |
| Contract changes | `JwtClaims.CURRENT_VERSION` goes 2→3 under A9 (not under A11). 403 becomes 404 for cross-tenant targets (B1). `user:write` changes meaning (A1). New endpoints for C1/C2/C3. Details in §14 |
| New dependencies | **None required.** Redis is already a dependency (ADR-0016, `pom.xml:100`). A circuit breaker library for A9 is optional and needs its own cost/benefit case (§8.7) |
| ADRs | Next free number is **0021** (`docs/adr/` holds 0001–0020; renumbered from 0019 at Gate 3 to avoid a clash). Needed: A1–A5 (supersedes parts of 0017/0018), A9/A10 (supersedes ADR-0013 D1/D4 and ADR-0016 D4/D5 on the points listed in §8.6), and B4 (accepted risk) |
| **Largest finding** | **A9 alone does not deliver near-immediate revocation.** A holder rejected for a stale epoch refreshes, and `RoleResolutionService` then serves the *same stale permission set* from cache under a *fresh* epoch, for up to 900 s (§8.2). A10 is therefore **not** subsumed by A9. The design must either fan out cache eviction or key the cache on the epoch |

### Re-trace of the two `[REPORTED]` findings (requirements §3)

| Finding | Result | Evidence |
|---|---|---|
| `RoleResolutionService` re-reads role names live; a cached permission set lives up to 900 s; `attach`/`detach` do not clear holders' cache entries | **CONFIRMED, and worse than reported** | Live role read: `RoleResolutionService.java:57`. Cache hit is decided on role-set equality alone: `:59-62`. TTL: `RedisPermissionCacheAdapter.java:45` (default 900), `application.yml:143`. `RoleManagementService` has **no** `PermissionCachePort` collaborator at all (constructor `:75-86`), so attach (`:175-276`) and detach (`:290-339`) cannot evict. Eviction exists only for the single target user on assign/revoke (`RoleAssignmentService.java:304`, `:546`). **Worse than reported:** this same cache also defeats A9 (§8.2) |
| `RoleManagementService`'s mint-side gate is name-based | **CONFIRMED** | `verifyCallerIsActiveTenantAdmin` (`RoleManagementService.java:386-413`) resolves the literal `TENANT_ADMIN` role id (`:392-393`) and probes one `(user, role)` pair (`:397-400`). It is called only for dangerous permissions: on attach (`:186-194`) and, since US-017 D13, on detach (`:297-305`). **Nuance not in the requirements doc:** the four non-dangerous permissions (`tenant:read`, `user:read`, `role:read`, `audit:read`) can be attached by *any* `role:write` holder with no caller check at all, including to a role the caller holds. A3 closes that too. Separately, `RoleController.java:175-176` still says "No AC11 gate" on detach, which is stale doc drift |

### Top 3 risks

Full list in §17.

1. **A9 is defeated by the mint-time cache and by bump/mint ordering** (§8.2, §8.3). Without per-holder cache eviction (or an epoch-keyed cache), and without "read the epoch before permissions; bump after commit", a revoked permission is re-minted into a token that carries a valid epoch. That is a silent fail-open.
2. **Rolling-deploy token churn from A11 plus A9.** Strict `schema_version == CURRENT_VERSION` (A11) followed by the 2→3 bump (A9) means that during a rolling deploy every in-flight token gets a 401 on instances of the other version. The refresh rate limit (30 per IP per window, `application.yml:203`) can then log out users who share a NAT'd IP. A11 must be built to accept a *set* of supported versions (§6, §14.1).
3. **Interim coexistence between M2 and M3, then A5's removal** (§14.3, §3). A1 moves the assign gate from `user:write` to `user:role:assign`. That invalidates the premise of ADR-0018 D2 ("every caller holds `user:write`"), and it leaves open whether the new permission joins `RbacDangerousPermissions`. A2 does not cover **revoke** at all, so A5 must not retire the US-016 revoke-side caller gate (T-E17, administrator stripping) without a replacement.

---

## 1. Milestone 1 — A8 deny-by-default enforcement

**Layers:** `common.security` (new annotation); `identity.interfaces.rest` (annotations only); test (`architecture`). **Reuse / extend / create:** create `@PublicEndpoint`; extend `HexagonalArchitectureTest`.

| File | Change | R/E/C |
|---|---|---|
| `common/security/PublicEndpoint.java` | New `@Target(METHOD) @Retention(RUNTIME)` marker. It is marker-only, with no AOP, so package-private handlers remain legal | Create |
| `architecture/HexagonalArchitectureTest.java` | New rule: every method carrying a `@*Mapping` meta-annotation in a `@RestController` class must carry exactly one classification. Second new rule: no class calls a `@RequiresPermission` method declared on itself (self-invocation). Existing rules `requires_permission_methods_must_be_public_and_non_final` (`:153-163`) and `..._declaring_classes_must_not_be_final` (`:165-172`) stay unchanged | Extend |
| `identity/interfaces/rest/LoginController.java` (`login` :85, `refresh` :106, `logout` :129) | `@PublicEndpoint` | Extend |
| `identity/interfaces/rest/RegistrationController.java` (:72, :100, :121) | `@PublicEndpoint` ×3 | Extend |
| `identity/interfaces/rest/PasswordResetController.java` (:61, :88) | `@PublicEndpoint` ×2 | Extend |
| `identity/interfaces/rest/JwksController.java` (:29) | `@PublicEndpoint` | Extend |
| `identity/interfaces/rest/UserProfileController.java` (`me()` :22-44) | **Does not fit a two-way classification** (see below) | Decide at Gate 2 |
| `rbac/interfaces/rest/{UserRole,Role,Permission}Controller.java` | Already fully annotated (7 handlers). No change | — |
| `config/SecurityConfig.java:77-84` | The `permitAll` list and the `@PublicEndpoint` set can drift apart. A unit test asserting that they match is cheap and recommended | Optional |

**Finding: A8 as written cannot classify `GET /api/v1/users/me`.** The endpoint is authenticated but needs no permission (`SecurityConfig.java:85`, `anyRequest().authenticated()`). The frontend calls it on every login and refresh (`auth.service.ts:193`). Under C5 (no role at registration), a new user holds **zero** permissions, so `me()` cannot take a `@RequiresPermission`. Marking it `@PublicEndpoint` would be false. **Gate 2 must add a third marker** (for example `@AuthenticatedEndpoint`) or define `@PublicEndpoint` as meaning "no permission required" and document the distinction. Recommended: the third marker, because "public" is read by reviewers as meaning unauthenticated.

**Scope note:** `@AnalyzeClasses(importOptions = DoNotIncludeTests)` (`HexagonalArchitectureTest.java:34-36`) excludes the test-only `GuardedTestController` used by `CrossTenantPermissionIT`, so it needs no annotation. The actuator and swagger endpoints are not `@RestController` methods and are out of the rule's reach.

**No DB, API, frontend or flag impact.**

---

## 2. Milestone 2 — A1–A4 grant-subset core (P0; closes US-016 RES-1(b)/T-E27 and US-017 RES-13)

**Layers:** domain, application, infrastructure.persistence, interfaces.rest, migration.

### 2.1 Files

| File | Region | Change | Driven by |
|---|---|---|---|
| `db/migration/V6__rbac_user_role_assign_permission.sql` | new | Seed `user:role:assign`. The next literal in the V5 sequence is `019f6839-1807-7000-8000-000000000008`. Grant it to **every** `is_system_role` `TENANT_ADMIN` (all tenants, via `INSERT … SELECT`), not only the bootstrap literal, so this is also the first instance of B7's pattern (§12.1) | A1, EC1 |
| `rbac/interfaces/rest/UserRoleController.java` | `USER_WRITE` constant `:62`; POST `:85`, `:99`; DELETE `:146`, `:158`; `@ApiResponse` text `:89-93`, `:150-152` | `@RequiresPermission` and `resolveActor` switch to the new permission. GET `:118` stays `user:read` | A1 |
| `rbac/application/RoleAssignmentService.java` (1,130 lines **[VERIFIED]**) | `USER_WRITE` `:67`, used as `requiredPermission` at `:215-216`, `:258`, `:442-443`, `:498`, `:790` | Becomes the new permission | A1 |
| same | `assign()` `:210-379`, between the throttle (`:225`) and the duplicate check (`:277`) | Insert A4 (self-target and caller not fully admin-equivalent) and A2 (target-role permission ids ⊆ caller's live permission ids). Placement in §13.2 | A2, A4 |
| same | `recordDenial` `:1083-1107` | Reused for A4's `ROLE_ASSIGNMENT_DENIED`, and for A2's if Gate 2 wants an A2 audit row | A4 |
| `rbac/application/RoleManagementService.java` (466 lines) | `attachPermission` `:174-276` | A3: the caller must hold `permissionId` (live read). This applies to **every** permission, not just dangerous ones | A3 |
| `rbac/application/port/out/UserRoleAssignmentPort.java` | new method(s) | "Caller's active permission **ids** in tenant", a fresh read inside the write transaction. **Do not reuse M12** (`findPermissionNamesForActiveAssignmentsOfUser`, `:127`): its contract says "MUST NEVER be used for an authorization decision" (`JpaUserRoleRepository.java:145-147`), and MC-G asserts that (`RoleAssignmentServiceTest.java:2366`, `:2435`, `:2613`) | A2, A3 |
| `rbac/infrastructure/persistence/JpaUserRoleRepository.java` | new query | Compare by permission **id**, not name. Ids sidestep the case-insensitivity trap documented at `RbacDangerousPermissions.java:42-51`, and they keep permission names off the port (ADR-0017 D2). Carry the `r.tenantId = ur.tenantId` cross-check (T-S1). If locking is chosen, **never** put `FOR SHARE`/`FOR UPDATE` on `permissions`: `nexus_app` holds only `SELECT` there (`02-grants-post-schema.sql:31`), so a locking read would fail in production and pass every Testcontainers IT. MC-A (`LastAdminLockoutIT.java:837`, `:873`, `:1010`) must be extended to the new query | A2, A3 |
| `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` | delegation | New delegate. The constructor should stay as it is (ADR-0017 D2) | A2, A3 |
| `common/security/DenialReason.java:8-15` | enum | Probably two new values (self-assignment; grant exceeds caller). Each adds one series to `nexus.rbac.permission_denied{reason}` (`GlobalExceptionHandler.java:167-171`). This is bounded | A2, A4 |
| `rbac/domain/RbacDangerousPermissions.java:14` | `NAMES` | **Interim decision (§14.3):** whether `user:role:assign` joins the set until A5 | A1/A5 |
| `rbac/domain/RbacAdminEquivalence.java:25-28` | `isFullyAdminEquivalent` | A candidate definition for A4's "fully admin-equivalent" (§13.2) | A4 |
| `docs/adr/0021-…md` | new | Grant-subset ADR (A1–A5) | Story Tech Notes |

### 2.2 Reuse vs create

- **Reuse:** the tenant 404 checks, `requireNotThrottled`, `recordDenial`, `registerPostCommitSideEffects`, `ROLE_ASSIGNMENT_DENIED`, `RBAC_001`, `InsufficientPermissionException`.
- **Extend:** `UserRoleAssignmentPort` with one read, and `DenialReason`.
- **Create:** V6, ADR-0021.
- **No new exception type and no new error code.** A2, A3 and A4 all return 403 `RBAC_001`.

### 2.3 Behavioural consequences worth naming

- **The benign path stops being free.** US-016/017 preserved "+0 statements on the benign path" (`RoleAssignmentService.java:235-238`). A2 applies to **every** assignment, so the benign path gains the caller-permissions read, and the target role's permission read (M7) becomes unconditional. Today M7 is skipped when the name matches (`:229-233`).
- **EC7 is confirmed at the code level:** a target role with no permissions passes A2 trivially. Most existing IT `seedRole` helpers attach no permissions, which is why most ITs survive A2 unchanged.
- **The closure claim needs a caveat for the threat model.** A4 blocks the *self* pre-positioning step behind RES-1(b). A non-admin with `user:role:assign` can still assign a role that A2 accepts to a *colluding second user*, whom an admin later escalates through attach. A3 does not help there, because the admin holds the permission. Record this as a residual, not a closure.

---

## 3. Milestone 3 — A5 retire superseded machinery (+ D3)

**Layers:** domain, application, infrastructure.health, tests, docs. **Nature:** removal, so the risk is Critical (requirements R1).

### 3.1 Candidate inventory

"Candidate" means the ADR decides. Nothing here is removed by this impact analysis.

| Machinery | Location | Verdict to argue in the ADR |
|---|---|---|
| Target-side privileged gate (name OR ANY dangerous) | `RoleAssignmentService.java:229-233` (assign), `:460-464` (revoke); `RbacAdminEquivalence.isAdminEquivalent` | On **assign**, redundant under A2. On **revoke**, **not** redundant: A2 does not apply to revoke, and this gate is the T-E17 control against administrator stripping. It needs a replacement, for example a "revoke-subset" rule: the caller must hold every permission of the role being revoked |
| Caller gate M5b (TENANT_ADMIN or ALL three) | `:846-879`, `:254-260`, `:493-500` | Same split: redundant on assign, still needed on revoke unless replaced |
| Union lock set M10+M8+M11, ascending comparator | `:118-124`, `:681-725`, `:241-251`, `:475-490` | **Keep in some form.** The last-admin guard `:507-528` depends on M11 and on `callerQualifyingIds`. The lockout is kept by story decree (FR-A5.b), so "admin" needs a post-A1 definition (§13.2), and whatever set that defines must still be locked |
| Canaries: `self_role_assignment{privileged,callerIsAdmin}`, M12-based second mechanism, pre-INSERT caller read | `:272-275`, `:333-365`, `:1005-1016` | Largely redundant once A4 denies non-admin self-assignment. The page alert `nexus_rbac_gate_bypass_canary` (`US-016/monitoring.md:33`) depends on it, so retire the alert in the same change |
| `privileged_role_change_allowed`, `admin_minted_by_non_named_admin`, lock-hold timer, lock-set-size summary | `:87-94`, `:598-619`, `:897-941` | Decide per signal |
| Mint-side name-based gate | `RoleManagementService.java:386-413`, `:186-194`, `:297-305` | Replaced by A3 on attach. Detach needs an explicit decision: A3 does not cover detach, and detach flips roles out of admin-equivalence (ADR-0018 D13) |
| Holder-count signal (D13) and "became fully admin-equivalent" (D22) | `RoleManagementService.java:201-210`, `:239-272`, `:421-427` | D22 is redundant if "admin-equivalence" is retired. D13 is a useful *signal* independent of A2/A3; keep it unless argued otherwise |
| `RbacZeroActiveAdminsHealthIndicator`, `ZeroAdminTenantReader` | `rbac/infrastructure/health/…` | Keep, and redefine to match the lockout's post-A1 "admin" definition. A7 reuses the same predicate |
| ArchUnit `role_management_service_must_not_call_the_non_locking_admin_read` | `HexagonalArchitectureTest.java:180-197` | Obsolete if `hasActiveAdminAssignment` is no longer called from `RoleManagementService`; otherwise keep |

**FR-A5.c ("shrinks materially") is still untestable.** A proposed measurable proxy: "no US-016/017 predicate symbol remains on the assign path".

### 3.2 D3

This is comment rewriting in the two services. Lines `:158-208` and `:385-436` duplicate a 50-line security narrative, and most of it becomes false after M2. Do it in this milestone, not before, so the prose is rewritten once.

---

## 4. Milestone 4 — A6 audit write atomicity

**Layers:** application (rbac, identity), infrastructure.audit, port contract.

| File | Change |
|---|---|
| `rbac/application/port/out/RbacAuditPort.java:11-20` | The contract splits. The five success methods (`:25`, `:28`, `:58`, `:64`, `:70`) go from "MUST NEVER throw, post-commit" to "joins the caller's transaction, MUST throw on failure". `recordRoleAssignmentDenied` (`:51`) keeps `REQUIRES_NEW` (FR-A6.c). Recommended: keep one port with two documented method groups, and do not add a second port. Adding one would be a new abstraction with a single use |
| `identity/infrastructure/audit/RbacAuthEventAdapter.java` | The success paths `record(…)` (`:132-163`, `:200-239`) currently catch-all and swallow (`RBAC_AUDIT_WRITE_LOST`). They must **propagate** instead. Metadata serialization failure must also propagate |
| `identity/application/service/SecureEventService.java:52-55` | `recordEvent` is `REQUIRES_NEW`. Add a sibling with `Propagation.MANDATORY`, which fails if no transaction is present and therefore also catches a mis-wired caller. **It must flush.** `AuthEvent` has an assigned `@Id`, so the INSERT otherwise happens at commit (`RbacAuthEventAdapter.java:37-46`), and a commit-time failure surfaces as a 500 (`TransactionSystemException`) instead of a mapped error |
| `identity/infrastructure/persistence/JpaAuthEventAdapter.java` | Its retry-buffer catch must **not** apply on the atomic path. A buffered success audit is by definition not atomic (ADR-0011 scope note) |
| `rbac/application/RoleAssignmentService.java` | Move `recordRoleAssigned` (`:305-312`) and `recordRoleRevoked` (`:547-554`) out of `registerPostCommitSideEffects` and inline them before return. Cache eviction, the INFO log, the timer stop and the canary stay post-commit |
| `rbac/application/RoleManagementService.java` | Same move for `recordRoleCreated` (`:116-125`), `recordRolePermissionGranted` (`:214-223`) and `recordRolePermissionRevoked` (`:319-328`) |

### 4.1 Side effects

- **Lock-hold time grows on the privileged path.** The audit INSERT now runs inside the M11 X-lock region, which lengthens what `nexus.rbac.privileged_revoke_lock_hold` measures. Re-baseline it; `US-016/monitoring.md` §4 is still "PENDING".
- **Connection-pool pressure improves on the success path.** It no longer takes a second pooled connection for `REQUIRES_NEW`. The denial path still does (`role-assignment-denial-pool-pressure.k6.js` remains the relevant load test).
- **No DB or grant change.** `GRANT INSERT, SELECT ON nexus.auth_events` (`02-grants-post-schema.sql:23`) already covers the insert. The append-only triggers on `auth_events` are untouched.
- **No outbox**, per the Gate 1 decision. EC9 therefore does not apply.

---

## 5. Milestone 5 — A7 first-admin bootstrap / break-glass (operator CLI)

**Layers:** new `rbac.interfaces.cli` (the adapter), `rbac.application` (a new service), `rbac.application.port.out` (an alert port), `identity.infrastructure.audit` (the adapter implementation), config.

| File | Change | R/E/C |
|---|---|---|
| `rbac/application/BootstrapAdminService.java` | New use case. It **must not call `RoleAssignmentService.assign()`**, which resolves EC2 by construction (§13.1). Precondition: the tenant has zero qualifying admins, evaluated **under the same M11 lock set** so it cannot race a concurrent assign or revoke. Otherwise it refuses (break-glass must not become a general backdoor). Audit is written atomically (A6 pattern) | Create |
| `rbac/interfaces/cli/…Runner` | `ApplicationRunner` under a dedicated profile, with `spring.main.web-application-type=none`. Precedent: `identity/infrastructure/seed/DevDataInitializer.java:31`, the only runner in the codebase. **There is no CLI precedent:** no picocli or spring-shell (`pom.xml`). Recommend plain `ApplicationRunner` arguments rather than a new dependency | Create |
| `rbac/application/port/out/…AlertPort` | FR-A7.c requires an alert. `identity.application.port.out.AuditAlertPort` / `LoggingAuditAlertAdapter` exist, but `rbac` must not import `identity` (`HexagonalArchitectureTest.java:113-125`). Declare the port in `rbac` and implement it in `identity.infrastructure`, which is the established direction (`RateLimitRoleChangeThrottleAdapter.java:21-26`) | Create |
| `identity/domain/AuthEventType.java` | New event type for the break-glass grant. Consider the PRIORITY lane (`:86-96`) | Extend |
| `docs/features/US-012/runbook.md` (the manual `INSERT` at line 59/124 area) | Replace with the CLI procedure | Extend |

### 5.1 Findings the design must handle

1. **`user_roles.assigned_by` is `NOT NULL` with an FK to `users(id)`** (`V5__rbac_schema.sql:68`, `:77`). A CLI has no acting user row. The only schema-compatible choice is `assigned_by = target user` (self-reference, as test fixtures do at `CrossTenantPermissionIT.java:163-164`), with the operator attribution carried in the audit metadata (actor type, ticket or change reference; **no operator PII**). Any other choice is a migration.
2. **Only the bootstrap tenant has a `TENANT_ADMIN` role row** (`V5__rbac_schema.sql:119-125`). "Create a tenant's first admin" for any other tenant would also require creating the system role and its permissions, and that is per-tenant role seeding, which the story lists as out of scope (Epic 3). Gate 2 must decide: either the CLI refuses tenants without a seeded `TENANT_ADMIN`, or it seeds one and the scope note is amended.
3. **DB user.** If the CLI runs as `nexus_app`, it already holds `INSERT` on `user_roles`, `roles`, `role_permissions` and `auth_events`. **No grant change.** If ops want a separate break-glass DB principal, that adds a fourth grant artifact set, and it is not recommended.
4. **Dependency on M2.** The admin the CLI creates must hold `user:role:assign`, so V6 must land first.

---

## 6. Milestone 6 — A11 token claim validation

**Layers:** identity.infrastructure.security (and web, defensively).

| File | Change |
|---|---|
| `identity/infrastructure/security/JwtRs256Service.java` `verify()` `:107-159` | **[VERIFIED]** `schemaVersion` is null-checked (`:137`) but never compared. `tenant_id` is read unchecked (`:143`). Add: a version check against a **supported-version set**, not strict equality (§14.1); `tenant_id` must be present and parse as a UUID; throw `AUTH_003` otherwise |
| `identity/infrastructure/web/JwtAuthenticationFilter.java` `:80-84` | **[VERIFIED]** `Map.of(...)` throws an NPE on a null `tenantId`. Once `verify()` guarantees non-null, the filter needs no change. A defensive null guard is optional |
| `identity/domain/JwtClaims.java:28-29` | No new field, so **no version bump**. If the supported set is modelled here (for example `SUPPORTED_VERSIONS`), that is an additive constant |

**Why the supported-set shape matters now:** M7 bumps the version to 3. With strict equality shipped in M6, a rolling deploy of M7 puts v2-checking and v3-issuing instances behind one load balancer, and tokens bounce with 401s. See §14.1.

---

## 7. Milestone 7 — A9 revocation epoch + A10 cache fan-out

**Layers:** rbac (application port + infrastructure.cache), identity (security, web), config, ADR.

### 7.1 Files

| File | Change | R/E/C |
|---|---|---|
| `rbac/application/port/out/PermissionEpochPort.java` + `rbac/infrastructure/cache/Redis…EpochAdapter.java` | Per-user epoch: read, bump, and a bump for many holders. Keyspace per ADR-0016 D3: `nexus:rbac:epoch:{tenantId}:{userId}`. Placing it in `rbac` keeps the existing `identity → rbac` direction; `JwtRs256Service` already imports `RoleResolutionService` (`:11`) | Create |
| `identity/domain/JwtClaims.java` | New epoch field; `CURRENT_VERSION` 2→3 (`:29`) | Extend |
| `identity/infrastructure/security/JwtRs256Service.java` `issue()` `:71-96` | Embed the epoch. **The epoch must be read before `roleResolutionService.resolve(...)` (`:74-75`)** (§8.3) | Extend |
| same, `verify()` | Parse the new claim, which is required for v3 | Extend |
| `identity/infrastructure/web/JwtAuthenticationFilter.java` `:72-87` | After `verify`, one O(1) epoch lookup. A stale epoch goes to the entry point and returns 401 `AUTH_003`. The constructor gains a collaborator | Extend |
| `config/SecurityConfig.java:133-136` | `jwtAuthenticationFilter` bean wiring | Extend |
| `rbac/application/RoleAssignmentService.java` `revoke()` post-commit block `:544-569` | Bump the target user's epoch (after commit) | Extend |
| `rbac/application/RoleManagementService.java` attach/detach post-commit blocks | Bump every **active holder's** epoch. The per-user granularity forces a fan-out; use `findActiveUserIdsForRole` (M9, `UserRoleAssignmentPort.java:197`). **Also evict each holder's permission cache (A10), or make the cache epoch-aware** (§8.2). A `PermissionCachePort` collaborator must be added (the constructor currently lacks one, `:75-86`) | Extend |
| `rbac/application/RoleResolutionService.java:57-67` | Either stays as is (with A10 eviction fan-out) or includes the epoch in the freshness fingerprint | Extend |
| `application.yml` | New `nexus.rbac.epoch.*` settings (fail-open time box, command timeout). **Do not inherit `spring.data.redis.timeout: 2000ms` (`:49`) on the hot path** | Extend |
| `docs/adr/0022-…md` | Token freshness ADR | Create |

### 7.2 Frontend

No frontend change is needed, but **only because of a backend rule the original version of this section missed** (corrected 2026-09-26, threat model T-D17 / RC-24.2). A 401 on a non-auth path triggers the shared single-flight refresh and replay (`auth.interceptor.ts:138-156`). If the replay fails, the session is cleared and the user is sent to `/auth/login` (`:150-154`).

**Correction.** The interceptor attaches the current bearer to **every** same-origin API call, including `POST /auth/refresh` and `/auth/logout` (`auth.interceptor.ts:125-129`; only the proactive block at `:104` excludes auth paths). `JwtAuthenticationFilter` verifies any bearer on any path and sends a failure to the entry point (`JwtAuthenticationFilter.java:66-92`, no `shouldNotFilter`). So a refresh after a stale-epoch 401 carries the same stale bearer. If M7's epoch check or its degraded-closed 503 ran on that request, the refresh would fail and the session would be cleared: every revoke or detach would log holders out, degraded-closed would block refresh for everyone, and a logout with a stale bearer would never revoke the refresh family. The same root cause already rejects a reactive refresh that carries an **expired** bearer. The terminal behaviour above is correct only if the backend (a) never issues a token that is stale on arrival (§8.3), **and** (b) never rejects a bearer on `@PublicEndpoint` requests. Design §9.5 adopts (b).

---

## 8. Cross-cutting findings for A9/A10 (inputs for ADR-0022)

### 8.1 A9 is the first per-request Redis dependency, despite what the ADRs say

ADR-0008 (trigger note, `:68-71`) and ADR-0016 D4 state that a `jti` denylist on Redis "is now implemented". **It is not.** No denylist code exists in `src/main` (repo-wide search), and `JwtAuthenticationFilter` consults nothing but `JwtPort.verify` (`:73`). Consequences: A9 introduces the **first** Redis call on the authenticated hot path, and ADR-0016's "fail open, loudly alerted" precedent for per-request checks has never been exercised in production. Record this drift in ADR-0022.

### 8.2 The mint-time cache defeats the epoch (A10 is not optional)

The sequence after `detachPermission(role R, perm P)`, with a holder H:

1. The post-commit step bumps H's epoch. H's next request is rejected with 401 (A9 works).
2. The frontend refreshes. `RefreshTokenUseCase` calls `JwtRs256Service.issue` (`:71`), which calls `RoleResolutionService.resolve` (`:74-75`).
3. H's **role set is unchanged**, so the cache check passes (`RoleResolutionService.java:59-62`) and returns the cached permission set **still containing P**.
4. The new token carries a **fresh epoch plus P**, and it is accepted for up to 900 s (the cache TTL) plus the remaining token TTL.

So "rely on A9's epoch bump" (the option A10's DoD leaves open) is **insufficient on its own**. It works only if one of these holds: holders' cache entries are evicted in the same post-commit step; the cache entry is keyed or fingerprinted on the epoch; or B6 removes the cache. This is also the concrete coupling that B6 ("must stay consistent with A9") was pointing at.

### 8.3 Ordering rules that decide fail-open vs fail-safe

- **Mint: read the epoch first, then resolve permissions.** Suppose a bump lands between the two reads. With the order epoch-then-permissions, the token has the old epoch and new permissions, so it is rejected and the client refreshes once (safe). With the reverse order, the token has old permissions and a new epoch, so it is **accepted with stale permissions (fail-open)**.
- **Bump: after commit** (`afterCommit`, the existing `registerPostCommitSideEffects` hook). A bump before commit lets a mint in the gap read the new epoch plus pre-commit permissions, which is the same fail-open.
- **Lost bumps.** A post-commit bump that fails because Redis is unavailable is lost. Tokens then stay valid until `exp` (≤900 s), which is the pre-A9 baseline, so this is bounded. It must be counted and alerted.
- **Absent key semantics.** If Redis loses keys (a restart without AOF, or a flush), "absent" must not mean "mismatch", or every session gets a 401 at once and a refresh storm follows. Gate 2 alternative: store a per-user **revoked-before timestamp** and compare it with the existing `iat` claim. An absent key then means "no revocation", which degrades exactly like a lost bump. It also needs **no new claim, so no `CURRENT_VERSION` bump** and no in-flight token break. The cost is second-level `iat` granularity: the design must pick `>=` or `>` for the same-second race. This is a per-user epoch in timestamp form and stays within Gate 1 decision OQ2. It avoids §14.1's churn entirely, and it is flagged here as the lower-risk option.

### 8.4 Time-boxed fail-open (Gate 1 OQ1) needs a defined end state

The story and Gate 1 fix "time-boxed fail-open with alert", but not what happens **after** the time box. The design must state:

- the post-box behaviour (fail closed with 401, or remain open after incident acknowledgement);
- the entry signal (metric, and a page on entry);
- per-instance versus cluster-wide degraded state;
- how a slow Redis differs from a down Redis (EC6).

`management.health.redis.enabled: false` (`application.yml:118-120`) means readiness will not reflect Redis. That is correct for fail-open, but it means the alert must come from the new metric.

### 8.5 Fan-out cost

Per-user granularity turns a single attach or detach into O(active holders) Redis writes (pipelined), plus O(holders) cache evictions. It is bounded by holder count. No production figures exist (requirements Gap §8.1). Add a holder-count bucket to the metric; the D13 bucket precedent is at `RoleManagementService.java:434-445`.

### 8.6 ADR supersession ADR-0022 must record

| Superseded point | Why |
|---|---|
| ADR-0013 D1 ("the JWT is the authority", no per-request RBAC state) | A9 adds per-request state |
| ADR-0013 D4 (accept cache lag, no bulk invalidation on role edits) | A10 reverses it |
| ADR-0016 D4 (the RBAC cache is consulted at mint only; the jti denylist is described as implemented) | New per-request capability, plus the drift in §8.1 |
| ADR-0016 D5 ("No bulk cache invalidation across all holders of a role") | A10 reverses it explicitly |

### 8.7 Circuit breaker

No Resilience4j (`pom.xml`). A small hand-rolled degraded-state holder (failure timestamp plus time box) is enough for one call site. A library needs a cost/benefit case (ADR-0016 follow-on rule).

---

## 9. Milestone 8 — Group B (B1–B8)

| AC | Files / lines | Layers | Notes |
|---|---|---|---|
| **B1** 403→404 | `RoleAssignmentService.verifySameTenant` `:1036-1045`, `resolveRoleInTenant` `:1051-1061`; `RoleManagementService.resolveRoleInTenant` `:348-357`; `GlobalExceptionHandler.java:65-69` (404, logged at DEBUG) versus `:159-176` (the 403 handler, which is where the WARN and `nexus.rbac.permission_denied{reason=CROSS_TENANT_TARGET}` are emitted today) | application, common.web | The WARN and the metric must move to the service, or into a new `ResourceNotFoundException` subtype that the handler maps to a **byte-identical** 404 body (same `code`: `USER_NOT_FOUND` / `ROLE_NOT_FOUND`). **Timing-oracle risk:** the cross-tenant path writes a `REQUIRES_NEW` denial audit row synchronously (`:217-222`, `:444-447`), while a genuine not-found writes nothing. Gate 2 must decide whether the denial row survives, and if so, how the latency difference is accepted or flattened. Also: `listActive` `:635` (cross-tenant GET goes 403→404), and the `@ApiResponse` text in all three controllers |
| **B2** | New V7 (§12.1) | migration | No entity change is needed, because `ddl-auto=validate` does not check FKs or unique keys |
| **B3** | `RoleAssignmentService.java:354`, `RoleManagementService.java:254`. These are the only two `tenantId` metric tags (repo-wide search) | application | `US-015/monitoring.md:75` groups a panel `by (tenantId, …)`, so update it. The alert expressions (`US-015/monitoring.md:54`, `US-016/monitoring.md:33`) do not group by tenant and are unaffected. Attribution already exists in the WARN logs (`:359-364`) |
| **B4** | `docs/adr/0023-…md` only | docs | ADR-only per Gate 1 |
| **B5** | New `common.security.Permissions` constants. Replace the per-class literals at `UserRoleController.java:62-63`, `RoleController.java:60-61`, `PermissionController.java:34`, `RoleAssignmentService.java:67-68`, `RoleManagementService.java:58-59`. Add a test (preferred over a startup check, because it has no runtime DB dependency) that scans `@RequiresPermission` values against the seeded catalogue. Frontend: a `Permission` union in `shared/types/` used by `has-permission.directive.ts:65` and `permission.guard.ts:48-52`. Fix the fake names `roles:read` / `users:delete` in `permission.guard.ts:18`, `has-permission.directive.ts`, the specs, and `docs/DEVELOPMENT_GUIDE.md:107`, `:146` | common, interfaces, frontend | The constants must live in `common.security`, not `rbac.domain`, because `identity` controllers may need them and `rbac → identity` is forbidden while `common` is neutral. A typed guard **must not** change the fail-open semantics that four `permission.guard.spec.ts` tests pin (`:68`, `:73`, `:78`, `:86`) unless that is decided explicitly |
| **B6** | `RoleResolutionService`, `PermissionCachePort`, `RedisPermissionCacheAdapter`, eviction calls in `RoleAssignmentService.java:304`, `:546` | application, infrastructure.cache | **Couples to §8.2.** Removing the cache also removes A9's defeat mode, so decide B6 with that option on the table, not after |
| **B7** | Migration pattern (already used by V6, §12.1) plus a test. `RbacSchemaMigrationIT` T-E6 (`:221+`) already asserts that `TENANT_ADMIN` holds every permission for the bootstrap tenant; generalize it to every `is_system_role` `TENANT_ADMIN` | migration, test | Runtime startup sync is not recommended: it would be a runtime write to an API-immutable system role |
| **B8** | `RoleAssignmentService.requireNotThrottled` `:769-791`, called at `:225`/`:455` **before** the privileged computation. `RateLimitRoleChangeThrottleAdapter` keeps a **per-JVM** throttled-until map even when the Redis store is used (`:38-43`, RES-11). `nexus.security.rate-limit.store-type: memory` is the default (`application.yml:198`) | application, identity.infrastructure.security, config | "Privileged" has to be redefined after A5. A shared store needs a non-destructive read on `RateLimitStore` or a Redis-native adapter. EC8 (probing through throttle timing) applies to the new placement |

---

## 10. Milestone 9 — Group C (C1, C2, C3, C5, C6)

| AC | Files | Layers | Notes |
|---|---|---|---|
| **C1** PATCH/DELETE `/api/v1/roles/{roleId}` | `RoleController`, `RoleManagementService`, `RoleManagementPort` (`:34-98`), `JpaRoleManagementAdapter`, `JpaRoleRepository`, new request DTO, `AuthEventType` (+ROLE_UPDATED/ROLE_DELETED), new `RBAC_009` for "role has holders" (`RBAC_001`–`008` are taken; `RBAC_003` exists at `SystemRoleImmutableException.java:20`) | all | **Hard delete is impossible for any role that was ever assigned.** `user_roles` is append-only (the trigger at `V5:96-102`), and revoked rows keep `fk_user_roles_role` (`V5:76`) pointing at the role. "Revoke first, then delete" therefore still fails on the FK. The design must choose one of two: **(a) soft delete**, a new column, which means V8 is expand/contract because `uq_roles_tenant_name` (`V5:39`) must be replaced by an active-name key so a deleted name can be reused, every role read must filter deleted rows, and a grant is needed; or **(b) hard delete only for never-assigned roles**, with 409 otherwise, which contradicts the story's "unless revoked first" wording. **Also:** CORS `allowedMethods` omits `PATCH` (`SecurityConfig.java:178`), so a browser PATCH fails preflight. A rename is also a role-name change, and role names feed the JWT `roles` claim and `RoleResolutionService`'s fingerprint. It is cosmetic for authorization (every name check reads the DB), so bumping the epoch is optional |
| **C2** pagination | `RoleListResponse`, `PermissionListResponse`, `RoleAssignmentListResponse` (currently `{data}` only); repos gain `Pageable` variants | interfaces, persistence | Adding `page`/`links` is additive on the wire. **Behavioural break:** a default page size of 20 truncates lists that were complete before (up to 500 roles per tenant, `RoleManagementService.java:80`). There is no frontend consumer today |
| **C3** access review | New controller (for example `AccessReviewController` in `rbac.interfaces.rest`), `@RequiresPermission("audit:read")`: `GET /api/v1/roles/{roleId}/holders`, `GET /api/v1/permissions/{permissionId}/holders`, `GET /api/v1/users/{userId}/effective-permissions` | all | Reuse: `findActiveUserIdsForRole` (M9, needs tenant scoping and paging), `UserRoleQueryPort.findActivePermissionNames` (`JpaUserRoleRepository.java:53-65`, already tenant-checked). New: a permission-holders query. The index path is `role_permissions.permission_id` (auto-index, `V5:53-57`) then `fk_user_roles_role`. **Responses carry ids only, no email or name (PII).** Cross-tenant ids return 404 (consistent with B1). It needs a flag decision: ride `feature.nexus-us015-rbac-role-management` or get its own. Gate 1's no-new-flags rule covers Group A only |
| **C5** | **No code change.** `RegisterUserUseCase` assigns no role **[VERIFIED]** (no role reference in the file). Docs: EPIC-002 [ARC] section. Stale comment: `RoleAssignmentService.java:627` says "every self-registered MEMBER otherwise holds `user:read`", which is false; fix it with D2 | docs | — |
| **C6** | `nexus-frontend/src/app/core/http/api-error.interceptor.ts:14-57`, which has no navigation today **[VERIFIED]** | frontend | Navigate on `status === 403 && code === 'RBAC_001'` only; `ACCESS_DENIED` does not redirect. Provide an opt-out, for example an `HttpContextToken`, for components that handle 403 inline. Epoch 401s are handled earlier: `authInterceptor` is last in `withInterceptors([correlationId, apiError, auth])` (`app.config.ts:109`), so it sees responses first. The `/access-denied` route already exists and is unguarded (`app.routes.ts:152-158`) |

---

## 11. Milestone 11 — Group D (D1, D2, D4, D5)

Docs only: `docs/story/2-rbac/EPIC-002.md`, `docs/features/US-016|US-017/*`, `docs/DEVELOPMENT_GUIDE.md`, ADR-0014/0015 (the correction for V5's stale header comment, since V5 itself is immutable). D4 must describe the **final** shapes of A1–A4, A8's classification markers (including the third one, §1), A9's latency and fail-open behaviour, and B5, so it lands last. D5 is traceability only.

---

## 12. Database changes summary

### 12.1 Migrations (ADR 0003: append-only, `ddl-auto=validate`)

The highest existing migration is `V5__rbac_schema.sql`. Version numbers assume the delivery order in §16. **Assign the number at merge time**, because Flyway rejects out-of-order versions by default.

> **Superseded numbering (2026-09-26, design Revision 1, RC-40.4).** The design splits the V7 below into one `ALTER` per file, so the final list is: V6 (M2) seed and footer · V7 (M8) `roles UNIQUE (id, tenant_id)` · V8 (M8) `user_roles` composite FK · V9 (M9) soft-delete expand · V10 (M9, next release) soft-delete contract. `03-design.md` is authoritative; the table below is kept as analysed.

| Version | Milestone | Content | Additive? | Existing-data risk |
|---|---|---|---|---|
| **V6** | M2 (A1, and B7's pattern) | `INSERT` permission `user:role:assign`; `INSERT role_permissions SELECT` for every `is_system_role` `TENANT_ADMIN` in all tenants (`NOT EXISTS`-guarded, idempotent). **Optional backfill** (§13.3) | **Additive** (data only) | None |
| **V7** | M8 (B2) | `ALTER TABLE roles ADD CONSTRAINT uq_roles_id_tenant UNIQUE (id, tenant_id)`; `ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_role_tenant FOREIGN KEY (role_id, tenant_id) REFERENCES roles (id, tenant_id)`. **Keep** `fk_user_roles_role`, because dropping it would be a contract step for no benefit | Additive schema, but a **tightening** | **The migration fails if any `user_roles.tenant_id` ≠ `roles.tenant_id` row exists**, which blocks application startup (Flyway runs on boot). A pre-flight detection query belongs in the runbook. Adding an FK with `foreign_key_checks=1` uses the COPY algorithm, which blocks writes on `user_roles` for the rebuild; the table is small today, but plan a maintenance window. `UNIQUE (id, tenant_id)` is trivially satisfied because `id` is the PK. `uq_user_role_active` and the DELETE trigger are unaffected |
| **V8** | M9 (C1), only if soft delete is chosen | New `deleted_at` column; an active-name generated key; a new unique index; **drop** `uq_roles_tenant_name` | **Expand/contract.** Expand: add the column and the new unique index, and deploy code that filters deleted rows. Contract: drop the old unique index in a later release | Low (new column is nullable) |

No migration for A6 (`auth_events` is sufficient), A7 (given §5.1 item 1), A9 (Redis), A11, B1, B3, or C2–C6.

### 12.2 `nexus_app` grant artifacts (ADR-0014 D6)

There are three artifacts that must stay byte-consistent:

- `nexus-database/mysql/init/02-grants-post-schema.sql:31-35`
- `docs/runbooks/nexus-app-provisioning.md:76-80`
- `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java:156-165`

`src/test/resources/nexus-app-grants.sql` only creates the user.

| Milestone | Grant change |
|---|---|
| M2 (V6) | **None.** Flyway's DDL user writes the seed. `nexus_app` only reads `permissions` |
| M8 (V7) | **None.** DML FK checks need no `REFERENCES` privilege for `nexus_app`, which matches the story's statement |
| M9 (C1) | **Yes.** `GRANT UPDATE (name, description) ON nexus.roles`, column-scoped (the ADR-0015 D7 precedent), plus either `UPDATE (deleted_at)` (soft delete) or `DELETE ON nexus.roles` (hard delete). **`RbacDbPrivilegeHealthIndicator` must change too:** its `roles` legs (`:274-307`) currently treat any `UPDATE`/`DELETE` on `roles` as drift. It must still flag `UPDATE` on `is_system_role`/`tenant_id`. **To verify:** whether the implicit `updated_at ON UPDATE CURRENT_TIMESTAMP` (`V5:37`) needs a column privilege under column-scoped UPDATE |
| M5 (A7) | None, if the CLI runs as `nexus_app` |

### 12.3 A1 seed and backfill

- **The seed** must use the all-tenants `INSERT … SELECT` pattern. The V5 bootstrap-only literal pattern would leave every other tenant's `TENANT_ADMIN` failing its own A2 check on any role that carries `user:role:assign` (EC1).
- **Backfill for custom roles holding `user:write`** is a Gate 2 decision (§13.3).
- **Blast-radius evidence:** both parent flags are hard-coded `enabled: false` in the base config (`application.yml:219-228`) and `true` only in `application-dev.yml:53-56` and `application-test.yml:11-14`. There is no prod profile file in the repo, so a production override (for example an env var through relaxed binding) **cannot be ruled out from code**. Confirm with Ops.

### 12.4 B2 composite FK and existing test data

`RoleResolutionServiceIT.should_excludeRole_when_userRolesTenantIdMismatchesTheRolesOwnTenant` (`:162-183`) **deliberately inserts** a mismatched row. After V7, that insert fails at the DB. Rewrite the test as TS-12 evidence (expect an FK violation), and let `JpaUserRoleRepository`'s T-S1 Javadoc (`:30-35`) record that the defense-in-depth now also has a DB backstop. `CrossTenantPermissionIT`'s seed is **consistent** (role and `user_roles` are both in tenant B, `:166-172`), so it survives V7.

---

## 13. Inputs for Gate 2 (preliminary; the decision belongs to design)

### 13.1 EC2: A4 versus the A7 bootstrap path

Resolve it **structurally**, not with an exemption flag. A7's `BootstrapAdminService` never calls `RoleAssignmentService.assign()` (§5), so A4 needs no bootstrap exemption and A4's code stays unconditional. Add an ArchUnit rule restricting `BootstrapAdminService` callers to `rbac.interfaces.cli`, so the privileged path cannot be reused from REST. A7's own guard is a "zero qualifying admins under lock" precondition.

### 13.2 A2/A4 denial precedence (and A4's "fully admin-equivalent")

Proposed order inside `assign()`:

1. tenant 404s
2. throttle (placement per B8)
3. **the existing US-016/017 caller gate (kept until A5)**
4. **A4**
5. **A2**
6. the duplicate check (409)

The same four checks without step 3 apply after A5. The rationale:

- Keeping step 3 first in M2 means **every existing `NOT_TENANT_ADMIN` denial assertion stays stable**. A2 and A4 only add denials on paths that are allowed today.
- A4 before A2: it is an in-memory equality plus a caller read that A2 needs anyway, and it is the more specific security signal (pre-positioning).
- **One denial audit row per request, carrying the first reason that fired.** Both checks return 403 `RBAC_001`, so they are wire-identical and only `DenialReason` and the audit metadata differ.

"Fully admin-equivalent" (A4) has two candidates:

- (i) the existing `RbacAdminEquivalence.isFullyAdminEquivalent` (`:25-28`): `TENANT_ADMIN` by name, or all three dangerous permissions;
- (ii) the caller holds **every permission in the catalogue**.

(ii) is the definition native to grant-subset: a caller holding everything cannot be escalated by a later attach, so self-assignment is provably harmless. It depends on B7's all-tenants pattern (EC1), which is why that pattern moves into V6. Recommend (ii). A5 then re-expresses the last-admin lockout on the same definition, so there is one notion of "admin".

### 13.3 A1 backfill

- **(a) No backfill.** Run a pre-deploy detection query (count non-system roles carrying `user:write`) and put a runbook note in place. This is recommended if Ops confirms no production override of the parent flags.
- **(b) V6 grants `user:role:assign` to every non-system role holding `user:write`.** This preserves capability but carries the old conflation forward into new data. Those roles are still bounded by A2.

The choice should follow the detection query's result in each environment, not be assumed.

### 13.4 Performance budgets

| Path | Today | Added I/O | Proposed budget |
|---|---|---|---|
| `assign`/`attach` (A2/A3) | Benign path: 5 statements, +0 for the gate | +1 indexed read (caller permission ids, via `fk_user_roles_user`), +M7 when the name matches | Inherit EPIC-002's **p95 < 300 ms** for guarded endpoints (`EPIC-002.md:185`); cap the added latency at **< 10 ms p95**. This is an admin-only, low-RPS path, so the < 5 ms read-path budget does not apply |
| Every authenticated request (A9) | JWT verify only | +1 Redis GET | Must fit inside EPIC-002's **< 5 ms p95 RBAC overhead** (`EPIC-002.md:29`, `:454`). Proposed: **≤ 2 ms p95** for the epoch check, and a **dedicated command timeout of about 50 ms** instead of the 2 s default. Lettuce pool: `max-active: 16` (`application.yml:52`) under virtual threads; benchmark at 200 RPS |
| Attach/detach fan-out (A9/A10) | 0 Redis writes | O(holders) pipelined epoch bumps plus cache evictions, post-commit | Report `holders` as a bucketed tag; no latency SLO (post-commit) |

---

## 14. Contract and breaking changes

### 14.1 `JwtClaims` version (A9, A11)

- **A11: no bump**, because no claim is added. It *must* ship accepting `{2}` in a form that can later accept `{2,3}` (a supported set).
- **A9: 2→3**, unless Gate 2 adopts the `iat`-based alternative (§8.3), which adds no claim and needs no bump.

**In-flight tokens at the A9 deploy (EC10):**

- **Hard cutover (accept only v3):** every live session gets one 401, then a refresh (the refresh token is an opaque DB row, not a JWT, so refresh works). The cost is a refresh spike at deploy, bounded by the per-IP refresh limit of 30 (`application.yml:203`). NAT'd tenants can be rate-limited into logout.
- **Grace window (accept {2,3} for one access-token TTL, 900 s):** no forced 401s. A v2 token carries no epoch, so it cannot be revoked during the window. That is the pre-A9 baseline for ≤15 minutes. **Recommended**, and it is also required for a safe rolling deploy.
- **Rolling deploy:** instances on the old and new versions coexist. Strict equality on either side produces 401 ping-pong. This is why A11 must use a supported set.

`JwtClaimsContractTest` (`:77-81`) pins exactly 10 claims and must be updated. That is its intended role as a freeze gate.

### 14.2 B1 (403→404)

- **Wire:** the status changes for cross-tenant targets on 5 handlers: POST, GET and DELETE on user roles, plus GET and POST/DELETE on role permissions through `resolveRoleInTenant`.
- **Error body:** it must equal the not-found body exactly.
- **Correction to the story and requirements:** `CrossTenantPermissionIT` does **not** exercise `CROSS_TENANT_TARGET`. It asserts a `PERMISSION_ABSENT` 403 from the evaluator through a test controller (`:102-112`), and that must **stay** 403. B1's real test blast radius is in §15.
- **Clients:** no frontend consumer. The flags are off in base config.

### 14.3 A1: what `user:write` means

- **Before:** "edit users + assign/revoke roles". **After:** "edit users" only.
- **Silent capability loss** for any custom role that relied on `user:write` to assign (EC3), mitigated per §13.3.
- **Knock-on:** ADR-0018 D2's vacuity proof ("every caller holds `user:write`", `RoleAssignmentService.java:183-185`) loses its premise. The ALL-three caller predicate stays narrower, so nothing fails open. ADR-0021 must restate the reasoning on the new premise.
- **Interim decision (M2→M3):** whether `user:role:assign` joins `RbacDangerousPermissions.NAMES`.
  - If it joins, `carriesAll` becomes all **four**, and every fully admin-equivalent custom role that lacks the new permission **stops qualifying** as a caller. That is a lockout-population change the health indicator would report.
  - If it does not join, a role carrying only `user:role:assign` is "benign" to the US-016 gate, and is bounded only by A2.
  - Recommended: **do not add it**, rely on A2, and let A5 retire the set.

### 14.4 API additions (no versioning bump; all additive under `/api/v1`)

- C1: `PATCH /api/v1/roles/{roleId}` (200) and `DELETE /api/v1/roles/{roleId}` (204). Errors: 409 `RBAC_003` for a system role, 409 `RBAC_009` if the role has holders, 404, 403. CORS must add PATCH.
- C2: `page`/`size` query params, and `page`/`links` in the envelope. The default of 20 truncates lists that were complete before.
- C3: three GET endpoints as in §10, guarded by `audit:read`, paginated, ids only.

### 14.5 Frontend-visible changes

- C6 redirect behaviour.
- B5 typing (compile-time only).
- A9: extra 401→refresh cycles, which are invisible to the user unless the refresh fails.
- **`/users/me` and `MeResponse` do not change.** The frontend never decodes the JWT (`shared/types/auth.ts:45`).

---

## 15. Test impact

### 15.1 Must change (by milestone)

| Milestone | Test | Why |
|---|---|---|
| M1 | `HexagonalArchitectureTest` | New rules |
| M1 | `RequiresPermissionWebTest` | Only if the marker semantics touch it |
| M2 | `RbacSchemaMigrationIT` `:182-190` (8→9 system role permissions), `:193-206` (7→8 names); `:162-171` stays true but becomes misleading | V6 |
| M2 | **Every HTTP-level IT whose caller is seeded with `user:write` to call POST/DELETE `/users/{id}/roles`.** Likely candidates: `RoleAssignmentIT`, `RoleAssignmentAuditIT`, `RoleAssignmentCacheIT`, `RoleAssignmentSecurityIT`, `RoleRevocationSymmetryIT`, `RoleAssignmentEscalationIT`, `LastAdminLockoutIT`, `AdminEquivalentLockoutIT` (where they go through HTTP) | A1 fixture churn |
| M2 | `RoleAssignmentServiceTest`, `RoleManagementServiceTest` | **Mockito default-empty now means DENY under A2/A3.** An empty caller permission set denies any target role that carries permissions. That inverts US-017 §12.1's note that "default empty = not admin-equivalent" was the safe default. Every successful-assign or attach test with a permissioned target needs new stubs |
| M2 | `RoleManagementAdminGateIT`, `RoleManagementIT` | A3 on non-dangerous attaches |
| M3 | Retired **only with threat-model sign-off**: `LastAdminLockoutIT`, `AdminEquivalentLockoutIT`, `AdminEquivalenceEquivalenceIT`, `AdminEquivalenceSqlJavaEquivalenceIT`, `RoleAssignmentSecurityIT`, `RoleRevocationSymmetryIT`, `RoleAssignmentEscalationIT`, `RoleManagementAdminGateIT`, `DangerousPermissionHolderSignalIT`, `RbacZeroActiveAdminsHealthIndicator{Test,IT}`, `RbacAdminEquivalenceTest`, `RbacDangerousPermissionsTest`, and the MC-A/MC-C/MC-G blocks in `RoleAssignmentServiceTest` | A5 (§15.3) |
| M4 | `RbacAuthEventAdapterTest` | Swallow-path assertions flip to propagate for the five success methods |
| M4 | `RoleAssignmentAuditIT`, `RoleManagementAuditIT` | New rollback test (TS-5) |
| M4 | Unit tests asserting post-commit audit ordering | Ordering changes |
| M5 | New CLI IT (TS-6) | — |
| M5 | `DevDataInitializer` tests | Only if the profile gating collides |
| M6 | `JwtRs256ServiceTest`, `JwtRs256ServiceSecurityTest` | Version and `tenant_id` cases (TS-10) |
| M6 | `JwtAuthenticationFilterTest` | 401-not-500 |
| M7 | `JwtClaimsContractTest` | Claim set, if the version is bumped |
| M7 | `JwtClaimsTest` | New field |
| M7 | `JwtAuthenticationFilterTest`, `SecurityConfigWebTest` | Filter constructor |
| M7 | `RefreshTokenPermissionResolutionIT`, `RoleAssignmentCacheIT`, `RoleResolutionService{Test,IT}`, `RedisPermissionCacheAdapter{Test,IT}` | §8.2 |
| M8 | `RoleAssignmentSecurityIT`, `RoleAssignmentAuditIT`, `RoleAssignmentCacheIT`, `RoleAssignmentServiceTest`, `RoleManagementServiceTest`, `RolePermissionSecurityIT`, `src/test/load/role-assignment-denial-pool-pressure.k6.js` | B1: the 54 `CROSS_TENANT_TARGET` occurrences across 11 files are the inventory. `RbacAuthEventAdapterTest` changes only if the reason enum changes. **Not `CrossTenantPermissionIT`** (§14.2) |
| M8 | `RoleResolutionServiceIT:162-183` | B2 (§12.4) |
| M8 | `permission.guard.spec.ts`, `permission-guard-contract.spec.ts`, `has-permission.directive.spec.ts` | B5 renames and types. The four fail-open tests stay unless the semantics are changed deliberately |
| M9 | `RbacSchemaMigrationIT:73-76` (the `roles` column list if soft delete) | C1 |
| M9 | `RbacDbPrivilegeHealthIndicator{Test,IT}`, `RolePermissionsPrivilegeIT` | C1 grants |
| M9 | `SecurityConfigWebTest` | CORS PATCH |
| M9 | `RbacRoleManagementFeatureFlagTest` | New endpoints behind the flag |
| M9 | `api-error.interceptor.spec.ts` | C6 |

### 15.2 Must keep passing unmodified (the non-regression contract)

- `CrossTenantPermissionIT` (both tests).
- `UserRolesAppendOnlyIT`, `UserRolesPrivilegeIT`, `ActiveAssignmentIT`.
- The `LastAdminLockoutIT` lockout outcome scenarios, until A5 redefines "admin".
- MC-A's no-locking-read-on-`permissions` assertions, which must be *extended* in M2.
- `TenantAwarePermissionEvaluatorTest`.
- The four `permission.guard.spec.ts` fail-open tests.

### 15.3 At risk under A5

Every test in the M3 row of §15.1. Most importantly, the **revoke-side** tripwires:

- `RoleRevocationSymmetryIT` (T-E17);
- `LastAdminLockoutIT.should_return403_when_nonAdminAttemptsToRevokeTheTenantsLastAdmin`;
- `RoleAssignmentSecurityIT`'s non-admin-holding-`user:write` denial.

A2 does not replace these, so any of them going green by inversion signals a lost control, not an obsolete test. The distinction FR-A5.d asks for is this: a test is **obsolete** only if the ADR names the control that now enforces its assertion **and** an equivalent test against that control exists in the same PR.

---

## 16. Cross-milestone file-contention map and delivery order

| File | M1 | M2 | M3 | M4 | M5 | M6 | M7 | M8 | M9 |
|---|---|---|---|---|---|---|---|---|---|
| `RoleAssignmentService.java` | | ● A1/A2/A4 | ● A5/D3 | ● A6 | ○ (lock reuse) | | ● A9 bump | ● B1/B3/B5/B8 | |
| `RoleManagementService.java` | | ● A3 | ● A5/D3 | ● A6 | | | ● A9/A10 fan-out | ● B1/B3/B5 | ● C1/C2 |
| `JwtRs256Service.java` | | | | | | ● A11 | ● A9 | | |
| `JwtClaims.java` | | | | | | ○ (supported set) | ● A9 | | |
| `JwtAuthenticationFilter.java` | | | | | | ○ (defensive) | ● A9 | | |
| `SecurityConfig.java` | ○ (permitAll test) | | | | | | ● filter wiring | | ● CORS PATCH |
| `UserRoleAssignmentPort` / `JpaUserRoleRepository` | | ● | ● | | ● | | ○ | | ● C3 |
| `RbacAuditPort` / `RbacAuthEventAdapter` / `SecureEventService` | | ○ (A4 denial) | | ● | ● | | | | ● C1 events |
| `RbacDangerousPermissions` / `RbacAdminEquivalence` | | ○ (interim) | ● | | ○ | | | | |
| `DenialReason` | | ● | | | | | | ● B1 | |
| `HexagonalArchitectureTest` | ● | | ● | | ● | | ○ | | |
| `RoleResolutionService` / `RedisPermissionCacheAdapter` | | | | | | | ● A10 | ● B6 | |
| `db/migration` | | V6 | | | | | | V7 | V8 |
| Grant artifacts (×3) + `RbacDbPrivilegeHealthIndicator` | | | | | | | | | ● |
| Frontend | | | | | | | | ● B5 | ● C6 |

(● = substantive edit; ○ = light or conditional touch)

**Hotspots:**

- `RoleAssignmentService`: 5 milestones.
- `RoleManagementService`: 6 milestones.
- `JwtRs256Service` / `JwtClaims`: M6 then M7, a hard dependency.
- `JwtAuthenticationFilter`: effectively M7 only. A11 belongs in `verify()`, which keeps M6 away from the filter entirely.

**Recommended linear order.** It respects the user's sequential-only working preference, and every step has a single upstream:

1. **M2**: P0, dated residual 2026-11-27, and the requirements' recommendation. Lands V6.
2. **M1**: small. Landing it before M9 means C1 and C3 endpoints are compliant from the start, and it settles `@AuthenticatedEndpoint` before any new handler exists.
3. **M6**: small. Its supported-set shape is a prerequisite for M7's rolling deploy.
4. **M4**: same methods as M2, so rebase once on the stable authorization rewrite. It also gives M5 the atomic-audit pattern.
5. **M5**: needs V6 (the admin must hold `user:role:assign`), EC2's structural answer from M2, and M4's pattern.
6. **M7**: needs M6. Decide the §8.2 cache remedy here, and scope B6 against that decision.
7. **M3**: needs M2 in production-like soak, plus M4 and M7, so that A5's ADR can cite A9/A10 as the replacement for canary-based detection. It carries its own threat-model re-pass. **This is the last Group A milestone**, and it closes the GA-blocker set.
8. **M8**: B6 after M7; B8 and B1 on the smaller post-A5 file; V7.
9. **M9**: C1 migration and grants; C3 queries on the settled schema; V8.
10. **M11**: last, per D4.

One trade-off to state plainly: in this order, M3 (a GA blocker) trails M7, so the GA date depends on A5's threat-model sign-off. If that becomes the critical path, M3 can move ahead of M7. The cost is that A5's ADR then cannot lean on A9 for detection.

---

## 17. Top risks

| # | Risk | Severity | Mitigation (design-level) |
|---|---|---|---|
| 1 | The A9 epoch is defeated by the fingerprint cache (§8.2) and by bump/mint ordering (§8.3). The fail-open is silent | **High** | Per-holder cache eviction or an epoch-aware cache, in M7; order "epoch before permissions, bump after commit"; an IT reproducing the detach → refresh → still-has-P sequence (TS-9) |
| 2 | Token churn from the version bump and a rolling deploy; the refresh rate limit logs out NAT'd users | **High** | A11 supported set; a grace window of one TTL; or the `iat`-based design with no bump |
| 3 | M2→M3 interim coexistence (the ADR-0018 D2 premise shifts, dangerous-set membership, revoke not covered by A2), then A5 removes the revoke-side control | **Critical (A5) / High** | §13.2 ordering keeps the existing gate first in M2; a revoke-subset replacement is named in ADR-0021 before any removal; the §15.3 obsolescence rule |
| 4 | Silent capability loss from A1 on custom `user:write` roles | High (pending Ops) | §13.3 detection query per environment |
| 5 | B2 migration fails on a drifted row, so the app does not start; COPY-algorithm ALTER locks writes | Medium | Pre-flight query in the runbook; maintenance window |
| 6 | C1 hard delete is impossible (append-only FK) → soft delete expand/contract, grants, health indicator, CORS PATCH | Medium | Decide (a) or (b) in §10 at Gate 2; size C1 as the largest item in M9 |
| 7 | B1 timing oracle from the synchronous `REQUIRES_NEW` denial write on the cross-tenant path only | Medium | Decide at Gate 2 whether the denial row survives; if it does, accept or flatten the difference in the threat model |
| 8 | A8's two-way marker misclassifies `/users/me` | Low | Third marker (§1) |
| 9 | A7: `assigned_by NOT NULL` and non-bootstrap tenants lack a `TENANT_ADMIN` role | Medium | §5.1 items 1–2 decided at Gate 2 |
| 10 | A9 hot-path latency: the inherited 2 s Redis timeout; no production sizing data | Medium | Dedicated ~50 ms timeout; benchmark against ≤ 2 ms p95 at 200 RPS before merging M7 |
