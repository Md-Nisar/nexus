# US-018 Milestone 2: Technical Documentation

**Feature:** US-018, harden RBAC for production readiness. This document covers **Milestone 2 (M2)**, the grant-subset core (A1 to A4), plus the four security-review fixes folded into the same branch (M-1, L-1, L-2, L-5). Later milestones (M1, M3 to M9, M11) are not on this branch.
**Branch:** `feature/US-018`. **Design:** [03-design.md](03-design.md) §2, §4 (binding). **ADR:** [ADR-0021](../../adr/0021-grant-subset-authorization-model.md) (Proposed). **Reviews:** [06-code-review.md](06-code-review.md), [07-security-review.md](07-security-review.md), [08-test-audit.md](08-test-audit.md).
**Operational companions:** [deployment.md](deployment.md), [rollback.md](rollback.md), [monitoring.md](monitoring.md), [runbook.md](runbook.md).
No PII: people are referred to by role, identifiers are UUIDs.

---

## 1. Overview and rationale

Before M2, assigning roles to users required `user:write`, which also meant "edit user accounts". A holder could hand out any role the legacy privilege gate allowed, and could grant themselves any non-privileged role. M2 replaces that with a **grant-subset model**: a caller may only hand out, take away, or attach what they themselves currently hold.

| Control | What it enforces | Where |
|---|---|---|
| **A1** | Assign and revoke are gated by a new permission `user:role:assign`. `user:write` now means "edit user accounts" only. GET stays on `user:read` | `UserRoleController` (`@RequiresPermission(USER_ROLE_ASSIGN)` on POST and DELETE), V6 |
| **A2** | On assign, every permission of the target role must be in the union of the caller's held permission ids | `RoleAssignmentService.requireGrantWithinCallerHoldings` |
| **A3** | On attach, the caller must hold the permission being attached (every permission, not only the dangerous ones) | `RoleManagementService.requireCallerHoldsPermission` |
| **A4** | A caller who is not an administrator cannot assign a role to themselves | `RoleAssignmentService.requireAdministratorForSelfAssignment` |
| **M-1** (security review) | Revoke-subset: the same subset check A2 applies, run on revoke, pulled forward from M3 | `revoke()` calls `requireGrantWithinCallerHoldings(..., OPERATION_REVOKE, ...)` |
| **L-1** (security review) | The endpoint permission itself (`user:role:assign`, or `role:write` on attach) must still be in the caller's live DB holdings, not only in the JWT | `requireCallerStillHoldsUserRoleAssign`, and the first branch of `requireCallerHoldsPermission` |
| **L-2** (security review) | M14 returns `Optional<Set<UUID>>`; empty means "role not in the caller's tenant" and denies | `JpaUserRoleAssignmentAdapter.findPermissionIdsForRole(roleId, tenantId)` |
| **L-5** (security review) | M15 lives on a narrow read-only repository, not on the writable `JpaPermissionRepository` | `JpaPermissionCatalogueRepository` |

**Why it matters.** It closes the literal self-target step of US-016 RES-1(b) and the mint side of US-017 RES-13 (name-based). It does **not** close RES-1(b) completely (section 7).

### Definition of "administrator" (design §2.1)

A role is **admin-defining** iff it alone carries every permission in the `permissions` catalogue (`RbacAdministrators.isAdminDefining(rolePermissionIds, catalogueIds)`, ids only, empty catalogue returns false). A user is an **administrator** iff they hold an active admin-defining role. Two different questions are asked, and each rule asks exactly one:

- *Could the caller have granted this themselves?* Uses the **union** of the caller's held permission ids: A2, A3, revoke-subset.
- *Is the caller an administrator?* Uses the **per-role** predicate: A4 (in M2).

Holding the whole catalogue across two partial roles does not make a caller an administrator.

## 2. Order of checks

`assign()` (`RoleAssignmentService.java`):

1. Tenant checks on the target user and the role (404, or 403 `CROSS_TENANT_TARGET` until M8's B1).
2. Throttle (`requireNotThrottled`).
3. Legacy privileged-role gate (US-016/017, name or dangerous-permission based; privileged targets only, under the M11 union lock). Retired in M3.
4. **One** M13 read (`findHeldRolePermissionIdsForAuthorization`).
5. **L-1:** the caller's live rows must contain `user:role:assign`.
6. **A4:** self-target only; M15 (catalogue) read only on this branch.
7. **A2:** M14 (target role's permission ids) is a subset of the M13 union.
8. Duplicate check, 409 `RBAC_004`.
9. Insert, then the post-commit side effects (audit row, cache eviction, logs, timers).

`revoke()`: tenant checks, then 404 if the assignment is not active, then throttle, legacy gate, **M13 read, L-1, revoke-subset (M13 contains M14)**, then the last-admin lockout 409, then the update. Authorization (403) always precedes the lockout (409), so a 409 never tells an unauthorized caller "this is the last admin". Note the 404 for an inactive assignment still precedes the throttle (L-6, pre-existing, deferred to M3).

`attachPermission()` (`RoleManagementService.java`): tenant resolution, 409 system role, 404 permission, legacy dangerous-permission gate (AC11, still present in M2), **L-1 (`role:write` in live rows), then A3**, then the duplicate check 409 `RBAC_005`, then insert. A3 runs before the duplicate check so a denied caller learns nothing about attachment state.

## 3. Denial model

Every denial is an `InsufficientPermissionException` carrying a `DenialReason`. `DenialReason` gained two values in M2: `GRANT_EXCEEDS_CALLER` and `SELF_ASSIGNMENT`. `PERMISSION_ABSENT` already existed and is now also used by L-1.

| Situation | Reason | 403 `requiredPermission` | Audit row | WARN log `event` |
|---|---|---|---|---|
| A2 on assign, or revoke-subset on revoke | `GRANT_EXCEEDS_CALLER` | `user:role:assign` | yes: `ROLE_ASSIGNMENT_DENIED` with `operation` and `missingCount` (a count, never ids) | `RBAC_GRANT_EXCEEDS_CALLER` (fields: `tenantId`, `actorUserId`, `targetUserId`, `roleId`, `operation`, `missingCount`) |
| A4 | `SELF_ASSIGNMENT` | `user:role:assign` | yes | `RBAC_SELF_ASSIGNMENT_DENIED` |
| L-1 on assign or revoke | `PERMISSION_ABSENT` | `user:role:assign` | yes | `RBAC_ENDPOINT_PERMISSION_NOT_HELD` |
| L-1 on attach | `PERMISSION_ABSENT` | `role:write` | **no** (Decision 7) | `RBAC_ENDPOINT_PERMISSION_NOT_HELD` |
| A3 | `GRANT_EXCEEDS_CALLER` | `role:write` | **no** (Decision 7) | `RBAC_ATTACH_EXCEEDS_CALLER` |

Properties:

- **One audit row per request**, carrying the first reason that fired (`recordDenial`, `REQUIRES_NEW`, ADR-0009).
- **Centralised metric.** `nexus.rbac.permission_denied{permission,reason}` is incremented in exactly one place, `GlobalExceptionHandler.handleInsufficientPermission`, from the exception. Services never increment it, so there is no double count.
- **No oracle on role contents.** The 403 body is `RBAC_001` with a generic message plus the endpoint permission. `reason` appears in logs and the metric, never in the body. Audit metadata carries `reason`, `operation` and (for A2/revoke-subset) `missingCount` only.
- **Fail closed.** A throwing M13, M14 or M15 read propagates as a 500 and never allows. An empty M13 result denies any role that has permissions. A role with no permissions passes A2 (EC7, it grants nothing). An empty catalogue means nobody is an administrator.
- **Throttle.** A4, A2, revoke-subset and L-1 denials on assign/revoke are booked against the same per-`(tenant, actor)` denial throttle (`nexus.rbac.denial-throttle.*`). A throttled actor currently receives reason `NOT_TENANT_ADMIN` (pre-existing; tidied in M8 with B8).

### 3.1 Defensive branch for M14

If M14 returns an empty `Optional` (the role is not readable in the caller's tenant), the service denies with `CROSS_TENANT_TARGET`, writes a denial row with no role name, and logs WARN `RBAC_GRANT_CHECK_ROLE_NOT_IN_TENANT`. It is unreachable today because `resolveRoleInTenant` runs first in the same transaction; seeing this log means an invariant broke.

## 4. The M13 / M14 / M15 lookups

| Id | Port method (`UserRoleAssignmentPort`) | Shape | Hosted on |
|---|---|---|---|
| **M13** | `List<RolePermissionRef> findHeldRolePermissionIdsForAuthorization(UUID userId, UUID tenantId)` | `(roleId, permissionId)` rows over the user's active `user_roles`, joined to `roles` with `r.tenantId = ur.tenantId` (T-S1) and to `role_permissions`. Ids only, never joins `permissions`, non-locking. The service derives the union (A2, A3, revoke-subset, L-1) and the per-role sets (A4) from this **one** read, so the inputs can never disagree | `JpaUserRoleRepository` |
| **M14** | `Optional<Set<UUID>> findPermissionIdsForRole(UUID roleId, UUID tenantId)` | One `LEFT JOIN` statement from `roles` to `role_permissions`, tenant-predicated. Empty `Optional` means the role is not in the tenant (denied as `CROSS_TENANT_TARGET`); a present empty set means a role with no permissions | `JpaRoleRepository.findPermissionIdsByRoleAndTenantId`, mapped by the adapter |
| **M15** | `Set<UUID> findCatalogueIds()` | All permission ids (the global catalogue has no tenant column). Read only on a self-target assign | `JpaPermissionCatalogueRepository` (`Repository<Permission, UUID>`, one method) |

None of the three is a locking read (asserted by `LastAdminLockoutIT` SQL capture and by unit tests). `nexus_app` has `SELECT` only on `permissions`. M13 runs inside the write transaction's snapshot; the resulting TOCTOU window is RES-27 (Low, accepted).

**M12 is never used for a decision.** `findPermissionNamesForActiveAssignmentsOfUser` is documented as non-authoritative; an ArchUnit rule (`m12_is_never_read_on_an_rbac_decision_path`) enforces this. M12 is deleted in M3.

## 5. Key decisions

1. **Permission name `user:role:assign`.** A three-token name for a relationship resource. ADR-0021 amends ADR-0013 D1. `role:assign` was rejected because `role:*` governs role definitions. Seeded id `019f6839-1807-7000-8000-000000000008` (V6), held in `RbacSeededPermissionIds`.
2. **`user:role:assign` is not added to `RbacDangerousPermissions`** in the M2 to M3 interim, so the legacy caller and lockout populations do not silently shrink (design §4.2).
3. **No backfill to custom roles** that hold `user:write`; instead the pre-deploy detection query in [deployment.md](deployment.md). The V6 footer does, however, preserve admin-defining status (statement (a)), which is not a backfill: only roles that already carried the whole catalogue gain the new id.
4. **Ids, not names**, cross the port for the new reads, which avoids the case-insensitivity trap and keeps permission names out of the application layer.
5. **Snapshot read, not locking**, for M13 (a locking read outside the set-lock region would reopen the ADR-0018 D6 hazard).
6. **A3 and L-1-on-attach write no audit row**, matching the shipped AC11 gate: `ROLE_ASSIGNMENT_DENIED` is scoped to assign and revoke by contract. The trail is the WARN (1-year retention precondition) plus the metric.
7. **No new feature flag, no new error code, no new config property.** The parent flags still gate the controllers (section 8).

## 6. Accepted deviations from the design, and corrections

These were found by the reviews and are recorded here because the design text (Revision 3) was not rewritten.

| # | Deviation | Reason |
|---|---|---|
| D-1 | **M14 signature** is `findPermissionIdsForRole(roleId, tenantId)` returning `Optional<Set<UUID>>`; design §4.3 says `Set<UUID> findPermissionIdsForRole(UUID roleId)` | Tenant predicate satisfies the tenant-isolation architecture test without an allowlist entry; the `Optional` makes "not in tenant" fail closed (security review L-2) |
| D-2 | **M15 is hosted on `JpaPermissionCatalogueRepository`**, not on `JpaRoleRepository` or `JpaPermissionRepository` | Read-only interface, least privilege (security review L-5). `UNSCOPED_ALLOWLIST` in `TenantIsolationArchitectureTest` is unchanged |
| D-3 | **`JpaUserRoleAssignmentAdapter`'s constructor changed** (design §4.3 says unchanged) | It now also takes the catalogue repository |
| D-4 | **Revoke-subset and the endpoint-permission re-check landed in M2**, not M3 and not at all | Security review M-1 and L-1. Revoke-subset in M2 is the **union check only**; the extra "administrator" requirement on admin-defining targets, and role-subset on detach, remain M3 |
| D-5 | **Stale design counts.** Design §4.7 said the pre-migration catalogue was "the 8 V5 permissions"; V5 seeds **7** (V6 makes **8**). §4.11 listed the `RbacSchemaMigrationIT` counts as "8→9 and 7→8" in the wrong order | Fixed in 03-design.md. Verified against `RbacSchemaMigrationIT`: permissions 7→8 (`should_seedExactly8Permissions_when_migrationApplied`), system-role permissions 8→9 |
| D-6 | **T-E32 / RES-1(b): "self path closed; transformed into RES-26".** A4 closes only the literal self-target step. A holder of `user:role:assign` can still assign an A2-permitted benign role to a second account that an administrator later escalates by attaching permissions to it. Where self-registration is open, one attacker can hold both accounts | Reported as "self path closed; transformed into RES-26", never "fully closed". RES-26 was accepted at Gate 2 (owner: Platform Security Owner; review 2026-11-27; Epic-3 hard expiry). Preventive and detective controls (`RBAC_010`, the attach provenance signal) are M3 |
| D-7 | **Build config:** `nexus-backend/.mvn/jvm.config` now carries `-Dscan=false -Ddevelocity.scan.disabled=true` | Disables Develocity build scans for local and CI Maven runs; no runtime effect |
| D-8 | **M1 (T-004): the `@AuthenticatedEndpoint` identifier rule is stricter than design §3.1 / RC-40.2**, which ban only `UUID`-typed `@PathVariable` / `@RequestParam`. The rule (`HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier`, name kept for traceability) fails on any `@PathVariable`, any `@RequestParam` (including `String`), any `@ModelAttribute`, any `@MatrixVariable`, any `@RequestHeader`, any `@CookieValue`, any parameter of raw type `UUID` whatever its annotations, any `ServletRequest` (`HttpServletRequest`) parameter, and any parameter with no `org.springframework.web.bind.annotation` annotation that is not a principal or response type (MVC would bind it implicitly: simple types as `@RequestParam`, others as `@ModelAttribute`; fail closed). Allowed: `Authentication`/`Principal`, `HttpServletResponse`, `@AuthenticationPrincipal`, `@RequestBody`. A header needed by a future handler is allowlisted by name, never by allowing `@RequestHeader` in general. Identifiers inside a `@RequestBody` are out of scope | User-approved: Option B in the T-004 plan (any `@PathVariable`, UUID `@RequestParam`), extended after code review M1 (M-2 and open question 1) to `String` request params, `@ModelAttribute`, `@MatrixVariable` and implicit binding. The house style declares identifiers as `String` (D15) and MVC binds an unannotated `UUID` as `?userId=`, so the UUID-only wording was bypassable. Extended again after security review M1 (F-4): `@RequestHeader("X-User-Id")`, `@CookieValue` and `HttpServletRequest.getParameter(...)` were the same IDOR by another route, and the rule's own `because()` already promised "no request-bound identifier of ANY type". `UserProfileController.me()` takes only `Authentication` and still passes. Negative fixtures in `AccessMarkerRuleFixturesTest` (the passing principal-only fixture no longer takes an `HttpServletRequest`) |
| D-9 | **M1 (T-004): the negative ArchUnit fixtures are static nested classes of the test classes** (`AccessMarkerRuleFixturesTest`, and the one `EndpointClassificationWebTest` imports explicitly), not a separate test-only package (design §3.4; 04-tasks.md T-004 suggests `architecture/fixtures/`) | A top-level fixture `@RestController` in test sources would be picked up by the `com.example.nexus` component scan of every `@SpringBootTest` and registered as a real handler. Spring Boot's `TestTypeExcludeFilter` leaves classes nested in a test class out of the scan; `EndpointClassificationWebTest` asserts that no other nested test handler is registered. The production ArchUnit scan uses `DoNotIncludeTests`, so the fixtures never fail it |
| D-10 | **Stale design count (M1).** Design §3.1 says `@RequiresPermission` covers "7 rbac handlers"; there are **9** | Verified: 9 `@RequiresPermission` handlers in `rbac.interfaces.rest` (`RoleController`, `UserRoleController`, `PermissionController`); `EndpointClassificationWebTest`'s completeness sweep covers 19 production handlers (9 public, 1 authenticated, 9 permission-guarded). 03-design.md is not rewritten |
| D-11 | **M1 security review F-1: handlers that `RequestMappingHandlerMapping` does not serve are banned and the handler mappings are pinned** (design §3.1 / §3.4 cover annotated controllers only). `HexagonalArchitectureTest.no_handlers_outside_annotated_controllers` fails any production class that depends on `org.springframework.web.servlet.function..` (`RouterFunction`), `HttpRequestHandler` or `org.springframework.web.servlet.mvc.Controller`, outside `NON_ANNOTATED_HANDLER_ALLOWLIST` (empty). `EndpointClassificationWebTest` pins the `HandlerMapping` bean types (`HANDLER_MAPPING_TYPES`, one reason each; an unlisted type fails), asserts `RouterFunctionMapping.getRouterFunction()` is null, `BeanNameUrlHandlerMapping` and the welcome-page mappings are empty, every `SimpleUrlHandlerMapping` holds only `ResourceHttpRequestHandler`s, and a main-source handler is registered only in `requestMappingHandlerMapping`. The silent `isProduction()` exclusion is replaced by `NON_PRODUCTION_HANDLER_ALLOWLIST` (springdoc, `BasicErrorController`, actuator operation handlers, `ResourceHttpRequestHandler`, MVC's OPTIONS handler, `GuardedTestController`, the matcher fixture; one reason each, never a main-source class): a non-production handler type not on it fails every sweep | A `RouterFunction`, a bean-name handler or an actuator `@ControllerEndpoint` bypassed the marker rule and both sweeps while a zero-permission caller reached it (review proof). Test-only; no production handler of these kinds exists. Fixtures: `RouterFunction`, `HttpRequestHandler` and `mvc.Controller` classes |
| D-12 | **M1 security review F-2: static handler methods and `@HttpExchange` mappings are selected by the marker rule.** A method counts as a handler when it is meta-annotated with `@RequestMapping` or `@HttpExchange` (`@GetExchange` etc.). A static method that carries a mapping fails `rest_handlers_must_carry_exactly_one_access_marker` whatever its markers, and `requires_permission_methods_must_be_public_and_non_final` also requires non-static (name kept for traceability) | MVC registers and invokes a `public static` handler directly, so `@RequiresPermission` on it was silently unenforced while every rule passed; an unmarked static or `@GetExchange` handler also passed. Fixtures: static `@RequiresPermission @GetMapping` (fails both rules), unmarked static, unmarked `@GetExchange` |
| D-13 | **M1 security review F-3: overrides of a `@RequiresPermission` supertype or interface method must be proxyable.** The hierarchy semantics added after code review M-1 stay (a marker on an interface or base-class method counts). The new rule `requires_permission_overrides_must_be_proxyable` requires every concrete method that overrides or implements an annotated method to be public, non-final and non-static, in a non-final class | The review offered direct-only resolution for this marker or a hierarchy rule; the hierarchy rule keeps M-1's behaviour, which matches how Spring Security resolves the annotation. A `public final` implementation was reachable by a zero-permission caller with only a startup WARN. Fixtures: `public final` implementation and final implementing class (fail), plain public implementation (passes) |
| D-14 | **M1 security review F-5: every HTTP method on every `permitAll` path is swept through the ordered handler mappings** (design §3.1 claims the drift test catches both directions; the per-pattern sweep sent one URI per pattern only). `should_reach_only_public_handler_when_request_hits_permit_all_path` resolves GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS on each `permitAll` entry (a trailing `/**` entry is sampled as its base and one child) the way `DispatcherServlet` does and requires no handler, a `@PublicEndpoint` handler method, or an allowlisted non-production handler. The `permitAll` list is a test constant, `PERMIT_ALL_PATTERNS`, mirroring `SecurityConfig.java:77-85`; `SecurityConfig` is unchanged. Drift guard: the configured chain's own `AuthorizationManager` (public `AuthorizationFilter.getAuthorizationManager()`) is asked, for an anonymous caller and every method, about every handler-mapping path, every sample, and the sibling and child of each entry; it must grant exactly when a mirror entry matches. Probe: the `@Nested` class `PermitAllOverlapProbe` runs a dedicated context with `@AuthenticatedEndpoint @GetMapping("/api/v1/auth/{action}")` imported (as a plain class, since Boot adds a test class's nested `@TestConfiguration` classes to its own context) and asserts the sweep reports GET and HEAD `/api/v1/auth/login` | The configured matchers are reachable only through private fields of `RequestMatcherDelegatingAuthorizationManager` behind `ObservationAuthorizationManager`; reading them by reflection would tie the test to Spring Security internals that may change on any upgrade, whereas the mirror plus a public-API drift guard fails loudly in both directions (checked by temporarily dropping `/api/v1/auth/logout` from, and adding `/api/v1/users/me` to, the mirror: both reported). The sweep accepts `SamePathOtherMethodController` (`GET /api/v1/auth/refresh`) because it is allowlisted: it is the matcher's own test-only fixture, already documented as reachable anonymously while `permitAll` is path-only. The root cause, path-only `permitAll`, stays for T-009 (build `permitAll` from `PublicEndpointRequestMatcher`) |

**Known gaps that remain open after M2** (all tracked, none introduced here): L-3 (the B7 footer scanner is T-021 in M8; until then review blocks any new `INSERT INTO permissions` migration), L-4 (A3 denials leave no durable audit row, by design), L-6 (revoke returns 404 before the throttle and the privilege gate), design Mockito consequence (an unstubbed M13 means deny, so new success-path tests need stubs).

A small documentation mismatch to be aware of: the controller's `@ApiResponse` text for the revoke 403 still reads "Missing permission or cross-tenant target" and does not mention the subset denial (the assign 403 text was updated). It is a description only.

## 7. Residual risks

- **RES-26** (second-account pre-positioning; Medium; accepted at Gate 2). See D-6.
- **RES-27** (snapshot TOCTOU on lock-free paths; Low; accepted). A caller whose role is revoked within a millisecond-scale window can complete one grant on authority held earlier.
- **Token staleness.** L-1 closes the window for the new endpoints at the service layer. Systemic freshness is M7 (epoch claim); until M7, other `@RequiresPermission` endpoints still trust the JWT for up to the access-token lifetime.

## 8. Rollout, flags, schema

- **Schema:** V6 only (`V6__rbac_user_role_assign_permission.sql`), data only: one `permissions` row and the two-statement B7 footer. No DDL, no grant change.
- **Flags:** none new. `feature.nexus-us012-rbac-role-assignment.enabled` gates `UserRoleController` and `feature.nexus-us015-rbac-role-management.enabled` gates `RoleController` (A3 and the attach L-1). Both default `false` outside `dev` and `test`. The design's merge checklist asks that the parent flag not be enabled in a shared environment until M-1 is dispositioned; M-1 is now fixed.
- Details: [deployment.md](deployment.md).

## 9. API and contract surface

No endpoint was added, removed or re-routed. `POST` and `DELETE /api/v1/users/{userId}/roles[/{roleId}]` now require `user:role:assign` instead of `user:write`; `GET` is unchanged (`user:read`). The 403 body shape is unchanged (`RBAC_001`, `requiredPermission`). OpenAPI annotations (`@Tag`, `@Operation`, `@ApiResponse`) are present on every handler of `UserRoleController`. `api-spec.json` was not regenerated (see the report that accompanies this document).

## 10. Tests (from 08-test-audit.md)

Final full run: 1177 unit tests (1 skipped), 353 integration tests, 0 failures, JaCoCo gate on, `BUILD SUCCESS`. Key classes: `RoleAssignmentServiceTest`, `RoleManagementServiceTest`, `RbacAdministratorsTest`, `RolePermissionRefTest`, `JpaUserRoleAssignmentAdapterTest`, `UserRoleControllerTest`, `GrantSubsetIT` (22 tests), `RbacSchemaMigrationIT` (14), `RoleAssignmentSecurityIT`, `LastAdminLockoutIT`. No assertion was weakened during fixture churn. No load test applies to M2 (admin-only, low-volume endpoints; the hot-path item is A9 in M7).

## 11. ADR decision

**No new ADR is needed for M2.** The grant-subset model, the per-role administrator definition, the `user:role:assign` naming amendment and the retirement plan are already recorded in **ADR-0021** (D1 to D8), and the freshness trade-off (JWT staleness, M7 as the systemic fix) in **ADR-0022**. The two review-driven additions, the live DB re-check of the endpoint permission (L-1) and revoke-subset arriving in M2, are tactical applications of ADR-0021 D2 and D5, and the central metric increment is the existing `GlobalExceptionHandler` behaviour. ADR-0021 is still **Proposed**; its status should be moved to Accepted when M2 merges (an ADR status change is a maintainer decision and was not made here).

---

## 12. M7: permission token freshness (A9, A10, T-009 to T-014)

Design: `03-design.md` §9; threat model: `03b-threat-model.md`; decision record: ADR-0022 (Proposed). Reviews: `06-code-review-M7.md`, `07-security-review-M7.md`, `09-code-review-M7-part2.md`, `10-security-review-M7-part2.md`, `12-security-review-pre-PR.md`. Tests: `11-test-audit-M7-part2.md`.

**What it does.** A revoked or detached user's access token is rejected with 401 `AUTH_003` on its next request, instead of staying valid for up to 15 minutes (token) plus 15 minutes (permission cache).

**How.**
- **Epoch.** Redis key `nexus:rbac:epoch:{tenantId}:{userId}` holds a millisecond counter. One Lua script bumps it to `max(old + 1, Redis TIME)` after the revoking transaction commits (MC-7b). Tokens carry it as `perm_epoch` (schema version 3), read before permissions are resolved (MC-7a). `JwtAuthenticationFilter` rejects a token whose `perm_epoch` is below the current value. Timeouts: 50 ms per read, 500 ms per bump.
- **Detach fan-out (A10).** A detach bumps every active holder of the role in batches of 500, and the permission cache is keyed by epoch, so a bump also retires the cached set.
- **Outage policy.** `PermissionFreshnessService` is a per-instance state machine: Healthy, DegradedOpen (3 failures in 10 s), DegradedClosed after 15 min (503 `AUTH_005`, `Retry-After: 30`), Recovering (60 s). While degraded-open, an epoch this instance already saw still makes a token stale.
- **Locally known epochs.** A bounded last-seen map (read pool and own-bump pool, per tenant and global) holds the highest epoch seen. Pre-PR review M-1: the Healthy and Recovering check and the mint also use it, so a bump Redis refused or lost (`maxmemory`, a bump timeout, a failover) still makes the old token stale, and the mint is then unverified (permission set resolved uncached). A failed bump also records its instant, so a token issued at or before it is stale for a user this instance never saw. `nexus.rbac.epoch.store_regressed` counts the cases.
- **Replay.** Failed bumps and failed holder reads are queued (bounded, coalesced, per-tenant share) and retried each second.
- **Refresh limits (T-013).** `REFRESH_FAMILY` 30/60 s, `REFRESH_IP` 300/60 s, `REFRESH_IP_FAIL` 30/60 s, answered 429 `RATE_001`; junk refreshes count against the per-IP total (RES-40, accepted).
- **Startup (T-014).** `nexus.rbac.redis.require-auth` fails startup unless all three Redis factories authenticate; `application-prod.yml` sets it.

**Decisions made late (pre-PR review).**
- `server.forward-headers-strategy: none` in `application.yml`: the per-IP keys stay `getRemoteAddr()` only (DF-1). Per-client keys behind a proxy need `native` and a pinned `server.tomcat.remoteip.internal-proxies`.
- `/actuator/metrics/**` and `/actuator/prometheus` need `ROLE_TENANT_ADMIN`.
- A refused read-derived last-seen entry pages but does not fail the tenant closed (RES-31).
- The SPA attaches the bearer token only on whole `/api` path segments.

**Residual risks** (all in `03b-threat-model.md`): RES-26, RES-30 (a Redis outage longer than 15 minutes is a platform-wide authenticated 503; SRE and PM acceptance pending), RES-31, RES-40.

**API surface.** No new endpoint. Refresh answers 429 `RATE_001`; authenticated endpoints can answer 503 `AUTH_005`; `perm_epoch` is a new token claim.

