# US-012 — Technical Documentation: Enable role assignment and revocation API

**Phase:** 9 (Docs)
**Status:** Shipped — `./mvnw.cmd -o verify` green (429/429 tests, JaCoCo gates met, SpotBugs 0 bugs, Checkstyle clean)
**Audience:** engineers picking up US-014/US-015 or debugging this feature later

---

## 1. Overview

US-012 adds the **first controller in the `rbac` bounded context**: three endpoints letting a Tenant Administrator assign, list, and revoke roles for users within their own tenant.

```
POST   /api/v1/users/{userId}/roles           user:write  → 201
GET    /api/v1/users/{userId}/roles           user:read   → 200 { "data": [...] }
DELETE /api/v1/users/{userId}/roles/{roleId}  user:write  → 204
```

It is the platform's first genuinely privileged surface, and per the story's own background note (forward-tracked from US-009's threat model, T-E1) it is the **only control** standing between a self-registered bootstrap-tenant member and the all-permissions `TENANT_ADMIN` role — `TenantAwarePermissionEvaluator` (US-011) checks only flat JWT `permissions[]` membership; it performs zero tenant or resource comparison. Every tenant-isolation and self-escalation guard in this feature is service-layer logic in `RoleAssignmentService`, not something `@RequiresPermission` can express.

Full requirement/design trail: `01-requirements.md` (Gate 1, §11 Resolutions), `02-impact.md` (F1–F3), `03-design.md` (D1–D15 + 8 post-threat-model revisions), `03b-threat-model.md` (16 threats, verdict APPROVE WITH CONDITIONS), `06-code-review.md` (APPROVE WITH NITS), `07-security-review.md` (APPROVED), `08-test-audit.md` (Phase 8 report, one real bug found and fixed).

---

## 2. Architecture

```
rbac.interfaces.rest.UserRoleController          (public handlers, @RequiresPermission)
        │
        ▼
rbac.application.RoleAssignmentService           (@Transactional; owns AC4/AC5/AC8)
        │
        ├── UserRoleAssignmentPort  → JpaUserRoleAssignmentAdapter (rbac.infrastructure)
        ├── UserDirectoryPort       → JpaUserDirectoryAdapter (identity.infrastructure)
        ├── RbacAuditPort           → RbacAuthEventAdapter (identity.infrastructure) → SecureEventService (REQUIRES_NEW) → auth_events
        └── PermissionCachePort     → RedisPermissionCacheAdapter (existing, evict() unused until this story)
```

**Dependency direction, made mechanical.** The only pre-existing cross-context edge was `identity → rbac` (`JwtRs256Service` imports `RoleResolutionService`). US-012 preserves that direction: `rbac.application.port.out` *declares* `RbacAuditPort`/`UserDirectoryPort`; `identity.infrastructure` *implements* them. `rbac` imports nothing from `identity`. A new ArchUnit rule (`rbac_must_not_depend_on_identity`, `HexagonalArchitectureTest`) makes this a build failure, not documentation — closing the exact drift a US-010 code review flagged once already. A second rule bans any `..rbac.application..` method from accepting a `java.security.Principal` or `java.util.Map` parameter, closing two authentication-laundering paths the standard Spring-Security-package rule doesn't cover.

`RoleAssignmentService`'s own class Javadoc states the resulting invariant plainly: its public methods accept only `RoleChangeActor`, `UUID`, and `RequestContext` — never `Authentication`, `Principal`, or `Map`. `UserRoleController` is the only class in the request path that touches `Authentication`.

---

## 3. Key design decisions (summary of D1–D15, `03-design.md`)

Full rationale lives in `03-design.md` §0; this is the "what shipped and why" version.

| # | Decision | Why it matters |
|---|---|---|
| D1/D2 | AC5's lock (M1) and the revocation write (M6) are both **single-table, `role_id`-driven** — never `tenant_id`-driven, which is unindexed on `user_roles`. M6 is a bulk single-column JPQL `UPDATE`, never `findById→revoke()→save()`. | `nexus_app`'s grant is `UPDATE (revoked_at)` — **column-scoped**. A load-mutate-save flow would emit a 5-column `UPDATE` MySQL rejects (`ERROR 1143`) — invisible to every `*IT` because they connect as the Testcontainers superuser, and it would fail **only in production** (impact-analysis finding F1). Empirically verified against live MySQL 8.4.10 in the threat model (§0.2). |
| D3 | Separate `UserRoleAssignmentPort`, not a widened `UserRoleQueryPort`. | `UserRoleQueryPort` is documented read-only and consumed by `RoleResolutionService`/its tests; widening it would leak a write capability to a read-only collaborator. |
| D4 | Dedicated `DuplicateRoleAssignmentException` (`RBAC_004`), no-arg constructor with a static literal message. | Never echoes a caught `DataIntegrityViolationException`'s message — that message contains the constraint name and a hex fragment of `active_key` (i.e. the raw target user/role ids), which would otherwise leak into the client-visible RFC 7807 `detail` field (threat T-T7). |
| D5 | Two new `DenialReason` constants: `CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`. | Makes AC4/AC8 denials separately alertable via the existing `nexus.rbac.permission_denied{reason}` counter, at zero new plumbing cost. |
| D6 | Audit metadata JSON built in `RbacAuthEventAdapter` using the Spring-Boot-managed Jackson **3** `ObjectMapper` (`tools.jackson.databind`), never a hand-rolled escaper. | Closes a JSON-injection vector into `auth_events.metadata` via a tenant-controlled `roleName` (once US-015 ships tenant-created roles) — RFC 8259-correct escaping by construction, not a second hand-maintained copy of `RequestContext#jsonEscape`. |
| D7 | `GET` returns `{ "data": [...] }`, no pagination. | Bounded result set (≤ 2 roles/user pre-US-015); forward-compatible envelope shape per the `api-design` skill. |
| D8 | Cross-tenant target → **403**, nonexistent → **404** (not collapsed to a uniform 404). | `handleNotFound` logs DEBUG with no metric; `handleInsufficientPermission` logs WARN + counter. Collapsing to 404 would move an authorization failure into a production-invisible log level — a worse outcome than the (accepted, Low-severity) existence oracle. |
| D9 | New ArchUnit rule enforcing `rbac ↛ identity`. | Converts Gate 1's dependency-direction resolution from documentation into a build failure. |
| D10 → **reversed post-threat-model** | `ROLE_ASSIGNED`/`ROLE_REVOKED` **are** in `AuthEventType.PRIORITY` (originally excluded). | Threat T-R4: the STANDARD lane drops the newest arrival under overflow: a correlated `LOGIN_FAILURE` flood could silently drop a role-change audit event. A role change is low-volume/high-value — exactly the `PRIORITY` lane's profile. |
| D11 | New feature flag `feature.nexus-us012-rbac-role-assignment.enabled`, default `false`, **overriding** the story's own "Feature flag required: No". | This endpoint is the platform's only control against a Critical self-escalation threat; a config flip is the fastest possible kill switch if a bypass is ever found post-deploy. Matches the universal flag-gating pattern every other controller already follows. |
| D12 | New counters (`nexus.domain.conflict{code}`, `nexus.rbac.audit_write_failed{operation}`), 6 alert rules, a "RBAC / Role Assignment" dashboard row, a zero-active-admins health indicator (adopted unconditionally per threat T-D4). | Closes an observability gap the impact analysis flagged: `RBAC_002`/`RBAC_004` previously logged at DEBUG with no metric — a tenant-lockout attempt would have been invisible in production. |
| D13 | New `rbac.domain.IdGenerator` + `rbac.infrastructure.crypto.UuidV7IdGenerator`, duplicating `identity.domain.UuidGenerator`'s one-line `UuidCreator.getTimeOrderedEpoch()` call. | D9's ArchUnit rule forbids `rbac` importing `identity.domain.UuidGenerator`. Consolidating both into `common.domain` is deliberately deferred to a US-015 prerequisite, not done here — promoting now would touch ~14 unrelated `identity` files. |
| D14 | Post-commit side effects (cache evict, audit write) run via `TransactionSynchronizationManager.afterCommit`, with an inline fallback when no transaction synchronization is active. | Releases the AC5 `FOR UPDATE` row lock **before** `SecureEventService`'s `REQUIRES_NEW` call borrows a second pooled connection — closes the "second connection held behind a row lock" hazard by construction, not by monitoring. The inline fallback is also the only way a plain unit test observes these side effects. |
| D15 | Path variables and the body's `roleId` are `String` + Bean Validation / a canonical-UUID regex, parsed to `UUID` only after validation passes. | A `UUID`-typed `@PathVariable`/body field would let a malformed value raise `MethodArgumentTypeMismatchException`, which `GlobalExceptionHandler` (a plain `@RestControllerAdvice`, not `ResponseEntityExceptionHandler`) does not catch — that would 500 instead of 400. |

**ADR required? No — confirmed unchanged after implementation.** `03-design.md` §0 already answered "No" with the trigger check: every decision above traces to an already-accepted ADR (0002, 0003, 0005, 0013, 0014, 0015, 0016) or a Gate 1 Resolution. Re-verified against what actually shipped, including the Phase 8 bug fix (§4 below) — that fix is a correctness fix to an already-decided mechanism (D2's bulk-`UPDATE`-not-load-mutate-save rule), not a new architectural decision, so it doesn't change the answer. No new ADR was created for this docs pass.

---

## 4. Notable bug found in Phase 8 (test-validate) — TOCTOU escape in the assign path

**Symptom.** `JpaUserRoleAssignmentAdapter.assign()` called `userRoleRepository.save(userRole)`. A plain `save()` only *queues* the INSERT in Hibernate's persistence context inside the current transaction — it does not force the physical statement to execute.

**Why it mattered.** The very next call in `RoleAssignmentService.assign()` is the M4a re-read (`findActiveAssignmentView(...)`), which triggers Hibernate's auto-flush. That flush — not the `save()` call — is where the physical `INSERT` (and, under a genuine concurrent duplicate-assignment race, the `uq_user_role_active` constraint violation) actually happened. The `DataIntegrityViolationException` therefore surfaced **one call frame away** from the adapter's own `try/catch (DataIntegrityViolationException)`, escaping the translation to `DuplicateRoleAssignmentException` entirely. A real concurrent duplicate `POST` would have surfaced to a client as an unhandled `500`, not the intended `409 RBAC_004`.

**How it was found.** No existing test drove two genuinely concurrent `RoleAssignmentService.assign()` calls through the real adapter — `RoleAssignmentIT`'s duplicate-assignment test only exercised the service's M2 pre-check (never reaches the adapter's insert), and `ActiveAssignmentIT`'s concurrent-insert test called `JpaUserRoleRepository#save` directly, bypassing the adapter. The Phase 8 audit added an 8-thread `CyclicBarrier` race (`RoleAssignmentIT#should_allowExactlyOneWinner_when_eightConcurrentAssignsRaceForSameUserAndRole`) that reproduced the escape against real Testcontainers MySQL — red before the fix, green after.

**Fix.** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` — `save()` → `saveAndFlush()`, forcing the INSERT (and any constraint violation) to happen synchronously inside the adapter's existing `try/catch`. See the inline comment at that call site for the full explanation.

**Coverage side effect.** The same audit found `JpaUserRoleAssignmentAdapter` at 12% unit line coverage / 0-of-4 branches (the translation branch had never been unit-tested either, since no IT exercised it — see above). A new `JpaUserRoleAssignmentAdapterTest` (15 tests) brought it to 100% lines / 4-of-4 branches.

This is the single most significant finding across Phases 6–8 for this story — everything else (code review: 2 Medium/4 Low nits; security review: 3 Medium/10 Low, zero Blocker/High) was either already-mitigated-and-verified or a deferred, currently-unreachable follow-up. See `06-code-review.md` and `07-security-review.md` for the full finding lists.

---

## 5. API surface

Three endpoints (`UserRoleController.java`), fully annotated with springdoc (`@Tag`, `@Operation`, `@ApiResponse` on all handlers, matching `RegistrationController`'s convention). Verified against the actual request/response DTOs and error codes — no annotation gaps found; nothing added in this docs pass.

| Method | Path | Permission | Success | Notable error responses |
|---|---|---|---|---|
| `POST` | `/api/v1/users/{userId}/roles` | `user:write` | `201` + `Location` + body | `400` malformed UUID · `403` missing permission / cross-tenant / not-active-admin (granting `TENANT_ADMIN`) · `404` user or role not found · `409` duplicate active assignment (`RBAC_004`) |
| `GET` | `/api/v1/users/{userId}/roles` | `user:read` | `200` `{ "data": [...] }` | `400` malformed UUID · `403` missing permission / cross-tenant · `404` user not found |
| `DELETE` | `/api/v1/users/{userId}/roles/{roleId}` | `user:write` | `204` | `400` malformed UUID · `403` missing permission / cross-tenant · `404` user/role/assignment not found · `409` would revoke the tenant's last active `TENANT_ADMIN` (`RBAC_002`) |

**Request/response DTOs** (`rbac.interfaces.rest.dto`):
- `AssignRoleRequest(String roleId)` — single field, `@Pattern`-validated as a canonical UUID. Deliberately carries **no** `assignedBy`/`tenantId` field — enforced by not modeling it at all (stronger than validating it away), closing threat T-S3.
- `RoleAssignmentResponse(String userId, String roleId, String roleName, Instant assignedAt, String assignedBy)` — `assignedBy` is `null` unless the caller holds an active `TENANT_ADMIN` assignment in the tenant (see `assignedBy` redaction, below).
- `RoleAssignmentListResponse(List<RoleAssignmentResponse> data)` — the `GET` envelope.

**`assignedBy` redaction (O-10, closes threat T-I5).** `GET` is reachable by any `user:read` holder — i.e. every self-registered `MEMBER`. Without redaction, any member could enumerate the tenant's complete admin roster and who granted each role — target-selection information for a privilege-escalation attempt. `RoleAssignmentService.listActive` nulls `assignedBy` unless the caller itself holds an active `TENANT_ADMIN` assignment (`callerHoldsActiveTenantAdmin`, reusing the same underlying check as AC8). The field is present-but-null, not absent, for non-admin callers.

The live OpenAPI spec was fetched from a running instance (`GET /v3/api-docs` against the `dev` profile) and saved to `docs/features/US-012/api-spec.json` — see that file for the exact generated schema (`AssignRoleRequest`, `RoleAssignmentResponse`, `RoleAssignmentListResponse`, and the `ProblemDetail`-shaped error responses referenced from each operation).

---

## 6. Known, deliberately-deferred gaps (carried forward, not fixed in this story)

Recorded here so a future story doesn't have to re-derive them from the security review:

- **T-E9 / M-3 (accepted, documented in-code).** AC8's guard matches on the role's *name* (`TENANT_ADMIN`), not the privilege it confers, and revocation of `TENANT_ADMIN` has no symmetric "must already be an active admin" check (only granting does). Both are unreachable today — pre-US-015, only `TENANT_ADMIN` itself carries `user:write` — but a future custom-roles story **must** close both before shipping a role that can carry `user:write`/`role:write`. See the Javadoc on `RoleAssignmentService.assign`/`revoke`.
- **M-1/M-2 (security review, before the flag is enabled in production).** The two new health indicators' `/actuator/health` detail payloads (cross-tenant `tenantIds`, DB account name) are readable by any authenticated user under the current `management.endpoint.health.roles` configuration, and `RbacZeroActiveAdminsHealthIndicator`'s query runs on every unauthenticated `/actuator/health` hit with no cache TTL. Tracked as a staging→production rollout gate item, not a merge blocker (see `deployment.md`).
- **L-1/L-3 (security review, small follow-ups).** No `DataAccessException`→409 handler for a `PessimisticLockingFailureException` (falls to a 500 today); `JpaUserDirectoryAdapter.findTenantId` materializes a full managed `User` entity to read one column.

---

## Cross-references

- `docs/features/US-012/03-design.md` — full decision rationale (D1–D15), sequence diagrams, component design
- `docs/features/US-012/03b-threat-model.md` — full STRIDE analysis, all 16 threats
- `docs/features/US-012/06-code-review.md` — APPROVE WITH NITS (2 Medium, 4 Low)
- `docs/features/US-012/07-security-review.md` — APPROVED (3 Medium, 10 Low, zero Blocker/High)
- `docs/features/US-012/08-test-audit.md` — Phase 8 report; the `save`→`saveAndFlush` bug in full detail
- `docs/features/US-012/api-spec.json` — live-generated OpenAPI 3 spec (`GET /v3/api-docs`, `dev` profile)
- `docs/features/US-012/deployment.md`, `rollback.md`, `monitoring.md`, `runbook.md` — operational documentation
