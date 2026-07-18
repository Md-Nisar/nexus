# ADR 0013 — RBAC Data Model, Enforcement Contract, and Permission Naming Convention

**Status:** Accepted
**Date:** 2026-07-16
**Feature:** EPIC-002 (RBAC Foundation) — US-009, US-011, US-015
**Note:** EPIC-002's discovery document originally called this "ADR-003." That number is already used by `0003-flyway-schema-migrations.md`; this ADR is renumbered to 0013, the next free slot.

---

## Context

EPIC-002 introduces the platform's Roles + Permissions model: four new tables (`permissions`, `roles`, `role_permissions`, `user_roles`), a `@RequiresPermission` enforcement contract, and a role/role-permission management API. Its discovery document flagged one ADR as required before Sprint 3 starts, to ratify the permission naming convention.

A feasibility review of the epic against the current codebase — `nexus-backend`'s `identity` bounded context, a MySQL 8.4 Testcontainers target, the jjwt-based frozen `JwtClaims` contract, and the Angular frontend's `/users/me`-based auth flow (no client-side JWT decoding) — surfaced three further decisions that also need to be locked down before implementation starts, because the epic's original draft either specified something invalid for this stack or left a design choice open:

1. How permissions are named (BA's proposed convention).
2. How `user_roles` enforces "at most one active assignment per `(user_id, role_id)`" on MySQL 8.4 — the epic originally specified a Postgres-style partial unique index (`CREATE UNIQUE INDEX ... WHERE revoked_at IS NULL`), which is invalid syntax on this stack (MySQL has no partial/filtered index support; functional indexes are a different feature).
3. How a method-security permission denial (`403 + RBAC_001`) is distinguished from the generic `AccessDeniedException → 403 + ACCESS_DENIED` handler that already exists in `GlobalExceptionHandler` from EPIC-001's filter-chain security config, so the two responses don't collide once `@EnableMethodSecurity` is turned on.
4. How a role's permission set changing (US-015) invalidates the permission cache for every user already holding that role — US-012's cache invalidation only ever targets one `{tenant_id}:{user_id}` key per assignment/revocation, which doesn't cover this case.

This ADR bundles all four decisions because they gate the same epic and were resolved together in the same review, immediately ahead of Sprint 3.

---

## Decision

### D1 — Permission naming convention

Permissions are named `resource:action` — lowercase, colon-separated, code-defined only (not runtime-configurable in Epic 2). Example set seeded by US-009: `tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`.

- `resource` names a noun the platform manages (`tenant`, `user`, `role`, `audit`), not a controller or table name — so the convention survives refactors of the underlying implementation.
- `action` is one of a small closed set (`read`, `write` for Epic 2; more granular actions like `delete` or `approve` may be added by future epics without changing the convention itself).
- No hierarchy or wildcard support (e.g. no `tenant:*`) — each permission a role needs must be listed explicitly in `role_permissions`. This keeps evaluation a flat set-membership check against the JWT `permissions[]` claim, with no traversal logic in the hot path.

### D2 — Active-assignment uniqueness on `user_roles`

Replace the invalid partial unique index with a `STORED` generated column plus a plain unique index:

```sql
ALTER TABLE user_roles ADD COLUMN active_key BINARY(32)
  GENERATED ALWAYS AS (
    CASE WHEN revoked_at IS NULL THEN CONCAT(user_id, role_id) ELSE NULL END
  ) STORED;

CREATE UNIQUE INDEX uq_user_role_active ON user_roles (active_key);
```

MySQL never treats two `NULL`s as duplicates in a unique index. A revoked row's `active_key` is `NULL`, so any number of revoked rows for the same `(user_id, role_id)` coexist without violating the index. An active row's `active_key` is a deterministic, non-null function of `(user_id, role_id)`, so a second active assignment for the same pair collides on insert and is rejected by the database — not by application-level check-then-insert logic, which would be racy under concurrent requests.

### D3 — Distinguishing RBAC permission denials from generic access-denied responses

Introduce `InsufficientPermissionException extends AccessDeniedException`, carrying a `requiredPermission` field, thrown by `TenantAwarePermissionEvaluator` (US-011) instead of letting Spring Security's default `AccessDeniedException` propagate from a failed `@PreAuthorize`. Register a handler for this subtype in `GlobalExceptionHandler` that Spring resolves in preference to the existing generic `AccessDeniedException` handler (Spring's `@ExceptionHandler` resolution picks the most specific matching type):

```java
@ExceptionHandler(InsufficientPermissionException.class)
ProblemDetail handleInsufficientPermission(InsufficientPermissionException ex) {
    // 403 + code=RBAC_001 + required_permission=ex.getRequiredPermission()
}
```

The pre-existing generic `AccessDeniedException` handler (EPIC-001, filter-chain-level denials) remains unchanged as the fallback for non-RBAC authorization failures. `RBAC_002` (last-active-admin lockout, US-012) and `RBAC_003` (system-role-immutable, US-015) are unaffected by this decision — both already return `409` via their own dedicated exceptions, a different status code from the `403` family this decision governs, so there is no handler-resolution ambiguity for them.

### D4 — Cache invalidation when a role's permission set changes

Default to **accepting the existing cache lag** (15-minute Redis TTL / 7-day token-refresh window) when a role's `role_permissions` are edited via US-015, identically to how US-012 already documents the same lag for a single user's revocation. Do **not** implement bulk cache invalidation across all holders of an edited role in the initial implementation.

Rationale: role-permission edits are expected to be infrequent relative to per-user assignment/revocation (which already has narrower, targeted invalidation), and the epic has already accepted the equivalent lag elsewhere as "acceptable for MVP; re-login is the immediate-effect path." Introducing a bulk-invalidation query (`SELECT all active user_roles WHERE role_id = ? → bulk Redis DELETE`) on every role-permission write adds complexity and a new failure mode (partial invalidation on Redis error) for a scenario with no immediate business driver. If a future epic needs tighter propagation (e.g., revoking a dangerous permission platform-wide within seconds), revisit this decision then rather than building the mechanism speculatively now.

---

## Alternatives Considered

| Decision | Alternative | Rejected because |
|---|---|---|
| D1 | Hierarchical/wildcard permissions (`tenant:*`) | Epic 2 explicitly excludes permission inheritance and hierarchy; adds evaluator complexity for a capability nothing currently needs |
| D1 | Namespaced dot notation (`tenant.read`) | No functional difference from colon form; colon already matches the BA's proposal and JWT claim examples throughout the epic |
| D2 | Application-level check-then-insert (`SELECT COUNT(*) ... WHERE revoked_at IS NULL` before insert) | Race condition under concurrent assignment requests for the same user+role; the generated-column approach pushes the guarantee into the database itself |
| D2 | A separate `active_role_assignments` table (one row per active assignment, deleted on revoke) | Duplicates data across two tables and reintroduces a hard-delete path, which conflicts with the epic's audit requirement that `user_roles` never hard-deletes |
| D3 | Let all `@PreAuthorize` denials fall through to the existing generic `AccessDeniedException` handler | Returns `code=ACCESS_DENIED` with no `required_permission` field, breaking the epic's explicit `403 + RBAC_001 + { required_permission }` contract (US-011 AC3) |
| D3 | A `ThreadLocal`/request-attribute flag set by the evaluator and read in the generic handler | Implicit, easy to leave unset on a code path, and harder to test than a distinct exception type resolved by Spring's own dispatch |
| D4 | Bulk-invalidate all affected users' cache keys on every `role_permissions` write | Correct but adds a DB query + N Redis deletes on every role-permission edit, and a new partial-failure mode, for a scenario the epic has no current SLA requiring |
| D4 | Reduce the cache TTL platform-wide to shrink the lag for this case | Penalises the performance of every permission check (more cache misses) to address a narrow edge case; the JWT is already documented as the enforcement authority, with the cache as a pure optimisation |

---

## Consequences

**Benefits:**
- D1 keeps permission evaluation a flat, O(1) set-membership check against the JWT claim — no hierarchy traversal in the request hot path.
- D2 gives the "one active assignment" invariant database-level enforcement with no race window, using a technique already provable in MySQL 8.4 (the confirmed Testcontainers target), unlike the original spec which would fail to apply at all.
- D3 keeps the `RBAC_001` contract exact (`required_permission` present, correct code) without touching or duplicating the existing EPIC-001 `AccessDeniedException` handling.
- D4 avoids new infrastructure (bulk cache-invalidation logic, its own failure handling) for a case with no demonstrated urgency, keeping US-015 scoped to CRUD + immutability rather than a cache-consistency subsystem.

**Trade-offs:**
- D2's generated column is MySQL-specific syntax; if the platform ever needs to support a second database engine, this technique does not port as-is and would need a database-specific migration.
- D3 requires every future RBAC-adjacent exception that needs a distinct `code` to follow the same "dedicated exception subtype + more-specific handler" pattern — a convention, not something the compiler enforces.
- D4 means a Tenant Admin who edits a role's permissions will see other users' effective access lag by up to 15 minutes (cache) or 7 days (token refresh) unless those users re-login. This must be stated in the security runbook and in any Epic 3 UI copy that surfaces role editing, exactly as US-012's revocation lag already is.

**Follow-on rules for future work:**
- Any new bounded context introducing its own soft-deletable "at most one active row per key" invariant on MySQL should default to the D2 generated-column pattern rather than reintroducing Postgres-style partial indexes.
- Any new `@PreAuthorize`/method-security denial that needs a response contract more specific than generic `403 + ACCESS_DENIED` should follow D3: a dedicated `AccessDeniedException` subtype + a more-specific `@ExceptionHandler`, not a shared flag or a change to the existing generic handler.
- If a future epic needs sub-15-minute propagation of a permission change to all affected users (D4), that is a new decision to make at that time — do not retrofit bulk invalidation into US-015 without a concrete driver.
