# US-012 — Deployment Guide: Enable role assignment and revocation API

**Feature:** Role assignment / revocation API (`POST`/`GET`/`DELETE /api/v1/users/{userId}/roles[/{roleId}]`)

---

## 1. Summary

This is an **additive-only** deployment. No new environment variables, no new Flyway migration, no new infrastructure dependency, zero frontend changes. The only deploy-relevant artifact is a feature flag, defaulted `false`, plus two scoped SpotBugs exclusions that require no operational action.

## 2. Database

**No new migration.** `02-impact.md` §2.1 confirmed `V5__rbac_schema.sql` already carries every column, index, constraint, and trigger this story needs on `user_roles` (`id`, `user_id`, `role_id`, `tenant_id`, `assigned_by`, `assigned_at`, `revoked_at`, `active_key`, `uq_user_role_active`, the `revoked_at >= assigned_at` CHECK, and the `BEFORE DELETE` trigger). `auth_events.event_type` is `VARCHAR(64)`, not a DB `ENUM`, so the two new `AuthEventType` constants (`ROLE_ASSIGNED`, `ROLE_REVOKED`) need no schema change either.

**`nexus_app` DB grants are unchanged.** Every operation this story performs (`SELECT` on `roles`/`permissions`/`user_roles`/`users`, `INSERT` on `user_roles`, `UPDATE (revoked_at)` on `user_roles` — column-scoped, `INSERT`/`SELECT` on `auth_events`) is already covered by the existing grant set (`nexus-database/mysql/init/02-grants-post-schema.sql`, ADR 0014 D6 / ADR 0015 D7). No `GRANT` statement needs to run as part of this deploy.

**Deployment order:** none blocking. This story adds no other service dependency and changes no existing contract — it can deploy independently of any other in-flight change.

## 3. Feature flag

| Property | Default (`application.yml`, incl. prod) | `dev` | `test` |
|---|---|---|---|
| `feature.nexus-us012-rbac-role-assignment.enabled` | `false` | `true` | `true` |

This is a **config property**, not an environment variable — no new env var is introduced by this story. It gates `UserRoleController` via `@ConditionalOnProperty(havingValue = "true")`: when `false`, Spring omits the controller bean entirely and all three endpoints return `404` (fail-closed, not a 403 that could be confused with an authorization check).

**Why a flag at all, given the story's own text says "Feature flag required: No"?** `03-design.md` §10.1 overrides that: this endpoint is the platform's only control against a Critical self-escalation threat (T-E1), and it is also the first genuinely privileged surface on the platform. Every other controller in the codebase is already flag-gated; a config flip is the fastest possible kill switch if a bypass is ever found post-deploy, and there is no reason to make this one an exception.

**Two traps documented for whoever flips this flag in a new environment** (`04-tasks.md` T-013, still applicable operationally):
1. The flag must live in profile YAML, not be set via a `DynamicPropertyRegistrar`-style mechanism — `@ConditionalOnProperty` on a `@Component` bean evaluates during component scan, before such contributions are visible (a known Spring Boot 4 property-precedence issue already documented for this repo).
2. If the flag is `false` in an environment where the feature is expected to be live, the fastest diagnostic is: does `/actuator/health` and the dashboard's "RBAC / Role Assignment" row show zero traffic on the three URIs? If so, check the flag before assuming an application bug.

**Rollout gate before flipping to `true` in production** (carried from `07-security-review.md` M-1/M-2, tracked as a staging→production exit criterion, not a merge blocker):
- Confirm `management.endpoint.health.roles` restricts `/actuator/health`'s detail payload (the two new health indicators, `RbacDbPrivilegeHealthIndicator`/`RbacZeroActiveAdminsHealthIndicator`, would otherwise expose cross-tenant `tenantIds` and the DB account name to any authenticated user of any tenant, since `show-details: when-authorized` treats any authenticated principal as authorized when `roles` is unset).
- Confirm `RbacZeroActiveAdminsHealthIndicator`'s underlying query has a cache TTL (`management.endpoint.health.cache.time-to-live`) or is moved to a `@Scheduled` gauge — as shipped it re-runs a cross-tenant scan on every unauthenticated `/actuator/health` hit.

## 4. SpotBugs exclusions — a deploy-time non-event

Two new scoped entries were added to `nexus-backend/spotbugs-exclude.xml` for this story:

- `RoleAssignmentService` — `EI_EXPOSE_REP2` on the constructor-injected `PermissionCachePort` field, mirroring the identical, already-accepted exclusion for `RoleResolutionService` (same port, same non-value-object/non-mutating-singleton rationale — constructor injection is this project's only DI style, per CLAUDE.md).
- `RbacAuthEventAdapter` — `EI_EXPOSE_REP2` on its constructor-injected `MeterRegistry` and `ObjectMapper` fields, mirroring the existing exclusions for `GlobalExceptionHandler`/`ExecutionObserver` (`MeterRegistry`) and the general "injected Spring singleton, not a value object, no sensible defensive copy" rationale already used throughout this file.

Both are pre-existing exclusion patterns applied to new classes, not new categories of suppression. They require **no operational action at deploy time** — they only affect the static-analysis gate at build time, which already passed (`SpotBugs: 0 bugs, 0 errors` per the Phase 8 test-validate run).

## 5. Observability wiring that ships with this deploy

No action required, but worth confirming the dashboard/alerting config picks these up post-deploy (see `monitoring.md` for the full reference):
- New counters: `nexus.domain.conflict{code}`, `nexus.rbac.audit_write_failed{operation}`.
- New `permission_denied` reason values on the existing counter: `CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`.
- Two new `AuthEventType.PRIORITY` members (`ROLE_ASSIGNED`, `ROLE_REVOKED`) — role-change audit events now route through the priority retry-buffer lane, not `standard`.
- Two new health indicators (`rbacDbPrivilege` already existed pre-US-012; `rbacZeroActiveAdmins` is new) on the aggregate `/actuator/health`. Neither is added to a liveness/readiness `management.endpoint.health.group.*.include` list — a DB-grant drift or a lockout condition should page/ticket via the alerts in `monitoring.md`, not fail a container health probe.

## 6. Frontend

**None.** `02-impact.md` §1.6 confirmed zero frontend impact (no client anywhere in `nexus-frontend/src` calls `/users/{userId}/roles`; `MeResponse`/`/users/me` is untouched). No build, no deploy step, no lockfile change on the frontend side for this story.

## 7. Rollback

See `rollback.md` for the full plan. Summary: the feature flag is the fastest rollback lever (flip to `false`, no redeploy of code needed if the flag is externalized via config server / env override); a full code revert is the secondary lever; there is no migration to reverse and no destructive data cleanup required.
