# US-009 — Technical Documentation

_Output of `/docs` (Phase 9). Cross-links: [`03-design.md`](03-design.md) (full design), [`03b-threat-model.md`](03b-threat-model.md) (STRIDE), [`04-tasks.md`](04-tasks.md) (task breakdown), [`06-code-review.md`](06-code-review.md), [`07-security-review.md`](07-security-review.md), [`08-test-audit.md`](08-test-audit.md)._

## Overview

US-009 establishes the RBAC data model for EPIC-002 (RBAC Foundation): four new tables (`permissions`, `roles`, `role_permissions`, `user_roles`), seeded with a fixed, code-defined permission set and two system roles (`TENANT_ADMIN`, `MEMBER`), plus the JPA entity/repository layer for a new `com.example.nexus.rbac` bounded context. It is schema-only — no runtime API, no enforcement, no assignment logic. Its job is to be the stable foundation US-010 (JWT population), US-011 (permission enforcement), US-012 (assignment API), and US-015 (role management API) build on, and the hard gate for Epic 3 (Tenant Management) kickoff.

## Design rationale (see `03-design.md` for full detail)

- **`resource:action` permission naming** (ADR-0013 D1) — flat, no hierarchy/wildcards, keeps enforcement an O(1) set-membership check.
- **`active_key` STORED generated column** (ADR-0013 D2) — MySQL 8.4 has no Postgres-style partial/filtered unique index. A generated column (`NULL` when revoked, a deterministic `(user_id, role_id)` value when active) plus a plain `UNIQUE INDEX` gives the same guarantee: MySQL never treats two `NULL`s as duplicates, so any number of revoked rows coexist while two active assignments for the same pair collide.
- **Bootstrap tenant sourcing** (ADR-0014 D5, amended ADR-0015 D8) — the seeded system roles need a `tenant_id` at migration time, but a static Flyway migration can't read a Spring property. Resolution: hardcode the same literal the non-prod environments already carry (`application-dev.yml`, `application-smoke.yml`, `TestcontainersConfiguration`) — **not** a base-`application.yml` fallback, which would have converted prod's fail-fast-on-unset into a silent default into the tenant holding `TENANT_ADMIN`.
- **Least-privilege `nexus_app` grants** (ADR-0014 D6, amended ADR-0015 D7) — per-table grants sized to actual need: `permissions` read-only, `roles`/`role_permissions` no blanket UPDATE, `user_roles` UPDATE **column-scoped to `revoked_at` only** — a raw connection cannot rewrite assignment history even with the app's own credential.
- **`@EmbeddedId`, not `@IdClass`, for `RolePermission`'s composite key** — a real implementation-time finding, not a stylistic choice: Hibernate 7.4.1.Final rejects an `AttributeConverter` (even an explicit one) on `@IdClass` composite-key attributes. `@EmbeddedId` doesn't have this restriction. See `RolePermissionId.java`'s Javadoc for the full account, including a reverted first attempt that introduced a real ArchUnit layering violation.

## Key decisions and where they're recorded

| Decision | ADR / doc |
|---|---|
| RBAC model, permission naming, `active_key` technique | ADR-0013 |
| Bootstrap tenant sourcing, `nexus_app` grant shape | ADR-0014 |
| Column-scoped `user_roles` grant, no base-config tenant fallback (Gate-2 threat-model hardening) | ADR-0015 |
| `@EmbeddedId` over `@IdClass` (implementation-time Hibernate constraint) | `RolePermissionId.java` Javadoc; no ADR — a design-detail correction, not an architectural decision |

## Deviations from the original design, and why

1. **`V3` → `V5` migration numbering** — corrected before implementation; the repo was already at `V4` from EPIC-001.
2. **`@IdClass` → `@EmbeddedId`** for `RolePermission`/`RolePermissionId` — Hibernate restriction, documented above.
3. **Story points 5 → 8** for US-009 — Gate-1 requirements analysis found JPA entities/repositories and `nexus_app` grants were genuinely new scope, not just clarifications.
4. **Epic total 34 → 33 → 36** across the review cycle — see `EPIC-002.md`'s Open Decisions and ARC effort-estimate sections for the full accounting.

## Known, accepted residuals (not fixed, documented and tracked)

- **T-T2**: the `chk_user_roles_revoked_not_before_assigned` CHECK constraint only rejects backdating `revoked_at` before `assigned_at`; it does **not** prevent a future-dated `revoked_at` (MySQL CHECK constraints can't reference `NOW()`). Both `/review` and `/security-review` flagged this — the threat model's "RESOLVED" label overstates what's technically enforced. No exploitable path exists today (no write code); US-012 must add an application-layer `revoked_at <= now()` guard before any revoke write ships.
- **DB-superuser residual**: a `root`/DBA principal can still `DROP TRIGGER` and hard-delete `user_roles` rows. Out of scope for an in-app control (ADR-0012's precedent for `auth_events`).
- **Grant CI-blind-spot**: Testcontainers ITs run as the container's default `test` user, not `nexus_app`, so a missing/wrong grant is only caught by the AC9 manual docker-compose smoke check (executed once this session, see `04-tasks.md` T-09-09), not by CI.

## Pre-existing issues found during implementation (unrelated to this story, not fixed here)

- `com.example.nexus.identity.infrastructure.seed.DevDataInitializer` has 0% test coverage, failing the JaCoCo infrastructure gate on a full unfiltered `mvnw verify`.
- `docker-compose.yml`'s `mysql` service mounts the entire `nexus-database/mysql/init/` directory into `docker-entrypoint-initdb.d`, causing MySQL's own first-boot init to prematurely run `02-grants-post-schema.sql` before Flyway has created any tables, crashing the container on a genuinely fresh volume. Worked around locally via a compose override for this story's smoke test; not fixed in the shared file (out of scope, flagged for the team).

## API documentation

**Not applicable.** This story ships zero controllers, DTOs, or endpoints — no OpenAPI spec to generate. The RBAC API surface arrives with US-012 (assignment) and US-015 (role management).
