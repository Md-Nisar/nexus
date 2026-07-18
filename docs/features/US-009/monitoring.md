# US-009 — Monitoring Guide

_Phase 9 (`/docs`) deliverable._

## No new runtime observability surface

This story ships **no runtime code that executes** — no controllers, use-cases, or application services. There is nothing to add a dashboard, metric, or alert for today; a fabricated monitoring setup would be theater. The first real observability surface for RBAC arrives with:

- **US-010** — JWT/permission-resolution latency, cache hit/miss (once the permission cache exists), and the forward-tracked runtime DB-privilege self-check (T-E3 in `03b-threat-model.md`) — an actuator health indicator warning if the live DB connection can `DELETE` `user_roles` or holds `ALL PRIVILEGES`/is `root`, mirroring `AuthEventDbPrivilegeHealthIndicator`.
- **US-011** — permission-check latency (the story's own AC targets <5ms p95 on the cache-hit path).
- **US-012** — `ROLE_ASSIGNED`/`ROLE_REVOKED` audit-event volume via the existing `auth_events` pipeline.

## What to check once, not continuously

- **The AC9 grant smoke check** — `docker compose --profile full up`, confirm `SHOW GRANTS FOR nexus_app` matches the expected 9-line shape (§6 of `03-design.md`), and confirm the negative proof (`UPDATE user_roles SET assigned_by=?` → `ERROR 1143`). This was executed once this session and passed; re-run before any environment's first deploy of `V5`, since it's the only thing that can catch a grant-provisioning mistake — Testcontainers CI structurally cannot (it runs as a different DB user).
- **JaCoCo coverage gate** — `rbac.domain` is now included in the 90% line-coverage package rule and passes at 100% (verified in `08-test-audit.md`). No ongoing monitoring needed; it's enforced automatically on every `mvnw verify`.

## Log queries

Not applicable — no new log lines are emitted by this story's code (there is no code that runs). If a migration failure occurs at deploy time, the relevant signal is Flyway's own migration log (`Successfully applied N migrations to schema` / a `FlywayException` on failure), not an application log line.

## Baseline metrics

None to establish — there is no traffic-facing behavior in this story to baseline. Do not build a dashboard for this story in isolation; fold RBAC monitoring into the dashboard built for US-010/011 once real query volume exists.
