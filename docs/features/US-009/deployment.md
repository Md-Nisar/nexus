# US-009 — Deployment Guide

_Phase 9 (`/docs`) deliverable._

## What ships in this deployment

- Flyway migration `V5__rbac_schema.sql` — 4 new tables, seed data (7 permissions, 2 system roles, 8 role-permission grants).
- 5 new JPA entities + 4 repositories in `com.example.nexus.rbac` (dormant — no application code reads/writes them yet).
- Least-privilege `nexus_app` DB grants for the 4 new tables, added to all 3 provisioning artifacts.

## Environment variables / config changes

**None.** `application.yml` is deliberately untouched (ADR-0015 D8) — the originally-planned bootstrap-tenant fallback was rejected because it would have converted prod's fail-fast-on-unset `NEXUS_IDENTITY_DEFAULT_TENANT_ID` into a silent default into the tenant holding `TENANT_ADMIN`. If `NEXUS_IDENTITY_DEFAULT_TENANT_ID` is not already set in a target environment, the app will (correctly) fail to boot — this is not a regression introduced by this story, and it must be set to `00000000-0000-7000-8000-000000000001` (the literal the migration seeds against) for the seeded `TENANT_ADMIN`/`MEMBER` roles to be reachable.

## Migration order

1. `V1`–`V4` (EPIC-001, already applied in any existing environment) must be present.
2. `V5__rbac_schema.sql` applies next — additive only (4 new tables, no existing table touched). No expand/contract sequencing needed.
3. **Hard coupling:** the migration and the 5 new JPA entities/4 repositories must deploy together in the same release. `ddl-auto=validate` means the app fails to boot if the entities and schema disagree — this is a boot-time safety net, not a manual step, but it means this story cannot be deployed as "just the SQL" ahead of the code, or vice versa.

## Grant provisioning (the one manual-adjacent step)

The 5 `nexus_app` GRANT statements (see `03-design.md` §6) must be present in **all 3** provisioning artifacts before/at deploy time:
- `nexus-database/mysql/init/02-grants-post-schema.sql` (dev, applied via Flyway's `afterMigrate` callback in the `flyway-migrate` compose service)
- `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java` (test-only, no prod impact)
- `docs/runbooks/nexus-app-provisioning.md` (the prod runbook — ops must apply the equivalent `GRANT` statements against the real prod DB before or immediately after this migration lands there)

**This is already done in this story's diff** — all 3 artifacts carry the identical grant block. For a genuinely fresh environment (prod, or any environment provisioned from scratch), ops must still run the equivalent grants manually if the environment isn't using the `flyway-migrate` afterMigrate mechanism.

**Verification gate (AC9):** a `docker compose --profile full up` run, with `nexus_app` exercising `SELECT`/`INSERT`/`UPDATE(revoked_at)` on the 4 new tables and confirming `SHOW GRANTS` matches the expected 9-line shape, was executed once this session (see `04-tasks.md` T-09-09) and passed. Re-run this smoke check before any environment's first deploy of this migration, since Testcontainers CI cannot verify `nexus_app`'s actual grants (it runs as a different DB user).

## Feature flag

**None.** This is schema-only with no runtime behavior to gate (`03-design.md` §8.2) — a flag here would be dead config.

## Rollout sequencing recommendation

No special sequencing needed beyond the standard migration-then-app-restart flow — this story introduces no traffic-facing behavior, so there's no canary/gradual-rollout concern. The migration + entities are effectively inert (no application code queries them) until US-010/012/015 ship.
