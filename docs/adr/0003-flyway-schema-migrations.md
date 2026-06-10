# ADR 0003 — Flyway Owns the Database Schema

**Status:** Accepted
**Date:** 2026-06-10
**Author:** Engineering Team

## Context

The backend used `spring.jpa.hibernate.ddl-auto=update`: Hibernate diffed entities against the database at startup and altered the schema in place. That works for a prototype, but at enterprise scale it has unacceptable properties: no reviewable record of schema changes, no rollback path, no way to coordinate non-additive changes (renames, drops) across deploys, divergent schemas between environments, and silent data-destroying surprises when Hibernate's diff does something unexpected.

## Decision

**Flyway is the single owner of the schema.** Hibernate is demoted to a verifier.

- Versioned migrations live in `nexus-backend/src/main/resources/db/migration` as `V<N>__<snake_case_description>.sql`, starting from `V1__baseline.sql`.
- Migrations are **append-only**: an applied migration is never edited — corrections are new migrations.
- `spring.jpa.hibernate.ddl-auto=validate` in every profile that runs Flyway: startup fails loudly if entities and schema disagree, which catches forgotten migrations at the first boot rather than at the first query.
- Non-additive changes (rename, drop, type change) require an expand→contract two-step deploy plan, reviewed in the design phase.
- Integration tests (`*IT`) run the real migrations against Testcontainers MySQL, so every migration is executed in CI before it touches a shared environment.
- The H2 `test` profile disables Flyway (migrations are MySQL-flavoured SQL); it exists only for the no-Docker context smoke test.

## Alternatives considered

**Keep `ddl-auto=update`:**
- Zero migration-writing effort.
- Ruled out for the reasons in Context — primarily the absence of a reviewable, ordered, reproducible history.

**Liquibase:**
- Equivalent capability, supports XML/YAML changelogs and broader rollback tooling.
- Flyway's plain-SQL model is simpler, matches the team's SQL-first preference, and is the de-facto Spring Boot default. No requirement currently favours Liquibase.

**Manual DBA-applied scripts:**
- Maximum control, but unautomatable, unauditable in CI, and incompatible with ephemeral environments and Testcontainers.

## Consequences

Positive:
- Schema history is code: reviewed in PRs, ordered, reproducible in every environment from scratch.
- CI executes migrations on real MySQL before merge.
- `validate` turns "entity drifted from schema" into an immediate startup failure.

Negative:
- Every schema change now requires writing SQL — slightly slower iteration than `update` during early development.
- Migration discipline (append-only, expand/contract) must be learned and enforced in review.

Follow-on:
- Define the audit-column convention (`created_at`, `updated_at`) in the first real migration.
- Consider `flyway-database-mysql` version pinning review whenever the Boot BOM bumps Flyway majors.
