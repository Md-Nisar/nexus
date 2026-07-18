# US-009 — Operational Runbook

_Phase 9 (`/docs`) deliverable. Scenarios for the schema/grant surface this story introduces; no runtime API exists yet, so no user-facing incident scenarios apply — that arrives with US-010/011/012._

## Scenario: `V5` migration fails to apply on deploy

**Symptoms:** Flyway reports a failed migration; app fails to boot (or the migration container/init step in `docker-compose.yml`'s `flyway-migrate` service exits non-zero).

**Diagnostic steps:**
1. Confirm `V1`–`V4` are already applied (`SELECT * FROM flyway_schema_history ORDER BY installed_rank`) — `V5` requires `users` (from `V2`) to exist for its FK constraints.
2. Confirm the target MySQL version is 8.4+ — the `active_key` `STORED` generated column and the `CHECK` constraint both require MySQL 8.0.16+/8.4 semantics; an older MySQL will reject the `CREATE TABLE` outright.
3. Check for a naming collision — if a `V5` migration already exists on the target environment from an unrelated change, this migration must be renumbered (`V6`) before retrying; never edit an already-applied migration file (ADR-0003).

## Scenario: backend fails to boot with a Hibernate schema-validation error after this deploy

**Symptoms:** `SchemaManagementException` / `ddl-auto=validate` failure referencing a `com.example.nexus.rbac.*` entity.

**Diagnostic steps:**
1. This should not happen — the entities and `V5` were deployed and tested together, and `RbacRepositoryRoundTripIT` proves the mapping boots under `validate` in CI. If it occurs anyway, the most likely cause is a partial/inconsistent deploy (code deployed without the migration, or vice versa) — confirm both landed in the same release per `deployment.md`'s hard-coupling note.
2. If the error specifically names `UserRole.activeKey`, check the column is genuinely `BINARY(32)` in the deployed schema (a `GENERATED ALWAYS AS (...) STORED` column) — a manual/out-of-band schema change could have altered its type.

## Scenario: `nexus_app` gets `Access denied` on an RBAC table

**Symptoms:** `SQLException: Access denied for user 'nexus_app'@'...' to table 'permissions'` (or `roles`/`role_permissions`/`user_roles`), surfacing whenever the first RBAC-consuming code (US-010+) tries to query.

**Diagnostic steps:**
1. Run `SHOW GRANTS FOR 'nexus_app'@'%';` against the target environment. Expected shape (9 lines total, including the 4 pre-existing identity grants) is documented in `docs/runbooks/nexus-app-provisioning.md`.
2. If the RBAC grants are missing entirely: the environment's grant-provisioning step wasn't run. For dev/docker-compose, confirm `flyway-migrate`'s `afterMigrate.sql` callback (mounted from `02-grants-post-schema.sql`) actually executed — check its container logs for `Executing SQL callback: afterMigrate`. For prod, ops must apply the 5 `GRANT` statements manually per the runbook.
3. This is the **one gap Testcontainers CI cannot catch** (it runs as a different DB user) — if this happens in a real environment, it means the AC9 smoke check (see `monitoring.md`) either wasn't run before that deploy or was run against a different environment than the one that failed.

## Scenario: `TENANT_ADMIN` role appears to not exist / Epic 3's admin gate is blocked

**Symptoms:** A query for `roles WHERE name = 'TENANT_ADMIN'` scoped to an environment's actual default tenant returns nothing, even though the migration seeded it.

**Diagnostic steps:**
1. `TENANT_ADMIN`/`MEMBER` are seeded against the literal `00000000-0000-7000-8000-000000000001` (the bootstrap tenant sentinel), **not** whatever tenant a given user happens to belong to. Confirm the environment's `NEXUS_IDENTITY_DEFAULT_TENANT_ID` is set to this exact same value — if it's set to something else (or unset, causing a boot failure — see `deployment.md`), the seeded roles exist but are scoped to a tenant nothing in that environment resolves to.
2. This is a bootstrap-only mechanism (ADR-0014 D5) — it is not expected to need per-tenant seeding until Epic 3 ships real tenant provisioning, at which point that flow (not this migration) becomes responsible for seeding `TENANT_ADMIN` into each newly created tenant.
