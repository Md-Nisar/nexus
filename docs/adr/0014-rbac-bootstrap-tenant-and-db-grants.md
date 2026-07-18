# ADR 0014 — RBAC Bootstrap Tenant Sourcing and Least-Privilege DB Grants

**Status:** Accepted
**Date:** 2026-07-16
**Feature:** EPIC-002 (RBAC Foundation) — US-009

---

## Context

Gate 1 requirements analysis for US-009 (see `docs/features/US-009/01-requirements.md`) surfaced two decisions that ADR-0013 didn't cover, both found by direct verification against the running config and the existing least-privilege DB-grant artifacts, not by reading the story text alone:

1. `V5__rbac_schema.sql` must seed `TENANT_ADMIN`/`MEMBER` rows with a `roles.tenant_id` value, but `roles.tenant_id` is `NOT NULL` and Flyway SQL cannot read a Spring property at migration time. The only existing "default tenant" concept, `nexus.identity.default-tenant-id`, is a per-environment property (`${NEXUS_IDENTITY_DEFAULT_TENANT_ID}`) with **no fallback** in `application.yml` — it only has a concrete value in `application-dev.yml`. Nothing today guarantees a real deployment's configured default tenant matches whatever literal the migration hardcodes.
2. `nexus_app` (the least-privilege runtime DB user introduced in ADR-0012 for `auth_events`) has grants hardcoded, table-by-table, in three places (`nexus-database/mysql/init/02-grants-post-schema.sql`, the Testcontainers grants callback, the prod runbook). All three currently list only `auth_events`, `users`, `refresh_tokens`, `auth_tokens` — verified directly; none reference the four new RBAC tables. Testcontainers CI cannot catch this gap, because the general application connection there deliberately runs as the container's default `test` user, not `nexus_app`.

Both decisions gate US-009 specifically (not the whole epic), so they're recorded here rather than as an edit to the already-Accepted ADR-0013 (per this repo's append-only ADR convention).

---

## Decision

### D5 — Bootstrap default-tenant sourcing for seeded system roles

Give `nexus.identity.default-tenant-id` an actual fallback value in `application.yml`, equal to the same literal `V5__rbac_schema.sql` seeds `TENANT_ADMIN`/`MEMBER` against:

```yaml
# application.yml
nexus:
  identity:
    default-tenant-id: ${NEXUS_IDENTITY_DEFAULT_TENANT_ID:00000000-0000-7000-8000-000000000001}
```

This makes "the migration's seed literal" and "the runtime default tenant" the same value **by construction**, in every environment that doesn't deliberately override `NEXUS_IDENTITY_DEFAULT_TENANT_ID` — rather than depending on each environment happening to configure the two consistently. The sentinel value itself (`00000000-0000-7000-8000-000000000001`) is the one already used by `application-dev.yml` and `TestcontainersConfiguration`, so no environment currently in use needs to change.

This is understood as a **bootstrap-only mechanism**. EPIC-002's own ARC section already states `TENANT_ADMIN` is "seeded on tenant creation" as Epic 3's ongoing mechanism for every tenant provisioned after Epic 3 ships; US-009's migration only needs to cover the one default/bootstrap tenant that exists before real tenant self-service provisioning exists. If an environment ever legitimately needs a *different* default tenant, that is a deliberate operational action which must be paired with directly inserting the corresponding `roles` rows for that tenant — not something this migration needs to anticipate.

### D6 — Least-privilege `nexus_app` grants for the 4 new RBAC tables

Extend all three existing grant-provisioning artifacts with per-table grants sized to each table's actual read/write pattern across US-009–US-015, mirroring ADR-0012's philosophy of granting only what the application's own code path needs and using triggers (not grants) for hard-delete prevention where one exists:

```sql
GRANT SELECT                              ON nexus.permissions      TO 'nexus_app'@'%';
GRANT SELECT, INSERT                       ON nexus.roles            TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE               ON nexus.role_permissions TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE               ON nexus.user_roles       TO 'nexus_app'@'%';
```

Rationale per table:
- **`permissions`**: read-only. Permissions are code-/migration-seeded only (ADR-0013 D1); no story ever writes to this table at runtime.
- **`roles`**: read + create only (US-015 `POST /roles`). No story renames/edits an existing role's own columns, and role deletion is explicitly out of scope (US-015 Out of Scope) — no `UPDATE`/`DELETE` grant.
- **`role_permissions`**: read (permission resolution joins) + create (US-015 attach) + delete (US-015 detach, `DELETE /roles/{roleId}/permissions/{permissionId}`). No `UPDATE` — no story ever modifies an existing row's columns, only inserts/removes whole rows.
- **`user_roles`**: read + create (US-012 assign) + update (US-012 revoke, which sets `revoked_at` via `UPDATE`). **No `DELETE` grant at all** — the `BEFORE DELETE` trigger (US-009 AC4) already blocks hard deletes, and omitting the grant entirely is defense-in-depth on top of that, matching the double-layered pattern ADR-0012 already established for `auth_events` (grant omits `UPDATE`/`DELETE`; trigger blocks both).

These statements are added to all three existing provisioning artifacts, applied after `V5` runs (matching ADR-0012's existing constraint that `GRANT ... ON db.table` fails with `ERROR 1146` if the table doesn't exist yet). This is out-of-band grant DDL per ADR-0012 §2 — it does not go in the Flyway migration itself.

**Known residual gap, explicitly not fixed by this ADR:** Testcontainers integration tests do not exercise queries as the `nexus_app` user for the general application connection (verified — it deliberately stays on the container's default `test` user). This means a green US-009 IT suite still cannot detect a grants mistake; it only surfaces in docker-compose `full` profile or a real deployment. This blind spot already exists for the four EPIC-001 tables under the identical mechanism and is not introduced or worsened by this decision — flagged here as a pre-existing hardening item, not a new risk this ADR needs to close.

---

## Alternatives Considered

| Decision | Alternative | Rejected because |
|---|---|---|
| D5 | Hardcode the sentinel only in the migration, leave `application.yml` as-is (no fallback) | Leaves the exact gap this ADR exists to close — nothing would guarantee a real environment's configured value matches the migration's literal |
| D5 | Have the migration read the tenant ID from an environment variable at Flyway-execution time (e.g. via a placeholder Flyway supports) | Adds a new migration-configuration mechanism for a single value that already has a perfectly good home (a Spring property with a sensible default); also couples schema migration timing to deployment-time environment plumbing unnecessarily |
| D6 | Grant `nexus_app` full `SELECT, INSERT, UPDATE, DELETE` on all 4 tables uniformly | Violates least-privilege for no benefit — `permissions` never needs writes, `roles`/`role_permissions` never need `UPDATE`, and `user_roles` should never be grantable `DELETE` given the trigger already exists specifically to prevent that |
| D6 | Rely on the `user_roles` trigger alone and skip a grants change entirely | The trigger enforces *delete-safety* but says nothing about `SELECT`/`INSERT`/`UPDATE` access existing at all — without any grant, `nexus_app` cannot read or write the table, which breaks US-010/US-012 outright, not just a defense-in-depth gap |

---

## Consequences

**Benefits:**
- D5 removes an entire class of "prod configured differently from what the migration assumed" failure mode, at the cost of a one-line config change.
- D6 gives every new RBAC table the same least-privilege posture already established for the identity tables, with grant scope traceable directly to which stories actually read/write each table.

**Trade-offs:**
- D5 means the bootstrap default tenant is effectively a fixed platform constant unless an operator deliberately changes both the property override and the corresponding `roles` rows together — this is intentional, not an oversight, but should be understood by whoever eventually builds Epic 3's real tenant-provisioning flow (that flow supersedes the "single default tenant" model entirely).
- D6's residual CI blind spot (Testcontainers not exercising `nexus_app`) remains open. If a future story wants to close it for all tables at once (not just RBAC's four), that is a separate, larger change to `TestcontainersConfiguration` and should be scoped as its own hardening item, not bundled into US-009.

**Follow-on rule for future work:** any new bounded context introducing tables that the running application must read/write should size its `nexus_app` grants per-table to the actual read/write pattern (as D6 does here), and add the grants to all three existing provisioning artifacts as part of the same story that creates the schema — not a follow-up story, since (as found here) a schema-only story with no grants change looks fully green in Testcontainers CI while being broken in every real environment.
