# ADR 0015 — US-009 Threat-Model Hardening: Column-Scoped `user_roles` Grant and Non-Prod-Only Tenant Fallback

**Status:** Accepted
**Date:** 2026-07-16
**Feature:** EPIC-002 (RBAC Foundation) — US-009

---

## Context

The Gate-2 STRIDE threat model for US-009 (`docs/features/US-009/03b-threat-model.md`) found two findings in the Gate-2 solution design (`03-design.md`) that are design changes, not follow-up tasks — both cheap to fix while the schema is still greenfield, both concretely weakening a security invariant the story otherwise establishes:

1. **T-T1 — `user_roles` UPDATE grant is table-wide.** ADR-0014 D6 grants `nexus_app` `SELECT, INSERT, UPDATE` on `user_roles` so US-012 can revoke a role by setting `revoked_at`. But the design deliberately installs no `BEFORE UPDATE` trigger (§2.2 of `03-design.md`) — `revoked_at` must remain updatable. The result: nothing at the database level stops a raw `UPDATE user_roles SET assigned_by = ?, user_id = ?, role_id = ?, assigned_at = ? …` from rewriting assignment history. This is strictly weaker than `auth_events`, which blocks *all* UPDATE via trigger. The JPA mapping (`insertable=false, updatable=false` on every column except `revoked_at`) only constrains the application's *own* code path, not a raw SQL connection, bulk script, or leaked credential.

2. **T-E2 — the bootstrap-tenant fallback was scoped to base `application.yml`.** ADR-0014 D5 resolved US-009's original OQ-3 (how does a static Flyway migration know the runtime's "default tenant" without a coordination gap) by giving `nexus.identity.default-tenant-id` a fallback value in `application.yml` equal to the migration's seed literal. Verified directly: `application.yml:105` today has **no** fallback (`${NEXUS_IDENTITY_DEFAULT_TENANT_ID}`, unresolved placeholder → fails to boot if unset), while `application-dev.yml:40` and `application-smoke.yml:40` already hardcode the identical literal independently, and `TestcontainersConfiguration` registers it dynamically. Also verified: `default-tenant-id` is not an inert placeholder — `RegistrationController` injects it (`@Value("${nexus.identity.default-tenant-id}")`, line 54) and uses it as the tenant for every self-registered user (lines 82, 130). Because base `application.yml` applies to **every** profile including prod, ADR-0014 D5's fallback would have converted prod's current fail-fast-on-unset behavior into a silent default into the one tenant that holds the seeded, all-permissions `TENANT_ADMIN` role and receives every self-registered user.

Both findings are recorded here rather than as an edit to ADR-0014 (Accepted, and this repo's ADRs are append-only — supersede, never edit).

---

## Decision

### D7 — Column-scoped `user_roles` grant, superseding part of ADR-0014 D6

Replace the table-wide `UPDATE` grant on `user_roles` with a column-scoped one, using MySQL's column-level privilege syntax:

```sql
GRANT SELECT, INSERT       ON nexus.user_roles TO 'nexus_app'@'%';
GRANT UPDATE (revoked_at)  ON nexus.user_roles TO 'nexus_app'@'%';
```

This restores `auth_events`-equivalent immutability for every column except the one soft-delete field that must remain writable: `nexus_app` (and therefore any leaked credential, bulk script, or raw connection using that user) can `INSERT` new rows and can `UPDATE` only `revoked_at` on existing ones — an attempt to `UPDATE user_roles SET assigned_by = ?` fails at the grant level with `ERROR 1143 (42000): UPDATE command denied`, regardless of what the JPA mapping intends. The `permissions` (SELECT-only), `roles` (SELECT, INSERT), and `role_permissions` (SELECT, INSERT, DELETE) grants from ADR-0014 D6 are unchanged.

### D8 — Bootstrap-tenant fallback scoped to non-prod only, superseding part of ADR-0014 D5

Do **not** add a fallback to base `application.yml`. Leave `application.yml:105` exactly as it is today (`${NEXUS_IDENTITY_DEFAULT_TENANT_ID}`, no default — fails to boot if unset). This preserves prod's existing fail-fast behavior: an environment that omits the tenant ID refuses to start rather than silently running with a well-known, publicly-documented tenant that holds a fully-privileged admin role.

ADR-0014 D5's actual goal — "the migration's seed literal and the runtime default tenant are the same value, not just coincidentally consistent" — is still achieved for every environment that currently relies on it, because `application-dev.yml`, `application-smoke.yml`, and `TestcontainersConfiguration` **already** hardcode the identical literal independently of any base-config fallback. No environment in current use changes behavior under this decision; only the *hypothetical* future case of an unconfigured prod changes, from "silently uses the public sentinel tenant" to "fails to boot," which is the correct default for a config value this security-sensitive.

---

## Alternatives Considered

| Decision | Alternative | Rejected because |
|---|---|---|
| D7 | Add a `BEFORE UPDATE` trigger checking `OLD.user_id = NEW.user_id AND OLD.role_id = NEW.role_id AND …` (only `revoked_at` may differ) | Functionally equivalent to the column grant but requires per-column comparison logic in trigger SQL (more moving parts, harder to read) for no additional guarantee — MySQL's native column-level `GRANT` expresses the identical constraint declaratively. Revisit only if a future column needs conditional (not blanket) writability that column-grants can't express. |
| D7 | Leave the table-wide grant and rely on the JPA mapping + code review | This is exactly the gap the threat model found: a raw SQL path, leaked credential, or future bulk script bypasses the JPA layer entirely. Application-layer-only enforcement is not a substitute for a database-level control when the database credential itself is the thing that could be compromised. |
| D8 | Keep the base fallback, but add a separate prod-specific override that unsets it / forces an explicit value | More complex (two config touchpoints instead of one absence) for the same outcome; simply not adding the fallback to base config is simpler and achieves the identical fail-fast property with zero new configuration surface. |
| D8 | Keep the base fallback, accept the prod risk, and rely on deployment-checklist discipline to always set the env var | Rejected precisely because this is the class of control ("someone must remember to configure X correctly") that this same story's ADR-0014 D5 was originally written to eliminate for the migration-literal side of the problem — applying weaker discipline to the config side would reopen an equivalent gap. |

---

## Consequences

**Benefits:**
- D7 gives `user_roles` the same class of database-level tamper-resistance `auth_events` already has, closing the one place this design was measurably weaker than its own precedent.
- D8 removes a newly-introduced production risk with zero cost to any environment currently in use — dev, smoke, and Testcontainers are unaffected because they already carry the literal independently.

**Trade-offs:**
- D7's column-level grant is slightly less common than table-level grants and must be remembered when any future column on `user_roles` needs runtime mutation — document this file as the reference point.
- D8 means a not-yet-configured prod (or any new environment) will fail to boot rather than "just working" with a default — this is intentional friction for a security-sensitive value, but it does mean deployment runbooks must explicitly call out setting `NEXUS_IDENTITY_DEFAULT_TENANT_ID`.

**Follow-on rule for future work:** any new least-privilege grant that permits `UPDATE` on a table with an otherwise-immutable history (soft-delete-only tables, audit-adjacent tables) should default to column-scoped grants (D7's pattern) rather than a blanket table-level `UPDATE`, unless every column on the table is genuinely intended to be runtime-mutable. Any config value that seeds a security-sensitive identifier (a tenant ID, a role ID, an admin credential) should default to **no fallback in base config** — fail fast — and only receive a hardcoded default in profile-specific files that are already scoped to non-production use (dev/test/smoke).
