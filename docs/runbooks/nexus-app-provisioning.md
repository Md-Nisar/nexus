# Runbook: Provisioning the `nexus_app` Least-Privilege DB User (Prod / Staging)

**Feature:** US-008 (Emit audit events for all authentication actions), Task T-08-10
**Decision record:** [ADR 0012 — Least-Privilege Runtime DB User for `auth_events`](../adr/0012-least-privilege-runtime-db-user-for-auth-events.md)
**Audience:** Ops / DBA. This is an out-of-band, per-environment provisioning step — it is
**not** applied by Flyway and **not** something application code or CI touches for prod
(`application-prod.*` is out of scope for the application repo's own tooling; see CLAUDE.md).

---

## What this runbook provisions

A single MySQL user, `nexus_app`, that the application connects as at runtime instead of
`root`. It has:

- `INSERT, SELECT` on `auth_events` — **no `UPDATE`/`DELETE`** (privilege-level backstop to the
  existing append-only triggers, `V2__identity_schema.sql:98-110`).
- `SELECT, INSERT, UPDATE, DELETE` on `users`, `refresh_tokens`, `auth_tokens` — normal
  application DML, no DDL.
- **No DDL whatsoever** (`CREATE`, `ALTER`, `DROP`, `GRANT`) — never grant this user DDL, under
  any circumstance, including to unblock a failing migration (ADR 0012 §3, T-E3).

This mirrors exactly what is already automated for local dev (`mysql/init/01-grants.sql` +
`mysql/init/02-grants-post-schema.sql`, wired via `docker-compose.yml`) and for Testcontainers
(`nexus-backend/src/test/resources/nexus-app-grants.sql` +
`TestcontainersConfiguration.nexusAppGrantsCallback`). Prod has no equivalent automation —
that is the explicit, accepted trade-off recorded in ADR 0012 §2, and is why this runbook
exists.

---

## Prerequisites

- A DDL-capable credential distinct from `nexus_app`, used only to run Flyway migrations and to
  create/grant `nexus_app` itself. **Do not reuse `nexus_app` for this** — see ADR 0012 §3 and
  §4 for why the migration credential and the runtime credential must stay separate, and why
  prod `root` (or an equivalent superuser) should be locked down, rotated, and not used for
  routine operations.
- Confirm the identity schema (`users`, `refresh_tokens`, `auth_tokens`, `auth_events`) already
  exists — i.e. Flyway migrations have already run. **The table-scoped `GRANT` statements below
  fail with `ERROR 1146 (42S02): Table 'nexus.<table>' doesn't exist` if run before the schema
  exists** (empirically verified against MySQL 8.4 during T-08-10's implementation). Always run
  migrations first, grants second — never combine them into one step or one credential.
- A password management process (vault, secrets manager, etc.) for `nexus_app`'s credential.
  Never place this password in a file the application repo tracks or in plaintext
  configuration — see "Credential handling" below.

---

## Provisioning steps

### 1. Create the `nexus_app` user

Run as the DDL-capable/superuser credential, against the target MySQL instance:

```sql
CREATE USER 'nexus_app'@'%' IDENTIFIED BY '<STRONG_GENERATED_PASSWORD>';
```

Restrict the host spec (`@'%'`) further if your network topology allows a narrower CIDR/host —
`@'%'` matches what dev/Testcontainers use for simplicity, but prod should scope this to the
actual application subnet if feasible.

### 2. Confirm the identity schema exists (see Prerequisites), then grant scoped privileges

```sql
-- auth_events: append + read only -- privilege-level backstop to the existing triggers
GRANT INSERT, SELECT ON nexus.auth_events TO 'nexus_app'@'%';

-- other identity tables: normal DML, no DDL
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.users          TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.refresh_tokens TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.auth_tokens    TO 'nexus_app'@'%';

FLUSH PRIVILEGES;
```

This is exactly ADR 0012 §1's grant shape — do not add tables, do not add privileges beyond
this list, and never add `WITH GRANT OPTION`.

### 3. Verify the grant is exactly what was intended

```sql
SHOW GRANTS FOR 'nexus_app'@'%';
```

Expected output (four lines, plus the implicit `GRANT USAGE`):

```
GRANT USAGE ON *.* TO `nexus_app`@`%`
GRANT SELECT, INSERT ON `nexus`.`auth_events` TO `nexus_app`@`%`
GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus`.`auth_tokens` TO `nexus_app`@`%`
GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus`.`refresh_tokens` TO `nexus_app`@`%`
GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus`.`users` TO `nexus_app`@`%`
```

If anything else appears (`DROP`, `ALTER`, `CREATE`, `GRANT OPTION`, or `UPDATE`/`DELETE` on
`auth_events`), treat it as a provisioning defect — do not proceed to step 4 until corrected.
(T-08-11's privilege-level integration test asserts this exact shape in CI/Testcontainers; this
manual check is the prod-side equivalent, since prod has no automated equivalent of that test.)

### 4. Wire the credential into the application's runtime configuration

Update the deployment's environment/secrets configuration (however `application-prod.*` sources
`DB_USERNAME`/`DB_PASSWORD` in your deployment pipeline — this repo's tooling does not manage
that file) so the running application connects as `nexus_app`, not `root` or any other
DDL-capable credential.

### 5. Confirm the application boots and can read/write as expected

After deploying with the new credential:
- Confirm the application starts successfully (no `ddl-auto=validate` failures — migrations
  must already be applied under the separate DDL credential, per Prerequisites).
- Confirm a login/logout/registration flow completes and an `auth_events` row is written
  (`SELECT COUNT(*) FROM auth_events` before/after, or check application logs for audit-write
  WARN messages, which would indicate a grant problem).
- If T-08-12 (runtime DB-privilege self-check) has shipped, confirm its health indicator/log
  reports the connection as `nexus_app`-scoped, not `root`-equivalent.

---

## Rotation

Rotate the `nexus_app` credential on the same cadence as other application-tier database
credentials in your environment. Rotation does not require re-running steps 1-3 (the user and
its grants are unaffected by a password change) — only:

```sql
ALTER USER 'nexus_app'@'%' IDENTIFIED BY '<NEW_STRONG_GENERATED_PASSWORD>';
```

followed by updating the deployment's secret store and restarting/redeploying the application
so it picks up the new credential. `ALTER USER ... IDENTIFIED BY` is the one DDL-adjacent
operation on this user's own account that is expected and safe — it does not touch table-level
grants and is not the same as granting this user general DDL privileges on `nexus.*`.

Also rotate the separate migration/DDL credential (see Prerequisites) on its own cadence — ADR
0012 §4 recommends this explicitly and notes it should be more tightly held than `nexus_app`,
since it is DDL-capable.

---

## Credential handling

- Never commit the `nexus_app` password to this repository, in any form (plaintext, base64,
  etc.). The dev (`mysql/init/01-grants.sql`) and test (`nexus-app-grants.sql`) passwords are
  intentionally non-secret placeholders, explicitly labeled as dev/test-only, and are never
  valid outside their ephemeral containers — they are not a template for how prod credentials
  should be stored.
- Source the prod password from your organization's secrets manager / vault, injected at
  deploy time, exactly as other prod database credentials already are.
- If this credential is ever suspected to have leaked (e.g. via a compromised deployment
  pipeline, log leak, or RCE/SSRF against the application), rotate immediately per the Rotation
  section above. Per ADR 0012's threat analysis (T-E1), a leaked `nexus_app` credential grants
  only scoped DML and read/insert-only access to `auth_events` — it cannot `DROP`, `GRANT`, or
  tamper with committed audit rows — but it should still be rotated as a matter of course.

---

## What this runbook does NOT cover

- **Locking down prod `root`** (network restriction, disabling remote root login, auditing) —
  this is general DB-server hardening, not specific to `nexus_app`, and is an accepted residual
  per ADR 0012 §4 (T-T4): this control binds the *application* principal, not a separately
  obtained DBA/superuser credential. Follow your organization's existing DB-hardening standard
  for that.
- **CI/Testcontainers provisioning** — that is fully automated already; see
  `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java` and
  `nexus-backend/src/test/resources/nexus-app-grants.sql`. This runbook is prod/staging-only.
- **The runtime self-check** (T-08-12) that detects grant drift at application startup — once
  shipped, that check is the automated complement to step 5 above; this runbook does not
  implement it.

---

### Cross-references
- `docs/adr/0012-least-privilege-runtime-db-user-for-auth-events.md` — the decision this runbook
  operationalizes.
- `docs/features/US-008/03-design.md` §6 — WS-2 design (grant SQL, environment-by-environment
  provisioning table).
- `docs/features/US-008/03b-threat-model.md` — T-T3, T-T4, T-E1, T-E2, T-E3 (the residual risks
  this provisioning must not reintroduce).
- `docs/features/US-008/04-tasks.md` — T-08-10 (this runbook's task), T-08-11 (privilege-level
  append-only `*IT`), T-08-12 (runtime self-check).
- `mysql/init/01-grants.sql`, `mysql/init/02-grants-post-schema.sql`, `docker-compose.yml` — the
  local-dev equivalent of steps 1-2 above, fully automated.
