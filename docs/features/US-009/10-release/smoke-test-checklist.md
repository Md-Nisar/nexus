# US-009 — Smoke Test Checklist

_Phase 10 (`/release-prep`) deliverable. Reformats the AC9 grant procedure (already executed once this session — `04-tasks.md` T-09-09, `08-test-audit.md`) into a repeatable checklist for every future deploy of this migration (dev/staging/prod). This is the **only** verification path that exercises the real `nexus_app` credential — Testcontainers CI structurally cannot (it runs as the container's default `test` user, `03-design.md` §6.2)._

**Run this after every deploy of `V5__rbac_schema.sql` + grants to a new environment, and after any change to the grant artifacts.** — **Owner: [ASSIGN: QA Engineer]** (all steps below; escalate to **[ASSIGN: DevOps/DBA]** if any grant-provisioning step itself needs correcting)

---

## 1. Healthcheck endpoint

- [ ] Application's existing healthcheck/actuator endpoint responds `200 OK` post-deploy (general regression check — this story adds no new health indicator itself; a US-010 forward item adds a DB-privilege self-check later).

## 2. Bring up the full stack as `nexus_app`

- [ ] Run:
  ```
  docker compose --profile full up
  ```
- [ ] Confirm the one-shot `flyway-migrate` service log shows it applied `V5` and then executed `afterMigrate.sql` (the grants file) — look for `Executing SQL callback: afterMigrate` and no `FlywayException`.
- [ ] Confirm `backend` connects using `DB_USERNAME=nexus_app` (per `docker-compose.yml:74`) and boots without a `ddl-auto=validate` error.

**Pass:** clean startup, no errors in either log. **Fail:** any `FlywayException`, container crash-loop, or schema-validation error → **do not proceed; treat as a deploy failure per `rollback-checklist.md`.**

## 3. Happy-path RBAC read/write, exercised as `nexus_app`

Connect to the target MySQL instance as `nexus_app` (via a scripted client or an ad-hoc `mysql` session using the environment's real `nexus_app` credential — never the DDL/root credential for this step):

- [ ] `SELECT * FROM permissions;` → **Pass:** 7 rows returned, no `Access denied`.
- [ ] `SELECT * FROM roles WHERE is_system_role = TRUE;` → **Pass:** 2 rows (`TENANT_ADMIN`, `MEMBER`), no `Access denied`.
- [ ] `SELECT * FROM role_permissions;` → **Pass:** 8 rows, no `Access denied`.
- [ ] `SELECT * FROM user_roles;` → **Pass:** query succeeds (row count depends on environment state), no `Access denied`.
- [ ] `INSERT INTO roles (id, tenant_id, name, is_system_role) VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN('00000000-0000-7000-8000-000000000001'), 'SMOKE_TEST_ROLE', FALSE);` → **Pass:** insert succeeds.
- [ ] `INSERT INTO role_permissions (role_id, permission_id) SELECT <smoke-test-role-id>, id FROM permissions LIMIT 1;` → **Pass:** insert succeeds.
- [ ] `INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by) VALUES (UUID_TO_BIN(UUID()), <existing-user-id>, <smoke-test-role-id>, UUID_TO_BIN('00000000-0000-7000-8000-000000000001'), <existing-user-id>);` → **Pass:** insert succeeds.
- [ ] `UPDATE user_roles SET revoked_at = NOW() WHERE id = <the row just inserted>;` → **Pass:** update succeeds (this is the one permitted mutation path).
- [ ] **Cleanup:** `DELETE FROM role_permissions WHERE role_id = <smoke-test-role-id>; DELETE FROM roles WHERE id = <smoke-test-role-id>;` (as the DDL credential, not `nexus_app` — `nexus_app` correctly cannot delete `roles`). Note the `user_roles` row inserted above **cannot** be hard-deleted by design (trigger) — leave it revoked, or use a disposable/ephemeral test environment for this step.

## 4. Negative proof — column-scoped grant (the ADR-0015 D7 guarantee)

- [ ] As `nexus_app`, attempt: `UPDATE user_roles SET assigned_by = UUID_TO_BIN(UUID()) WHERE id = <any row>;`
  **Expected exact result:** `ERROR 1143 (42000): UPDATE command denied to user 'nexus_app'@'...' for column 'assigned_by' in table 'user_roles'`
  **Pass:** denied with `ERROR 1143`. **Fail:** the update succeeds (grant is too broad — this is the T-T1 regression case; **block and escalate to [ASSIGN: Backend Lead] immediately**, do not sign off the deploy).

## 5. Negative proof — append-only trigger (defense-in-depth check)

- [ ] As `nexus_app`, attempt: `DELETE FROM user_roles WHERE id = <any row>;`
  **Expected exact result:** the query is rejected — either `ERROR 1142 (42000): DELETE command denied` (grant-level, since `nexus_app` holds no DELETE on `user_roles`) or, if a broader credential is used for this specific negative test, `SQLSTATE '45000'` with message `user_roles is append-only; use revoked_at to soft-delete` (trigger-level). **Pass:** denied by one or the other. **Fail:** the delete succeeds → **block and escalate immediately.**

## 6. Grant-scope assertion — the full `SHOW GRANTS` shape

- [ ] Run: `SHOW GRANTS FOR 'nexus_app'@'%';`
- [ ] **Expected exact output** (9 lines + implicit `GRANT USAGE`, per `docs/runbooks/nexus-app-provisioning.md` §3):
  ```
  GRANT USAGE ON *.* TO `nexus_app`@`%`
  GRANT SELECT, INSERT ON `nexus`.`auth_events` TO `nexus_app`@`%`
  GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus`.`auth_tokens` TO `nexus_app`@`%`
  GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus`.`refresh_tokens` TO `nexus_app`@`%`
  GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus`.`users` TO `nexus_app`@`%`
  GRANT SELECT ON `nexus`.`permissions` TO `nexus_app`@`%`
  GRANT SELECT, INSERT ON `nexus`.`roles` TO `nexus_app`@`%`
  GRANT SELECT, INSERT, DELETE ON `nexus`.`role_permissions` TO `nexus_app`@`%`
  GRANT SELECT, INSERT ON `nexus`.`user_roles` TO `nexus_app`@`%`
  GRANT UPDATE (`revoked_at`) ON `nexus`.`user_roles` TO `nexus_app`@`%`
  ```
- [ ] **Pass:** output matches exactly (order may vary, content must not). **Fail:** anything extra (`DROP`, `ALTER`, `CREATE`, `GRANT OPTION`, `ALL PRIVILEGES`, table-wide `UPDATE`/`DELETE` on `user_roles`, or any grant on a table not listed above) → treat as a provisioning defect, **do not sign off**, escalate to **[ASSIGN: DevOps/DBA]**.

## 7. Critical pre-existing flows (regression, not RBAC-specific)

- [ ] Login flow completes successfully (EPIC-001, unaffected by this story but the app did restart).
- [ ] Registration flow completes successfully and writes to the correct default tenant.
- [ ] **Payment: N/A** — no payment feature exists in this platform/story.
- [ ] Dashboard/basic authenticated navigation loads (if applicable to the environment under test).

## 8. Error monitoring shows no spike

- [ ] Check the application's error-rate dashboard/log aggregator for the 15 minutes surrounding this deploy — no spike above the environment's normal baseline. (No RBAC-specific error signal exists yet — this is a general regression check, since the app restarted.)

## 9. Logs flowing

- [ ] Confirm application logs are being ingested by the normal log pipeline post-restart (no RBAC-specific log lines expected — this story emits none, `monitoring.md`).

## 10. Metrics flowing

- [ ] Confirm the application's standard metrics endpoint / dashboard is receiving data post-restart (no RBAC-specific metric expected — general health check only).

---

## Overall Pass / Fail

**PASS** = every check above passes, including both negative proofs (§4, §5) and the exact `SHOW GRANTS` shape (§6).
**FAIL** = any single check fails → **do not sign off the deploy; go to `rollback-checklist.md`.**

**Executed once already, this session, against real Docker MySQL 8.4** (not just Testcontainers) — see `04-tasks.md` T-09-09 and `08-test-audit.md`. This checklist formalizes that same procedure for repeat execution on every future environment (dev, staging, prod) — do not skip it as "already done," since grants must be re-verified per-environment.
