# US-009 — Deployment Checklist

_Phase 10 (`/release-prep`) deliverable. Builds on `deployment.md`; adds go/no-go sequencing and named owners. Feature: EPIC-002 RBAC Foundation — US-009 (schema-only: Flyway `V5`, 5 JPA entities, 4 repositories, DB grants). No runtime API, no controllers, no traffic-facing behavior._

**Branch:** `feature/US-009` · **Prerequisite gates already passed:** code review `APPROVE WITH NITS` (`06-code-review.md`), security review `APPROVED` (`07-security-review.md`), test audit 606/607 passing incl. 27/27 RBAC `*IT` (`08-test-audit.md`).

---

## Pre-Deploy

- [ ] **Confirm Flyway migration slot is still `V5` on target `main`** — re-run `ls nexus-backend/src/main/resources/db/migration/` immediately before merge; if a `V5` has landed from an unrelated PR since this was authored, this migration must be renumbered before merge (never edit an already-applied file, ADR-0003). — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Confirm the migration is additive-only, no expand/contract review needed** — verified: 4 new `CREATE TABLE`s, one new trigger, one CHECK constraint, seed DML; zero existing tables/columns touched (`02-impact.md` §6, `03-design.md` §10). No non-additive change to flag per ADR-0003. — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Confirm the atomic-PR invariant:** `V5__rbac_schema.sql` + the 4 entities (`Permission`, `Role`, `RolePermission`, `UserRole`) + `RolePermissionId` + 4 repositories are all in the **same** merge/release. `ddl-auto=validate` fails boot if they disagree (`03-design.md` §10.1, `04-tasks.md` DoD). — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Confirm `application.yml` is genuinely unchanged** — `grep -n default-tenant-id nexus-backend/src/main/resources/application.yml` must still show line 105 as `${NEXUS_IDENTITY_DEFAULT_TENANT_ID}` with **no** `:default` fallback (ADR-0015 D8; verified during this release-prep pass). Any diff here is a regression of a deliberate security decision — block merge if found. — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Confirm all 3 `nexus_app` grant artifacts are byte-identical** (`nexus-database/mysql/init/02-grants-post-schema.sql`, `TestcontainersConfiguration.nexusAppGrantsCallback`, `docs/runbooks/nexus-app-provisioning.md` Step 2) — 5 statements each, `user_roles` UPDATE column-scoped to `revoked_at` only (ADR-0014 D6 + ADR-0015 D7). Verified identical during this release-prep pass; re-diff if any of the 3 files changes again before merge. — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Record the backend build artifact identifier** — commit SHA of the merge commit + Maven `nexus-backend` version (`4.1.0` at time of writing, `pom.xml`). This is the ID the rollback plan reverts *to* the prior artifact from. — **Owner: [ASSIGN: Release Manager]**
- [ ] **Frontend build artifact identifier: N/A.** Zero `nexus-frontend/` files touched (`02-impact.md` §7, `03-design.md` §7 — verified). No frontend build to tag for this release. — **Owner: [ASSIGN: Release Manager]** (confirm only, no action)
- [ ] **Config / env vars added: NONE, explicitly.** `application.yml` is deliberately untouched (ADR-0015 D8). The **only** environment-variable dependency is pre-existing: `NEXUS_IDENTITY_DEFAULT_TENANT_ID` must already be set in the target environment (source: environment secrets/config store, not new for this release) — if it's unset, the app **fails to boot** (intentional fail-fast, not a regression). Confirm it is set to `00000000-0000-7000-8000-000000000001` in the target environment before deploying. — **Owner: [ASSIGN: DevOps/DBA]**
- [ ] **Feature flag: N/A, confirmed no flag exists or is needed** — schema-only change, no runtime behavior to gate (`03-design.md` §8.2, `deployment.md`). Do not add one. — **Owner: [ASSIGN: Backend Lead]** (confirm only)
- [ ] **Secrets rotated / added: NONE.** No new credentials or Vault paths introduced by this story. The `nexus_app` credential itself is pre-existing (ADR-0012) — this release only adds table-scoped grants to that existing principal, not a new secret. — **Owner: [ASSIGN: DevOps/DBA]** (confirm only)
- [ ] **Prod/staging `nexus_app` grant provisioning drafted and ready to apply** — the 5 `GRANT` statements (§2 of `docs/runbooks/nexus-app-provisioning.md`) must be applied against the target environment's real DB, using the separate DDL-capable credential (never `nexus_app` itself), **after** `V5` has applied. For docker-compose/dev this is automatic via `flyway-migrate`'s `afterMigrate.sql`; for a genuinely fresh prod/staging provisioning, this is a manual step. — **Owner: [ASSIGN: DevOps/DBA]**
- [ ] **Communication sent to stakeholders** — notify the Epic 3 (Tenant Management) team that `TENANT_ADMIN` will exist and be correctly tenant-scoped once this deploys (this is their kickoff gate, `01-requirements.md` §14); notify whoever owns US-010/US-012/US-015 planning that the RBAC schema + grants are now live and stable to build against. — **Owner: [ASSIGN: Release Manager / PM]**
- [ ] **Smoke test plan ready** — `smoke-test-checklist.md` reviewed and commands rehearsed against a non-prod environment before the real deploy window. — **Owner: [ASSIGN: QA Engineer]**

### Go/No-Go Gate 1 (before merge)

**Go criteria:** all Pre-Deploy items checked, migration slot confirmed current, all 3 grant artifacts verified identical, `application.yml` verified unchanged.
**No-go:** any item above unchecked, or a grant-artifact mismatch found.
**Decision owner: [ASSIGN: Backend Lead]**

---

## During Deploy

- [ ] **Apply `V1`–`V4` if not already present** (should already be true in any existing environment; verify via `flyway_schema_history`) — **Owner: [ASSIGN: DevOps/DBA]**
- [ ] **Apply `V5__rbac_schema.sql`** — via the standard deploy pipeline / `flyway-migrate` compose service. Confirm Flyway reports `Successfully applied 1 migration` (or equivalent) with no `FlywayException`. — **Owner: [ASSIGN: DevOps/DBA]**
- [ ] **Apply the `nexus_app` grants** — for environments using the `flyway-migrate afterMigrate.sql` mechanism this is automatic and immediate; for prod/staging provisioned outside that mechanism, run `docs/runbooks/nexus-app-provisioning.md` §2 manually **now**, immediately after `V5` completes (`GRANT ... ON db.table` fails `ERROR 1146` if run before the tables exist). — **Owner: [ASSIGN: DevOps/DBA]**
- [ ] **Deploy the backend artifact** (the entities + repositories, same release as `V5`) and confirm the application boots cleanly under `ddl-auto=validate` — no `SchemaManagementException` referencing `com.example.nexus.rbac.*`. — **Owner: [ASSIGN: Backend Lead / DevOps]**
- [ ] **No frontend deploy step** — nothing to deploy on the frontend side for this release. — **Owner: [ASSIGN: Release Manager]** (confirm only)

### Go/No-Go Gate 2 (before traffic / before declaring deploy complete)

**Go criteria:** Flyway reports success, app boots without schema-validation error, `SHOW GRANTS FOR 'nexus_app'@'%'` (run now, ahead of the full smoke test) shows the 4 new RBAC grant lines present.
**No-go:** Flyway failure, boot failure, or grants missing → **halt, do not proceed to post-deploy sign-off, go to `rollback-checklist.md`.**
**Decision owner: [ASSIGN: DevOps/DBA] jointly with [ASSIGN: Backend Lead]**

---

## Post-Deploy

- [ ] **Run the full smoke test checklist** (`smoke-test-checklist.md`) — the AC9 grant procedure, reformatted as a repeatable gate, against this environment specifically (Testcontainers CI cannot verify `nexus_app`'s real grants — this is the only place that can). — **Owner: [ASSIGN: QA Engineer]**
- [ ] **Run the monitoring checklist's one post-deploy check** (`monitoring-checklist.md`) — confirm tables exist, seed counts (7/2/8) correct, `TENANT_ADMIN`/`MEMBER` join queries correct. — **Owner: [ASSIGN: QA Engineer / DevOps]**
- [ ] **Confirm no regression on pre-existing flows** — login, registration, and any existing health/readiness endpoints still respond normally post-deploy (this release touches `application.yml`'s neighborhood not at all, but the app restarted, so a basic regression pass is warranted). — **Owner: [ASSIGN: QA Engineer]**
- [ ] **Confirm Epic 3 gate is unblocked** — `SELECT * FROM roles WHERE name='TENANT_ADMIN'` scoped to the environment's actual default tenant returns exactly one row with all 7 permissions joined. Notify the Epic 3 team once confirmed. — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Close out communication** — confirm to stakeholders (Epic 3 team, US-010/012/015 owners) that the deploy completed and the schema/grants are live. — **Owner: [ASSIGN: Release Manager]**
- [ ] **Record this deploy's artifact IDs and grant-check evidence** in the release log / PR for future rollback reference. — **Owner: [ASSIGN: Release Manager]**

### Go/No-Go Gate 3 (deploy sign-off)

**Go criteria:** smoke test passed (incl. the `ERROR 1143` negative proof and the exact 9-line `SHOW GRANTS` shape), monitoring check passed, no regression found.
**No-go:** any smoke test failure → **do not sign off; invoke `rollback-checklist.md`.**
**Decision owner: [ASSIGN: Release Manager]**
