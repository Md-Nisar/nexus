-- V9__rbac_roles_soft_delete.sql
-- US-018 M9 / C1 (03-design.md 11.1, Decision 26), EXPAND step: roles become soft-deletable.
--   deleted_at   NULL while the role is live; set by DELETE /api/v1/roles/{roleId}.
--   active_name  STORED generated column, the role's name while it is live and NULL once deleted
--                (the ADR-0013 D2 pattern, as user_roles.active_key). Not mapped by JPA.
--   uq_roles_tenant_active_name  makes the NAME unique among LIVE roles only. It is added next to
--                the existing uq_roles_tenant_name, which stays until V10 (the contract step, one
--                release after M9 is live everywhere): until then a deleted role's name still
--                collides on uq_roles_tenant_name (409 RBAC_006), which is safe, merely restrictive.
--
-- RUNS IN A MAINTENANCE WINDOW (RC-49.2). A STORED generated column cannot be added in place, so
-- MySQL rebuilds `roles` (ALGORITHM=COPY): create, PATCH and DELETE of roles block for the
-- duration; reads continue. Roles are few (at most max-roles-per-tenant per tenant), so the window
-- is short, but it is a window. Never edit this file after first apply (ADR 0003).
--
-- ONE statement per migration file (RC-40.4). MySQL DDL is not transactional across statements, so
-- a file with two statements could apply the first and fail the second, leaving Flyway in a failed
-- state that blocks every booting instance. A failed file is recovered by `flyway repair` and a
-- re-run, as the Flyway DDL user (runbook; RES-44).
--
-- Grants are NOT part of this file (nexus_app holds no DDL, ADR 0012): the column-scoped
--   GRANT UPDATE (name, description, deleted_at) ON nexus.roles TO 'nexus_app'@'%';
-- is applied per environment (nexus-database/mysql/init/02-grants-post-schema.sql,
-- docs/runbooks/nexus-app-provisioning.md, TestcontainersConfiguration), after the code is deployed.

ALTER TABLE roles
    ADD COLUMN deleted_at DATETIME(6) NULL,
    ADD COLUMN active_name VARCHAR(64) COLLATE utf8mb4_0900_ai_ci
        GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN name END) STORED,
    ADD UNIQUE INDEX uq_roles_tenant_active_name (tenant_id, active_name);
