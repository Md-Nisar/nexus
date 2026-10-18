-- V10__rbac_roles_drop_tenant_name_unique.sql
-- US-018 M9-contract / C1 (03-design.md 11.1, Decision 26), CONTRACT step: a deleted role's name
-- can be reused.
--
-- V9 added deleted_at, the STORED generated active_name and uq_roles_tenant_active_name, which makes
-- the name unique among LIVE roles only, and left the old uq_roles_tenant_name in place so a
-- release that did not yet filter deleted rows could not create two live roles with one name. This
-- file drops the old key. Uniqueness is then enforced only by uq_roles_tenant_active_name.
--
-- DEPLOY ONLY AFTER the V9 release (T-025) is live on EVERY instance. An older instance would
-- otherwise insert a role whose name collides with a live one and rely on the dropped key to
-- refuse it (04-tasks.md T-031 risk). Never edit this file after first apply (ADR 0003).
--
-- ONE statement per migration file (RC-40.4): a failed file is recovered by `flyway repair` and a
-- re-run, as the Flyway DDL user (runbook; RES-44).

DROP INDEX uq_roles_tenant_name ON roles;
