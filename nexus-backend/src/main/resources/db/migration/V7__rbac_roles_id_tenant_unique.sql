-- V7__rbac_roles_id_tenant_unique.sql
-- US-018 M8 / B2 (03-design.md 10.2, Decision 21): a UNIQUE key over (id, tenant_id) on `roles`, the
-- parent key V8's composite foreign key needs. Trivially satisfiable: `id` is already the primary key.
-- Online: MySQL adds a unique secondary index in place (no table rebuild, concurrent DML allowed).
--
-- ONE statement per migration file (RC-40.4). MySQL DDL is not transactional across statements, so a
-- file with two statements could apply the first and fail the second, leaving Flyway in a failed
-- state that blocks every booting instance. A failed file is recovered by `flyway repair` and a
-- re-run, as the Flyway DDL user (runbook; RES-44). No grant change, no entity change.
-- Append-only (ADR 0003): never edit after first apply.

ALTER TABLE roles ADD CONSTRAINT uq_roles_id_tenant UNIQUE (id, tenant_id);
