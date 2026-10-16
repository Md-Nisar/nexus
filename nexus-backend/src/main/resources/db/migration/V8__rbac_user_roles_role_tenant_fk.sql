-- V8__rbac_user_roles_role_tenant_fk.sql
-- US-018 M8 / B2 (03-design.md 10.2, Decision 21): the database refuses a `user_roles` row whose
-- `tenant_id` differs from the assigned role's own `tenant_id` (closes US-010 T-S1 at the schema).
-- `fk_user_roles_role` is KEPT (dropping it would be a contract step for no benefit). The optional
-- `users` composite FK is not adopted (03b-threat-model.md 11.4).
--
-- RUNS IN A MAINTENANCE WINDOW. With foreign_key_checks=1 MySQL adds this FK with ALGORITHM=COPY:
-- `user_roles` is rebuilt and writes to it (assign, revoke, break-glass) are blocked for the
-- duration; reads continue. Never `SET foreign_key_checks=0`: that would skip validating existing
-- rows, which is the point of the constraint.
--
-- PRE-FLIGHT, every environment, before deploy (A-9; runbook): the count below must be 0.
--   SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.tenant_id <> r.tenant_id;
-- A non-zero count stops the deploy: user_roles cannot be DELETEd (append-only trigger) and a revoked
-- mismatched row still violates the FK; remediation needs a DBA exception with Security sign-off.
--
-- ONE statement per migration file (RC-40.4). A failed file is recovered by `flyway repair` and a
-- re-run, as the Flyway DDL user (runbook; RES-44). DML foreign key checks need no REFERENCES
-- privilege, so no grant changes. No entity change (ddl-auto=validate does not check keys).
-- Append-only (ADR 0003): never edit after first apply. Requires V7's uq_roles_id_tenant.

ALTER TABLE user_roles
    ADD CONSTRAINT fk_user_roles_role_tenant
    FOREIGN KEY (role_id, tenant_id) REFERENCES roles (id, tenant_id);
