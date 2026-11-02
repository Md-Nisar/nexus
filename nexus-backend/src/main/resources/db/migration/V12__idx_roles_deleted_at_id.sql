-- V12__idx_roles_deleted_at_id.sql
-- US-018 / [OR-11]: composite index on roles(deleted_at, id)
-- Optimizes the health check query countActiveAssignmentsOnDeletedRolesInAnyTenant:
--   SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
--   WHERE r.deleted_at IS NOT NULL AND ur.revoked_at IS NULL
--
-- ONE statement per migration file (RC-40.4).

CREATE INDEX idx_roles_deleted_at_id ON roles(deleted_at, id);
