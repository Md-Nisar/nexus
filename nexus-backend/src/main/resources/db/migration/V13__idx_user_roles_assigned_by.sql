-- V13__idx_user_roles_assigned_by.sql
-- US-018 / [OR-23]: index on user_roles(assigned_by)
-- Supports foreign key validation when users are purged and avoids table-level locks.
--
-- ONE statement per migration file (RC-40.4).

CREATE INDEX idx_user_roles_assigned_by ON user_roles(assigned_by);
