-- V6__rbac_user_role_assign_permission.sql
-- US-018 M2 / A1 (ADR-0021 D1): seed `user:role:assign`, the permission that gates assigning and
-- revoking roles. `user:write` keeps only "create and modify user accounts".
-- Append-only migration (ADR 0003) -- never edit after first apply. Data only: no DDL, no grant,
-- no index change.
--
-- Seeded PK literal is a format-valid UUIDv7, continuing V5's sequence:
--   user:role:assign 019f6839-1807-7000-8000-000000000008
-- UUID_TO_BIN default swap_flag=0 => big-endian, byte-identical to UuidV7Converter (ADR-0005).
--
-- No backfill to custom roles that carry `user:write` (03-design.md Decision 3): the pre-deploy
-- A1 detection query and an administrator's explicit attach replace it (03-design.md §4.8).

INSERT INTO permissions (id, name, description) VALUES
    (UUID_TO_BIN('019f6839-1807-7000-8000-000000000008'), 'user:role:assign',
     'Assign and revoke roles for users in the tenant');

-- ---------------------------------------------------------------------------
-- B7 footer, pre-V9 variant (03-design.md §4.7, §10.7; RC-27.1, RC-48.1).
-- Instantiated from the one-placeholder template with
--   {{INSERTED_PERMISSION_IDS}} = UUID_TO_BIN('019f6839-1807-7000-8000-000000000008')
-- i.e. exactly the ids this file inserts above. Both statements are idempotent
-- (INSERT ... SELECT ... WHERE NOT EXISTS) and their order does not change the result.
-- RbacSchemaMigrationIT re-executes the statements between the two markers below.
-- B7-FOOTER-BEGIN
-- ---------------------------------------------------------------------------

-- (a) Admin-defining preservation: every role, system or custom, in any tenant, that carried
--     EVERY permission of the pre-migration catalogue (every permissions row except the ids this
--     file inserts) gains the inserted ids, so it stays admin-defining (ADR-0021 D1, D3). A role
--     one permission short gains nothing. An empty pre-migration catalogue qualifies no role
--     (fail closed, matching RbacAdministrators' empty-catalogue rule).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON p.id IN (UUID_TO_BIN('019f6839-1807-7000-8000-000000000008'))
WHERE EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN (UUID_TO_BIN('019f6839-1807-7000-8000-000000000008')))
  AND NOT EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN (UUID_TO_BIN('019f6839-1807-7000-8000-000000000008'))
          AND NOT EXISTS (
                SELECT 1
                FROM role_permissions rpc
                WHERE rpc.role_id = r.id AND rpc.permission_id = pc.id))
  AND NOT EXISTS (
        SELECT 1
        FROM role_permissions rp
        WHERE rp.role_id = r.id AND rp.permission_id = p.id);

-- (b) System re-sync: every system TENANT_ADMIN, in any tenant, gains every permission it does
--     not already carry -- not only the new one, so earlier drift is repaired too.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.is_system_role = TRUE
  AND r.name = 'TENANT_ADMIN'
  AND NOT EXISTS (
        SELECT 1
        FROM role_permissions rp
        WHERE rp.role_id = r.id AND rp.permission_id = p.id);

-- B7-FOOTER-END
