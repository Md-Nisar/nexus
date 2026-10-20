-- V11__rbac_user_directory_read_permission.sql
-- US-019 S1a (03-design.md §3.1, §3.2): seed `user:directory:read`, the permission that gates the
-- tenant user directory (B1, B2), which includes email addresses.
-- Append-only migration (ADR 0003) -- never edit after first apply. Data only: no DDL, no grant,
-- no index change (ADR-0014 D6).
--
-- Seeded PK literal is a format-valid UUIDv7, continuing V5/V6's sequence:
--   user:directory:read 019f6839-1808-7000-8000-000000000009
-- UUID_TO_BIN default swap_flag=0 => big-endian, byte-identical to UuidV7Converter (ADR-0005).
--
-- The administrator definition does not change (ADR-0021 D3): a role is admin-defining iff it
-- carries every row of `permissions`. From this commit the catalogue has nine rows, so footer (a)
-- completes every live role that carried all eight pre-V11 permissions (no demotion), and gives
-- nothing to a role that was short of one (no promotion). System MEMBER gets nothing (Gate 1 Q1).
-- Runbook ordering (RC-63(d)): flush the permset/roleset cache after this applies, and enable
-- feature.nexus-us019-user-directory only after a fresh administrator token carries the permission.

INSERT INTO permissions (id, name, description) VALUES
    (UUID_TO_BIN('019f6839-1808-7000-8000-000000000009'), 'user:directory:read',
     'Read the tenant user directory, including email addresses');

-- ---------------------------------------------------------------------------
-- B7 footer, A-V9 variant (db/templates/permission-migration-footer.sql; US-018 RC-27.1, RC-48.1).
-- Instantiated from the one-placeholder template with
--   {{INSERTED_PERMISSION_IDS}} = UUID_TO_BIN('019f6839-1808-7000-8000-000000000009')
-- i.e. exactly the id this file inserts above. Both statements are idempotent
-- (INSERT ... SELECT ... WHERE NOT EXISTS) and their order does not change the result.
-- RbacSchemaMigrationIT re-executes the statements between the two markers below.
-- B7-FOOTER-BEGIN
-- ---------------------------------------------------------------------------

-- (a) Admin-defining preservation (V9-and-later variant: soft-deleted roles are excluded).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON p.id IN (UUID_TO_BIN('019f6839-1808-7000-8000-000000000009'))
WHERE r.deleted_at IS NULL
  AND EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN (UUID_TO_BIN('019f6839-1808-7000-8000-000000000009')))
  AND NOT EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN (UUID_TO_BIN('019f6839-1808-7000-8000-000000000009'))
          AND NOT EXISTS (
                SELECT 1
                FROM role_permissions rpc
                WHERE rpc.role_id = r.id AND rpc.permission_id = pc.id))
  AND NOT EXISTS (
        SELECT 1
        FROM role_permissions rp
        WHERE rp.role_id = r.id AND rp.permission_id = p.id);

-- (b) System re-sync: every system TENANT_ADMIN, in any tenant, gains every permission it lacks.
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
