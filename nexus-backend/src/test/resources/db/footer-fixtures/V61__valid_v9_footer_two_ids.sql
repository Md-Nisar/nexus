-- Negative/positive fixture for PermissionMigrationFooterScannerTest. Never run by Flyway.
INSERT INTO permissions (id, name, description) VALUES
    (UUID_TO_BIN('019f6839-1810-7000-8000-000000000011'), 'fixture:perm0', 'Fixture permission'),
    (UUID_TO_BIN('019f6839-1810-7000-8000-000000000012'), 'fixture:perm1', 'Fixture permission');

-- (a) Admin-defining preservation (V9-and-later variant: soft-deleted roles are excluded).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON p.id IN (UUID_TO_BIN('019f6839-1810-7000-8000-000000000012'), UUID_TO_BIN('019f6839-1810-7000-8000-000000000011'))
WHERE r.deleted_at IS NULL
  AND EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN (UUID_TO_BIN('019f6839-1810-7000-8000-000000000012'), UUID_TO_BIN('019f6839-1810-7000-8000-000000000011')))
  AND NOT EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN (UUID_TO_BIN('019f6839-1810-7000-8000-000000000012'), UUID_TO_BIN('019f6839-1810-7000-8000-000000000011'))
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
