-- permission-migration-footer.sql -- the B7 footer TEMPLATE (US-018 M8 / T-021, 03-design.md 4.7, 10.7).
--
-- NOT a Flyway migration: it lives outside `db/migration` (spring.flyway.locations) and is never run.
-- It is the mandatory footer of EVERY migration that inserts into `permissions`, so that every new
-- permission reaches every role that was already a full administrator stand-in, and every system
-- TENANT_ADMIN (T-T21 / T-E35). PermissionMigrationFooterScannerTest fails the build when a
-- migration that inserts into `permissions` lacks either statement, when statement (a)'s exclusion
-- list differs from exactly the ids that file inserts (RC-48.1), or (from V9) when (a) does not
-- filter `deleted_at IS NULL`.
--
-- HOW TO USE
--   1. Copy the statements between the BEGIN/END markers of the variant you need into your migration,
--      after your `INSERT INTO permissions` statement. Pre-V9 migrations use variant A-PRE-V9;
--      V9 and later use A-V9 (roles gains `deleted_at` in V9). Statement B is the same in both.
--   2. Replace {{INSERTED_PERMISSION_IDS}} (the ONLY placeholder) with the literal id list of the
--      `permissions` rows YOUR file inserts, in the form
--          UUID_TO_BIN('019f6839-1807-7000-8000-000000000008'), UUID_TO_BIN('...')
--      Do NOT copy another migration's footer verbatim: its exclusion list is for its own ids and
--      would silently attach nothing, demoting every custom administrator.
--   3. Keep the statements textually identical to the template apart from the placeholder and
--      whitespace; the scanner compares them.
--
-- ALSO REQUIRED FOR EVERY PERMISSION-ADDING MIGRATION (not scanned; carry them in the runbook/PR)
--   * Semantic IT: seed a FULL-CATALOGUE CUSTOM ROLE before the migration and assert it gains the new
--     permission (RC-48.2); the V6 equivalent is RbacSchemaMigrationIT.
--   * Custom-admin exposure check, before and after deploy: list tenants whose administrators hold
--     only custom roles (ids only) and confirm each still has an administrator afterwards. A tenant
--     that ends at zero is recovered by break-glass (runbook), where a system TENANT_ADMIN is seeded.
--   * Cache flush after the migration applies: permission sets are cached per user; scan and delete
--     `{keyPrefix}:rbac:permset:*` (and `roleset:*`) so holders do not keep a stale set for up to
--     900 s. A migration bumps no revocation epochs, so the epoch-keyed cache does not help here.

-- B7-TEMPLATE-A-PRE-V9-BEGIN
-- (a) Admin-defining preservation (pre-V9 variant, `roles` has no `deleted_at`).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON p.id IN ({{INSERTED_PERMISSION_IDS}})
WHERE EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN ({{INSERTED_PERMISSION_IDS}}))
  AND NOT EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN ({{INSERTED_PERMISSION_IDS}})
          AND NOT EXISTS (
                SELECT 1
                FROM role_permissions rpc
                WHERE rpc.role_id = r.id AND rpc.permission_id = pc.id))
  AND NOT EXISTS (
        SELECT 1
        FROM role_permissions rp
        WHERE rp.role_id = r.id AND rp.permission_id = p.id);
-- B7-TEMPLATE-A-PRE-V9-END

-- B7-TEMPLATE-A-V9-BEGIN
-- (a) Admin-defining preservation (V9-and-later variant: soft-deleted roles are excluded).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON p.id IN ({{INSERTED_PERMISSION_IDS}})
WHERE r.deleted_at IS NULL
  AND EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN ({{INSERTED_PERMISSION_IDS}}))
  AND NOT EXISTS (
        SELECT 1
        FROM permissions pc
        WHERE pc.id NOT IN ({{INSERTED_PERMISSION_IDS}})
          AND NOT EXISTS (
                SELECT 1
                FROM role_permissions rpc
                WHERE rpc.role_id = r.id AND rpc.permission_id = pc.id))
  AND NOT EXISTS (
        SELECT 1
        FROM role_permissions rp
        WHERE rp.role_id = r.id AND rp.permission_id = p.id);
-- B7-TEMPLATE-A-V9-END

-- B7-TEMPLATE-B-BEGIN
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
-- B7-TEMPLATE-B-END
