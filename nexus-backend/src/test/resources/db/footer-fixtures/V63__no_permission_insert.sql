-- Negative/positive fixture for PermissionMigrationFooterScannerTest. Never run by Flyway.
-- insert into permissions (mentioned only in this comment)
INSERT INTO role_permissions (role_id, permission_id) VALUES (UUID_TO_BIN('019f6839-1810-7000-8000-000000000021'), UUID_TO_BIN('019f6839-1810-7000-8000-000000000011'));
