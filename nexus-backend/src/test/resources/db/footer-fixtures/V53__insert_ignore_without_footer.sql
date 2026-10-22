-- Negative/positive fixture for PermissionMigrationFooterScannerTest. Never run by Flyway.
INSERT IGNORE INTO permissions (id, name, description) VALUES
    (UUID_TO_BIN('019f6839-1810-7000-8000-000000000011'), 'fixture:perm0', 'Fixture permission');
