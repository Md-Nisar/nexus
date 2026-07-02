-- mysql/init/02-grants-post-schema.sql
-- US-008 T-08-10 (ADR 0012): table-scoped grants for nexus_app, applied AFTER the identity
-- schema exists (empirically verified: GRANT ... ON db.table fails with ERROR 1146 if the
-- table doesn't exist yet on mysql:8.4).
--
-- NOT mounted into /docker-entrypoint-initdb.d (that fires before Flyway ever runs — see
-- 01-grants.sql). This file is executed by the one-shot `flyway-migrate` compose service, as
-- root, immediately after Flyway completes its migration run. It is mounted into that
-- service's Flyway -locations directory AS "afterMigrate.sql" (see docker-compose.yml) —
-- Flyway auto-discovers and runs any file literally named afterMigrate.sql in its locations
-- directory as a SQL callback, once, right after `migrate` finishes, using Flyway's own root
-- JDBC connection. This was chosen over a separate `mysql` CLI invocation because the official
-- flyway/flyway image does not bundle a mysql client (empirically confirmed) — the SQL-callback
-- mechanism needs nothing beyond what Flyway itself already provides.
--
-- Idempotent: GRANT is safe to re-run (re-issuing the same grant is a no-op), so this can be
-- executed on every `flyway-migrate` run without side effects.
--
-- Exactly matches ADR 0012 §1's grant shape. Never add DDL (CREATE/ALTER/DROP/GRANT) to this
-- user — ADR 0012 §3.

-- auth_events: append + read only -- privilege-level backstop to the existing triggers
GRANT INSERT, SELECT ON nexus.auth_events TO 'nexus_app'@'%';

-- other identity tables: normal DML, no DDL
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.users          TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.refresh_tokens TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.auth_tokens    TO 'nexus_app'@'%';

FLUSH PRIVILEGES;
