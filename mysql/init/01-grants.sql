-- mysql/init/01-grants.sql
-- US-008 T-08-10 (ADR 0012): provision the least-privilege runtime DB user for local dev.
--
-- Mounted into /docker-entrypoint-initdb.d, so it runs once, as root, the first time the
-- nexus-mysql container initializes an empty data directory. CREATE USER succeeds here even
-- though no tables exist yet; the auth_events/users/refresh_tokens/auth_tokens tables ARE
-- created later by this same script only if they already exist by the time this file runs.
--
-- IMPORTANT (empirically verified against mysql:8.4): GRANT ... ON db.table FAILS with
-- ERROR 1146 if the target table does not exist yet. In docker-entrypoint-initdb.d, scripts
-- run in filename order BEFORE the application (and therefore Flyway) ever connects, so the
-- identity schema does not exist when this file executes. This script therefore only creates
-- the user; the table-scoped GRANTs are applied by the one-shot `flyway-migrate` compose
-- service AFTER Flyway has created the schema (see docker-compose.yml `nexus_app-grants`
-- command step). Do not add table-scoped GRANT statements here — they will fail on a fresh
-- volume and silently no-op (or error and abort init) rather than provision correctly.
--
-- Password: dev-only, non-secret, matches the existing MYSQL_ROOT_PASSWORD placeholder
-- pattern (see application-dev.yml). Sourced from docker-compose.yml's
-- NEXUS_APP_DB_PASSWORD env var (default: nexus_app_dev_only) via envsubst-free direct
-- literal below — docker-entrypoint-initdb.d scripts are not templated, so the literal here
-- must be kept in sync with docker-compose.yml's default. Override both together if changed.
--
-- Never grant nexus_app DDL (CREATE/ALTER/DROP/GRANT) — ADR 0012 §3.

CREATE USER IF NOT EXISTS 'nexus_app'@'%' IDENTIFIED BY 'nexus_app_dev_only';
FLUSH PRIVILEGES;
