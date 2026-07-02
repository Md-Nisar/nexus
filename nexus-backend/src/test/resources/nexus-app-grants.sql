-- nexus-app-grants.sql
-- US-008 T-08-10 (ADR 0012): create the nexus_app runtime user for Testcontainers *IT.
--
-- Copied into /docker-entrypoint-initdb.d by TestcontainersConfiguration
-- (withCopyFileToContainer), MySQL's OWN first-boot init mechanism, which runs as root before
-- any JDBC connection is accepted. This is deliberately NOT
-- MySQLContainer.withInitScript(...): that Testcontainers convenience method executes its
-- script over JDBC using the container's configured application user ("test"), which lacks
-- CREATE USER privilege and fails with "Access denied; you need (at least one of) the CREATE
-- USER privilege(s)" -- empirically confirmed when this was first tried. CREATE USER has no
-- dependency on the identity schema, so it is safe to run here, before Flyway has migrated
-- anything.
--
-- Table-scoped GRANTs are intentionally NOT in this file: empirically verified (mysql:8.4)
-- that GRANT ... ON db.table fails with ERROR 1146 if the table does not exist yet, and the
-- identity schema does not exist until Flyway runs as part of Spring context startup, which
-- happens strictly after this init script. The GRANTs are applied by a Flyway afterMigrate
-- Callback bean in TestcontainersConfiguration, which fires exactly once, right after
-- migrations complete, using the same container's root connection.
--
-- Password: test-only, non-secret placeholder — never used outside the ephemeral Testcontainers
-- MySQL instance, which is destroyed at the end of the test JVM. Kept in sync with the Callback
-- bean in TestcontainersConfiguration.java, which issues the matching GRANT statements.
--
-- Never grant nexus_app DDL (CREATE/ALTER/DROP/GRANT) — ADR 0012 §3.

CREATE USER IF NOT EXISTS 'nexus_app'@'%' IDENTIFIED BY 'nexus_app_test_only';
FLUSH PRIVILEGES;
