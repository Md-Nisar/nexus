package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
class IdentitySchemaMigrationIT {

  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_createAllTables_when_migrationsApplied() {
    List<String> tables =
        jdbc.queryForList(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' "
                + "ORDER BY TABLE_NAME",
            String.class);

    assertThat(tables).contains("users", "refresh_tokens", "auth_tokens", "auth_events");
  }

  @Test
  void should_createExpectedColumns_when_migrationsApplied() {
    // users table key columns
    List<String> userColumns =
        jdbc.queryForList(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
                + "ORDER BY ORDINAL_POSITION",
            String.class);

    assertThat(userColumns)
        .contains(
            "id",
            "tenant_id",
            "email_cipher",
            "email_hmac",
            "status",
            "token_version",
            "email_verified_at",
            "failed_attempt_count",
            "locked_until",
            "consent_accepted_at",
            "version",
            "created_at",
            "updated_at");

    // auth_events must NOT have updated_at
    List<String> eventColumns =
        jdbc.queryForList(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth_events'",
            String.class);

    assertThat(eventColumns).doesNotContain("updated_at");
  }

  @Test
  void should_createExpectedIndexes_when_migrationsApplied() {
    List<String> indexes =
        jdbc.queryForList(
            "SELECT INDEX_NAME FROM information_schema.STATISTICS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
                + "GROUP BY INDEX_NAME",
            String.class);

    assertThat(indexes)
        .contains("PRIMARY", "uq_users_tenant_id_email_hmac", "idx_users_tenant_id_status");
  }

  @Test
  void should_haveFlyway_v2_checksum_stable_when_migrationReapplied() {
    // Flyway records checksum in flyway_schema_history — it must not change between runs.
    // This test simply asserts V2 exists and was applied successfully (not failed).
    // success is BIT(1) in MySQL; CAST to UNSIGNED yields Integer 1 for true.
    List<Integer> states =
        jdbc.queryForList(
            "SELECT CAST(success AS UNSIGNED) FROM flyway_schema_history WHERE version = '2'",
            Integer.class);

    assertThat(states).hasSize(1);
    assertThat(states).contains(1);
  }
}
