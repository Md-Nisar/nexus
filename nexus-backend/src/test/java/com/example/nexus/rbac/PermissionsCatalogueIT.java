package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.security.Permissions;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * B5 Test 2 (US-018 T-022, TS-13, FR-B5.b): {@link Permissions#ALL} equals the {@code permissions}
 * table after Flyway has run. Fixture permissions that sibling ITs insert into the shared schema
 * all use the {@code rt:} prefix and are removed by their own cleanup; they are excluded here so
 * the comparison does not depend on test order.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class PermissionsCatalogueIT {

  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_equalPermissionsTable_when_flywayHasRun() {
    List<String> names =
        jdbc.queryForList(
            "SELECT name FROM permissions WHERE name NOT LIKE 'rt:%'", String.class);

    assertThat(names).containsExactlyInAnyOrderElementsOf(Permissions.ALL);
  }

  /** US-019 T-001: V11 grows the catalogue to nine with {@code user:directory:read}. */
  @Test
  void should_holdNinePermissionsIncludingDirectoryRead_when_flywayHasRun() {
    List<String> names =
        jdbc.queryForList(
            "SELECT name FROM permissions WHERE name NOT LIKE 'rt:%'", String.class);

    assertThat(names).hasSize(9).contains(Permissions.USER_DIRECTORY_READ);
  }
}
