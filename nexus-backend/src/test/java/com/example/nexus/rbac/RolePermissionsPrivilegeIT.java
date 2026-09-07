package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-015 T-010 (04-tasks.md, non-negotiable per 03b-threat-model.md F7): proves the {@code
 * nexus_app} DB-privilege boundary on {@code roles}/{@code role_permissions} that AC7's
 * application-layer-only immutability guard depends on for a DB backstop against an accidental
 * production-only {@code Role} entity dirty-flush (R-6, {@code RoleManagementPort}'s own Javadoc)
 * — every {@code *IT} in this suite connects as the Testcontainers superuser ({@code test}), so
 * this is the ONLY test that can catch such a regression; it fails in production only otherwise.
 *
 * <p>Direct structural mirror of {@code UserRolesPrivilegeIT}: a separate raw JDBC {@link
 * Connection} against the shared {@link MySQLContainer} bean, connected as {@code nexus_app}/
 * {@code nexus_app_test_only}, never the autowired {@code DataSource} (wired to {@code test}).
 * Fixtures are seeded via the regular JPA repositories (connected as {@code test}), with
 * randomized names and {@code is_system_role = false}, per this suite's shared-Spring-context/
 * shared-schema caveat ({@code RbacSchemaMigrationIT}'s Javadoc).
 *
 * <p>The exact MySQL error code for the {@code roles}/{@code role_permissions} {@code UPDATE}
 * denial is deliberately NOT pre-pinned here (unlike {@code UserRolesPrivilegeIT}'s pinned 1143
 * for {@code user_roles}' column-scoped case): both tables have ZERO {@code UPDATE} grant at all
 * (table-level denial, typically MySQL error 1142/ER_TABLEACCESS_DENIED_ERROR, distinct from
 * {@code user_roles}' column-scoped 1143/ER_COLUMNACCESS_DENIED_ERROR) — {@code SQLState=42000}
 * plus a case-insensitive "command denied" message substring is the robust, portable assertion,
 * matching {@code UserRolesPrivilegeIT}'s own first assertion's style.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RolePermissionsPrivilegeIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";

  @Autowired private MySQLContainer<?> mysqlContainer;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;

  private Connection nexusAppConnection;

  @BeforeEach
  void openNexusAppConnection() throws SQLException {
    nexusAppConnection =
        DriverManager.getConnection(
            mysqlContainer.getJdbcUrl(), NEXUS_APP_USER, NEXUS_APP_PASSWORD);
  }

  @AfterEach
  void closeNexusAppConnection() throws SQLException {
    if (nexusAppConnection != null) {
      nexusAppConnection.close();
    }
  }

  @Test
  void should_insertRole_when_insertingIntoRolesAsNexusApp() throws SQLException {
    UUID tenantId = uuidGenerator.newId();
    UUID roleId = uuidGenerator.newId();

    try (PreparedStatement insert =
        nexusAppConnection.prepareStatement(
            "INSERT INTO roles (id, tenant_id, name, is_system_role) VALUES (?, ?, ?, FALSE)")) {
      insert.setBytes(1, toBytes(roleId));
      insert.setBytes(2, toBytes(tenantId));
      insert.setString(3, "RPP-INSERT-" + UUID.randomUUID());
      int rows = insert.executeUpdate();
      assertThat(rows).as("nexus_app must be able to INSERT into roles (AC1)").isEqualTo(1);
    }
  }

  @Test
  void should_denyUpdate_atPrivilegeLevel_when_updatingRoleNameAsNexusApp() throws SQLException {
    Role role = seedRole("update-denied");

    assertThatThrownBy(
            () -> {
              try (PreparedStatement update =
                  nexusAppConnection.prepareStatement(
                      "UPDATE roles SET name = ? WHERE id = ?")) {
                update.setString(1, "RENAMED-" + UUID.randomUUID());
                update.setBytes(2, toBytes(role.getId()));
                update.executeUpdate();
              }
            })
        .isInstanceOf(SQLException.class)
        .satisfies(RolePermissionsPrivilegeIT::assertCommandDenied);
  }

  @Test
  void should_insertAndDeleteRolePermission_when_asNexusApp() throws SQLException {
    Role role = seedRole("rp-insert-delete");
    UUID permissionId = anySeededPermissionId();

    try (PreparedStatement insert =
        nexusAppConnection.prepareStatement(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)")) {
      insert.setBytes(1, toBytes(role.getId()));
      insert.setBytes(2, toBytes(permissionId));
      int inserted = insert.executeUpdate();
      assertThat(inserted).as("nexus_app must be able to INSERT into role_permissions").isEqualTo(1);
    }

    try (PreparedStatement delete =
        nexusAppConnection.prepareStatement(
            "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?")) {
      delete.setBytes(1, toBytes(role.getId()));
      delete.setBytes(2, toBytes(permissionId));
      int deleted = delete.executeUpdate();
      assertThat(deleted).as("nexus_app must be able to DELETE from role_permissions").isEqualTo(1);
    }
  }

  @Test
  void should_denyUpdate_atPrivilegeLevel_when_updatingRolePermissionsAsNexusApp()
      throws SQLException {
    Role role = seedRole("rp-update-denied");
    UUID permissionId = anySeededPermissionId();
    rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));

    assertThatThrownBy(
            () -> {
              try (PreparedStatement update =
                  nexusAppConnection.prepareStatement(
                      "UPDATE role_permissions SET created_at = NOW(6) WHERE role_id = ? AND"
                          + " permission_id = ?")) {
                update.setBytes(1, toBytes(role.getId()));
                update.setBytes(2, toBytes(permissionId));
                update.executeUpdate();
              }
            })
        .isInstanceOf(SQLException.class)
        .satisfies(RolePermissionsPrivilegeIT::assertCommandDenied);
  }

  @Test
  void should_grantNoUpdateAtAll_when_showGrantsForNexusAppOnRolesAndRolePermissions()
      throws SQLException {
    List<String> grants = new ArrayList<>();
    try (Statement statement = nexusAppConnection.createStatement();
        ResultSet rs = statement.executeQuery("SHOW GRANTS FOR 'nexus_app'@'%'")) {
      while (rs.next()) {
        grants.add(rs.getString(1));
      }
    }

    List<String> rolesGrants =
        grants.stream().filter(g -> g.contains("`roles`") || g.contains(".roles")).toList();
    List<String> rolePermissionsGrants =
        grants.stream()
            .filter(g -> g.contains("`role_permissions`") || g.contains(".role_permissions"))
            .toList();
    assertThat(rolesGrants).as("expected at least one GRANT line for roles: " + grants).isNotEmpty();
    assertThat(rolePermissionsGrants)
        .as("expected at least one GRANT line for role_permissions: " + grants)
        .isNotEmpty();

    rolesGrants.forEach(
        g -> assertThat(g.toUpperCase(Locale.ROOT)).as(g).doesNotContain("UPDATE"));
    rolePermissionsGrants.forEach(
        g -> assertThat(g.toUpperCase(Locale.ROOT)).as(g).doesNotContain("UPDATE"));
  }

  private static void assertCommandDenied(Throwable ex) {
    SQLException sqlEx = (SQLException) ex;
    assertThat(sqlEx.getSQLState()).isEqualTo("42000");
    assertThat(sqlEx.getMessage().toLowerCase(Locale.ROOT)).contains("command denied");
  }

  private Role seedRole(String tag) {
    return roleRepository.save(
        new Role(
            uuidGenerator.newId(),
            uuidGenerator.newId(),
            "RPP-" + tag + "-" + UUID.randomUUID(),
            null,
            false));
  }

  /** {@code role:write}, per V5__rbac_schema.sql's header comment seeded literals. */
  private UUID anySeededPermissionId() {
    return UUID.fromString("019f6839-1805-7000-8000-000000000006");
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
