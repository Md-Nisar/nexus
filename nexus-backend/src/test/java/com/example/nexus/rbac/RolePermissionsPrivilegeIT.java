package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
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
import org.springframework.data.jpa.repository.Query;
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
  void should_denyUpdate_atPrivilegeLevel_when_updatingIsSystemRoleAsNexusApp()
      throws SQLException {
    // US-018 C1: name, description and deleted_at became updatable (column-scoped, see
    // RolesPrivilegeIT); is_system_role must stay unwritable, which is the AC7 backstop.
    Role role = seedRole("update-denied");

    assertThatThrownBy(
            () -> {
              try (PreparedStatement update =
                  nexusAppConnection.prepareStatement(
                      "UPDATE roles SET is_system_role = ? WHERE id = ?")) {
                update.setBoolean(1, true);
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
  void should_grantOnlyTheC1ColumnSetOnRolesAndNoUpdateOnRolePermissions_when_showGrants()
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

    // US-018 C1: roles carries exactly the column-scoped UPDATE (name, description, deleted_at),
    // never a table-scoped UPDATE, a column outside that set, or any DELETE.
    rolesGrants.forEach(
        g -> {
          // \b: the column deleted_at is allowed, the DELETE privilege is not.
          assertThat(g.toUpperCase(Locale.ROOT)).as(g).doesNotContainPattern("\\bDELETE\\b");
          if (g.toUpperCase(Locale.ROOT).contains("UPDATE")) {
            assertThat(g).as(g).containsPattern("UPDATE \\(");
            String columns = g.substring(g.indexOf('(') + 1, g.indexOf(')')).replace("`", "");
            assertThat(java.util.Arrays.stream(columns.split(",")).map(String::trim).toList())
                .as(g)
                .isSubsetOf("name", "description", "deleted_at");
          }
        });
    rolePermissionsGrants.forEach(
        g -> assertThat(g.toUpperCase(Locale.ROOT)).as(g).doesNotContain("UPDATE"));
  }

  // ── US-019 B8 (design §10.4): the replace's current reads, as nexus_app ────────────────

  /** The production step-9 read: {@code FOR SHARE} needs SELECT plus DELETE, which nexus_app has. */
  @Test
  void should_readTheCurrentSetForShare_when_lockingOneRolesPermissionsAsNexusApp()
      throws Exception {
    Role role = seedRole("for-share");
    rolePermissionRepository.save(new RolePermission(role.getId(), RbacSeededPermissionIds.ROLE_READ));
    String sql =
        JpaRolePermissionRepository.class
            .getMethod("lockPermissionIdsByRoleId", byte[].class)
            .getAnnotation(Query.class)
            .value()
            .replace(":roleId", "?");

    List<byte[]> ids = new ArrayList<>();
    nexusAppConnection.setAutoCommit(false);
    try (PreparedStatement select = nexusAppConnection.prepareStatement(sql)) {
      select.setBytes(1, toBytes(role.getId()));
      try (ResultSet rs = select.executeQuery()) {
        while (rs.next()) {
          ids.add(rs.getBytes(1));
        }
      }
    }
    nexusAppConnection.rollback();

    assertThat(ids).singleElement().isEqualTo(toBytes(RbacSeededPermissionIds.ROLE_READ));
  }

  /**
   * RC-57.1: the multi-role current read the set-lock verbs use (the production statement of
   * {@code JpaUserRoleRepository#lockRolePermissionsByRoleIds}) is allowed as nexus_app, returns
   * only the tenant's rows, and locks {@code role_permissions} rows only: its tenant join takes no
   * lock on {@code roles} ({@code FOR SHARE OF rp}), so it adds nothing outside RC-46's order.
   */
  @Test
  void should_readSeveralRolesForShareWithoutLockingRoles_when_lockingWithAnInListAsNexusApp()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role first = seedRole("for-share-in-1", tenantId);
    Role second = seedRole("for-share-in-2", tenantId);
    Role foreign = seedRole("for-share-in-foreign");
    rolePermissionRepository.save(new RolePermission(first.getId(), RbacSeededPermissionIds.ROLE_READ));
    rolePermissionRepository.save(new RolePermission(second.getId(), RbacSeededPermissionIds.ROLE_WRITE));
    rolePermissionRepository.save(new RolePermission(foreign.getId(), RbacSeededPermissionIds.ROLE_READ));
    String sql =
        JpaUserRoleRepository.class
            .getMethod("lockRolePermissionsByRoleIds", Collection.class, byte[].class)
            .getAnnotation(Query.class)
            .value()
            .replace(":roleIds", "?, ?, ?")
            .replace(":tenantId", "?");
    assertThat(sql).contains("FOR SHARE OF rp");

    int rows = 0;
    List<String> lockedTables;
    nexusAppConnection.setAutoCommit(false);
    try (PreparedStatement select = nexusAppConnection.prepareStatement(sql)) {
      select.setBytes(1, toBytes(first.getId()));
      select.setBytes(2, toBytes(second.getId()));
      select.setBytes(3, toBytes(foreign.getId()));
      select.setBytes(4, toBytes(tenantId));
      try (ResultSet rs = select.executeQuery()) {
        while (rs.next()) {
          rows++;
        }
      }
      lockedTables = tablesLockedByNexusAppTransaction();
    } finally {
      nexusAppConnection.rollback();
    }

    assertThat(rows).as("the foreign tenant's row is excluded").isEqualTo(2);
    assertThat(lockedTables).contains("role_permissions").doesNotContain("roles");
  }

  /** Tables on which the nexus_app connection's open transaction holds a row lock (read as root). */
  private List<String> tablesLockedByNexusAppTransaction() throws SQLException {
    long threadId;
    try (Statement statement = nexusAppConnection.createStatement();
        ResultSet rs = statement.executeQuery("SELECT CONNECTION_ID()")) {
      rs.next();
      threadId = rs.getLong(1);
    }
    List<String> tables = new ArrayList<>();
    try (Connection observer =
            DriverManager.getConnection(
                mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
        PreparedStatement locks =
            observer.prepareStatement(
                "SELECT DISTINCT l.OBJECT_NAME FROM performance_schema.data_locks l"
                    + " JOIN performance_schema.threads t ON t.THREAD_ID = l.THREAD_ID"
                    + " WHERE t.PROCESSLIST_ID = ? AND l.LOCK_TYPE = 'RECORD'")) {
      locks.setLong(1, threadId);
      try (ResultSet rs = locks.executeQuery()) {
        while (rs.next()) {
          tables.add(rs.getString(1));
        }
      }
    }
    return tables;
  }

  private static void assertCommandDenied(Throwable ex) {
    SQLException sqlEx = (SQLException) ex;
    assertThat(sqlEx.getSQLState()).isEqualTo("42000");
    assertThat(sqlEx.getMessage().toLowerCase(Locale.ROOT)).contains("command denied");
  }

  private Role seedRole(String tag) {
    return seedRole(tag, uuidGenerator.newId());
  }

  private Role seedRole(String tag, UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RPP-" + tag + "-" + UUID.randomUUID(), null, false));
  }

  /** {@code role:write}, per V5__rbac_schema.sql's header comment seeded literals. */
  private UUID anySeededPermissionId() {
    return RbacSeededPermissionIds.ROLE_WRITE;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
