package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
 * US-018 T-025 (RC-36.2): proves the {@code roles} privilege boundary of C1 as {@code nexus_app},
 * the only identity that can catch a statement that works for the Testcontainers superuser and
 * fails in production (the US-016 D5 trap). It never uses the autowired superuser {@code
 * DataSource} for the statements under test; fixtures are seeded through the JPA repositories.
 *
 * <p>Both grant sets are exercised. The Testcontainers callback applies {@code GRANT UPDATE (name,
 * description, deleted_at) ON nexus.roles}; the pre-grant tests revoke it through a root
 * connection and always re-apply it afterwards ({@link #restoreColumnGrant}).
 *
 * <ul>
 *   <li><b>Pre-grant:</b> assign's conditional {@code INSERT ... SELECT} works (it needs only
 *       {@code SELECT} on {@code roles} and {@code INSERT} on {@code user_roles}); the soft-delete
 *       {@code UPDATE} fails with a privilege error.
 *   <li><b>Post-grant:</b> soft delete and rename work, {@code updated_at} still moves
 *       ({@code ON UPDATE CURRENT_TIMESTAMP} needs no column privilege), the conditional insert
 *       inserts zero rows for a deleted role, and {@code is_system_role}, {@code tenant_id},
 *       {@code id} and any {@code DELETE} stay denied.
 * </ul>
 *
 * The conditional INSERT is the production statement itself, read from the repository's {@code
 * @Query} annotation, so this test cannot drift from the code.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RolesPrivilegeIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final String COLUMN_GRANT =
      "GRANT UPDATE (name, description, deleted_at) ON nexus.roles TO 'nexus_app'@'%'";
  private static final String COLUMN_REVOKE =
      "REVOKE UPDATE (name, description, deleted_at) ON nexus.roles FROM 'nexus_app'@'%'";

  @Autowired private MySQLContainer<?> mysqlContainer;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;

  private Connection nexusApp;

  @BeforeEach
  void openNexusAppConnection() throws SQLException {
    nexusApp =
        DriverManager.getConnection(mysqlContainer.getJdbcUrl(), NEXUS_APP_USER, NEXUS_APP_PASSWORD);
  }

  @AfterEach
  void closeConnectionAndRestoreColumnGrant() throws SQLException {
    if (nexusApp != null) {
      nexusApp.close();
    }
    restoreColumnGrant();
  }

  // ── Pre-grant set ──────────────────────────────────────────────────────────────────────

  @Test
  void should_assignButNotDelete_when_columnGrantIsNotYetApplied() throws Exception {
    rootExecute(COLUMN_REVOKE);
    reconnect();
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    User user = seedUser(tenantId);

    int inserted = conditionalInsert(user.getId(), role.getId(), tenantId, user.getId());

    assertThat(inserted).as("assign works under the pre-grant set").isEqualTo(1);
    assertThatThrownBy(() -> softDelete(role.getId(), tenantId))
        .isInstanceOf(SQLException.class)
        .satisfies(RolesPrivilegeIT::assertCommandDenied);
  }

  // ── Post-grant set ─────────────────────────────────────────────────────────────────────

  @Test
  void should_softDeleteAndRename_and_moveUpdatedAt_when_columnGrantIsApplied() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    Timestamp before = updatedAt(role.getId());
    Thread.sleep(20);

    int renamed = rename(role.getId(), tenantId, "RPIT-RENAMED-" + UUID.randomUUID(), "new text");
    int deleted = softDelete(role.getId(), tenantId);

    assertThat(renamed).isEqualTo(1);
    assertThat(deleted).isEqualTo(1);
    assertThat(updatedAt(role.getId()))
        .as("updated_at must move without any column privilege on it")
        .isAfter(before);
    assertThat(softDelete(role.getId(), tenantId)).as("second delete matches no row").isZero();
  }

  @Test
  void should_insertNoRow_when_assigningToASoftDeletedRoleAsNexusApp() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    User user = seedUser(tenantId);
    softDelete(role.getId(), tenantId);

    int inserted = conditionalInsert(user.getId(), role.getId(), tenantId, user.getId());

    assertThat(inserted).as("RC-36.1: a deleted role takes no new holder").isZero();
  }

  @Test
  void should_denyIsSystemRoleTenantIdIdAndDelete_when_columnGrantIsApplied() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);

    for (String sql :
        List.of(
            "UPDATE roles SET is_system_role = TRUE WHERE id = ?",
            "UPDATE roles SET tenant_id = tenant_id WHERE id = ?",
            "UPDATE roles SET id = id WHERE id = ?",
            "DELETE FROM roles WHERE id = ?")) {
      assertThatThrownBy(
              () -> {
                try (PreparedStatement statement = nexusApp.prepareStatement(sql)) {
                  statement.setBytes(1, toBytes(role.getId()));
                  statement.executeUpdate();
                }
              })
          .as(sql)
          .isInstanceOf(SQLException.class)
          .satisfies(RolesPrivilegeIT::assertCommandDenied);
    }
  }

  // ── US-019 B8 (design §10.4, AS-1): the replace's role-row lock, as nexus_app ──────────

  /**
   * The production {@code FOR UPDATE} on the live role row succeeds under the column-scoped
   * {@code UPDATE} grant, and a second {@code nexus_app} connection running it blocks (lock wait
   * timeout 1205 with a 1 s timeout) until the first commits, after which it gets the lock.
   */
  @Test
  void should_lockTheLiveRoleRowAndBlockASecondLocker_when_selectingForUpdateAsNexusApp()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    nexusApp.setAutoCommit(false);

    assertThat(lockRoleRow(nexusApp, role.getId(), tenantId)).as("the first locker").isTrue();

    try (Connection second =
        DriverManager.getConnection(
            mysqlContainer.getJdbcUrl(), NEXUS_APP_USER, NEXUS_APP_PASSWORD)) {
      second.setAutoCommit(false);
      try (Statement statement = second.createStatement()) {
        statement.execute("SET SESSION innodb_lock_wait_timeout = 1");
      }
      assertThatThrownBy(() -> lockRoleRow(second, role.getId(), tenantId))
          .as("a second locker must wait for the first")
          .isInstanceOf(SQLException.class)
          .satisfies(e -> assertThat(((SQLException) e).getErrorCode()).isEqualTo(1205));
      second.rollback();

      nexusApp.commit();

      assertThat(lockRoleRow(second, role.getId(), tenantId))
          .as("after the first commits, the second gets the lock")
          .isTrue();
      second.rollback();
    }
  }

  @Test
  void should_returnNoRow_when_lockingASoftDeletedRoleAsNexusApp() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    softDelete(role.getId(), tenantId);

    assertThat(lockRoleRow(nexusApp, role.getId(), tenantId)).isFalse();
  }

  @Test
  void should_returnNoRow_when_lockingARoleOfAnotherTenantAsNexusApp() throws Exception {
    Role role = seedRole(uuidGenerator.newId());

    assertThat(lockRoleRow(nexusApp, role.getId(), uuidGenerator.newId())).isFalse();
  }

  // ── Statements under test, as nexus_app ────────────────────────────────────────────────

  /** The production {@code lockLiveRoleRow} statement, taken from its @Query annotation. */
  private static boolean lockRoleRow(Connection connection, UUID roleId, UUID tenantId)
      throws Exception {
    String named =
        JpaRoleRepository.class
            .getMethod("lockLiveRoleRow", byte[].class, byte[].class)
            .getAnnotation(Query.class)
            .value();
    Map<String, byte[]> values = Map.of("roleId", toBytes(roleId), "tenantId", toBytes(tenantId));
    List<String> order = new ArrayList<>();
    Matcher matcher = Pattern.compile(":(\\w+)").matcher(named);
    StringBuilder positional = new StringBuilder();
    while (matcher.find()) {
      order.add(matcher.group(1));
      matcher.appendReplacement(positional, "?");
    }
    matcher.appendTail(positional);
    try (PreparedStatement statement = connection.prepareStatement(positional.toString())) {
      for (int i = 0; i < order.size(); i++) {
        statement.setBytes(i + 1, values.get(order.get(i)));
      }
      try (ResultSet rs = statement.executeQuery()) {
        return rs.next();
      }
    }
  }

  private int softDelete(UUID roleId, UUID tenantId) throws SQLException {
    try (PreparedStatement statement =
        nexusApp.prepareStatement(
            "UPDATE roles SET deleted_at = ? WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL")) {
      statement.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
      statement.setBytes(2, toBytes(roleId));
      statement.setBytes(3, toBytes(tenantId));
      return statement.executeUpdate();
    }
  }

  private int rename(UUID roleId, UUID tenantId, String name, String description)
      throws SQLException {
    try (PreparedStatement statement =
        nexusApp.prepareStatement(
            "UPDATE roles SET name = ?, description = ? "
                + "WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL")) {
      statement.setString(1, name);
      statement.setString(2, description);
      statement.setBytes(3, toBytes(roleId));
      statement.setBytes(4, toBytes(tenantId));
      return statement.executeUpdate();
    }
  }

  /** The production INSERT ... SELECT, taken from the repository's @Query so it cannot drift. */
  private int conditionalInsert(UUID userId, UUID roleId, UUID tenantId, UUID assignedBy)
      throws Exception {
    String named =
        JpaUserRoleRepository.class
            .getMethod(
                "assignIfRoleLive",
                byte[].class, byte[].class, byte[].class, byte[].class, byte[].class)
            .getAnnotation(Query.class)
            .value();
    Map<String, byte[]> values =
        Map.of(
            "id", toBytes(uuidGenerator.newId()),
            "userId", toBytes(userId),
            "roleId", toBytes(roleId),
            "tenantId", toBytes(tenantId),
            "assignedBy", toBytes(assignedBy));
    List<String> order = new ArrayList<>();
    Matcher matcher = Pattern.compile(":(\\w+)").matcher(named);
    StringBuilder positional = new StringBuilder();
    while (matcher.find()) {
      order.add(matcher.group(1));
      matcher.appendReplacement(positional, "?");
    }
    matcher.appendTail(positional);
    try (PreparedStatement statement = nexusApp.prepareStatement(positional.toString())) {
      for (int i = 0; i < order.size(); i++) {
        statement.setBytes(i + 1, values.get(order.get(i)));
      }
      return statement.executeUpdate();
    }
  }

  // ── Fixtures and plumbing ──────────────────────────────────────────────────────────────

  private Timestamp updatedAt(UUID roleId) throws SQLException {
    try (Connection root = rootConnection();
        PreparedStatement statement =
            root.prepareStatement("SELECT updated_at FROM nexus.roles WHERE id = ?")) {
      statement.setBytes(1, toBytes(roleId));
      try (ResultSet rs = statement.executeQuery()) {
        assertThat(rs.next()).isTrue();
        return rs.getTimestamp(1);
      }
    }
  }

  private void reconnect() throws SQLException {
    nexusApp.close();
    nexusApp =
        DriverManager.getConnection(mysqlContainer.getJdbcUrl(), NEXUS_APP_USER, NEXUS_APP_PASSWORD);
  }

  private void restoreColumnGrant() throws SQLException {
    rootExecute(COLUMN_GRANT);
  }

  private void rootExecute(String sql) throws SQLException {
    try (Connection root = rootConnection();
        Statement statement = root.createStatement()) {
      statement.execute(sql);
      statement.execute("FLUSH PRIVILEGES");
    }
  }

  private Connection rootConnection() throws SQLException {
    return DriverManager.getConnection(
        mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
  }

  private Role seedRole(UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RPIT-" + UUID.randomUUID(), null, false));
  }

  private User seedUser(UUID tenantId) {
    String email = "rpit-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private static void assertCommandDenied(Throwable ex) {
    SQLException sqlEx = (SQLException) ex;
    assertThat(sqlEx.getSQLState()).isEqualTo("42000");
    assertThat(sqlEx.getMessage().toLowerCase(Locale.ROOT)).contains("command denied");
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
