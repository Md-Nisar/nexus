package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.UserRole;
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
 * US-012 T-001 (03-design.md §5.3, closes R-4/O-1 and guards against T-E12): proves the {@code
 * nexus_app} DB-privilege boundary that US-012's whole locking-read design depends on — connecting
 * as {@code nexus_app} (the least-privilege runtime role), never the default Testcontainers
 * application user ({@code test}) every other {@code *IT} in this suite uses.
 *
 * <p>This was originally scoped as a blocking discovery task; the threat model already resolved
 * the underlying question empirically against a throwaway container (03-design.md §5.3), so this
 * class codifies that result as a permanent regression assertion rather than re-discovering it. If
 * assertion 3 below ever unexpectedly fails, stop and re-open §5.3's decision tree rather than
 * silently adjusting this test (04-tasks.md T-001 "Risks").
 *
 * <p>Modeled directly on {@code
 * identity.infrastructure.persistence.AuthEventsPrivilegeAppendOnlyIT} — same raw JDBC {@link
 * Connection} against the shared {@link MySQLContainer} bean (autowired from {@link
 * TestcontainersConfiguration}), same {@code nexus_app} credentials, same rationale for bypassing
 * the autowired {@code DataSource} (wired to {@code test}, not {@code nexus_app}). Fixtures are
 * seeded via the regular JPA repositories (autowired, connected as {@code test}) — the same
 * seeding style {@code ActiveAssignmentIT} uses — with randomized names and {@code
 * is_system_role = false}, per this suite's shared-Spring-context/shared-schema caveat ({@code
 * RbacSchemaMigrationIT}'s Javadoc) so as not to collide with other tests' scoped seed-count
 * assertions.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class UserRolesPrivilegeIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");

  @Autowired private MySQLContainer<?> mysqlContainer;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
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
  void should_revokeActiveAssignment_when_updatingRevokedAtColumnAsNexusApp() throws SQLException {
    UserRole assignment = seedActiveAssignment("revoke-ok");

    try (PreparedStatement update =
        nexusAppConnection.prepareStatement(
            "UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ?")) {
      update.setBytes(1, toBytes(assignment.getId()));
      int rows = update.executeUpdate();
      assertThat(rows)
          .as("nexus_app must be able to revoke via the column-scoped UPDATE (revoked_at) grant")
          .isEqualTo(1);
    }
  }

  @Test
  void should_denyUpdate_atPrivilegeLevel_when_updatingNonRevokedAtColumnAsNexusApp()
      throws SQLException {
    UserRole assignment = seedActiveAssignment("denied-column");

    // tenant_id has no UPDATE grant at all for nexus_app -- only revoked_at does (03-design.md
    // §5.3 assertion 2). MySQL denies the statement at the privilege-check stage, before any
    // FK/constraint validation of the supplied value ever runs, so an arbitrary random UUID is
    // a valid probe value here.
    assertThatThrownBy(
            () -> {
              try (PreparedStatement update =
                  nexusAppConnection.prepareStatement(
                      "UPDATE user_roles SET tenant_id = ? WHERE id = ?")) {
                update.setBytes(1, toBytes(UUID.randomUUID()));
                update.setBytes(2, toBytes(assignment.getId()));
                update.executeUpdate();
              }
            })
        .isInstanceOf(SQLException.class)
        .satisfies(
            ex -> {
              SQLException sqlEx = (SQLException) ex;
              assertThat(sqlEx.getErrorCode()).isEqualTo(1143);
              assertThat(sqlEx.getSQLState()).isEqualTo("42000");
              assertThat(sqlEx.getMessage().toLowerCase(Locale.ROOT)).contains("command denied");
            });
  }

  @Test
  void should_allowLockingRead_when_selectingActiveAssignmentForUpdateAsNexusApp()
      throws SQLException {
    UserRole assignment = seedActiveAssignment("locking-read-ok");

    try (PreparedStatement select =
        nexusAppConnection.prepareStatement(
            "SELECT id FROM user_roles WHERE role_id = ? AND tenant_id = ?"
                + " AND revoked_at IS NULL FOR UPDATE")) {
      select.setBytes(1, toBytes(assignment.getRoleId()));
      select.setBytes(2, toBytes(TENANT_ID));
      try (ResultSet rs = select.executeQuery()) {
        assertThat(rs.next())
            .as("the locking read must return the pre-seeded active row, not throw")
            .isTrue();
        assertThat(rs.getBytes("id")).isEqualTo(toBytes(assignment.getId()));
      }
    }
  }

  @Test
  void should_grantColumnScopedUpdateOnly_when_showGrantsForNexusApp() throws SQLException {
    List<String> grants = new ArrayList<>();
    try (Statement statement = nexusAppConnection.createStatement();
        ResultSet rs = statement.executeQuery("SHOW GRANTS FOR 'nexus_app'@'%'")) {
      while (rs.next()) {
        grants.add(rs.getString(1));
      }
    }

    List<String> userRoleGrants =
        grants.stream()
            .filter(g -> g.contains("`user_roles`") || g.contains(".user_roles"))
            .toList();
    assertThat(userRoleGrants)
        .as("expected at least one GRANT line for user_roles: " + grants)
        .isNotEmpty();

    // The mandatory assertion (04-tasks.md T-001 / 03-design.md §5.3): UPDATE on user_roles must
    // be scoped to the revoked_at column specifically -- this is the assertion that would catch
    // a future silent grant-widening regression (threat T-E12) that assertions 1 and 3 alone
    // would not (a table-scoped UPDATE would also pass both of those).
    long columnScopedUpdateLines =
        userRoleGrants.stream()
            .filter(
                g ->
                    g.toUpperCase(Locale.ROOT)
                        .matches(".*UPDATE\\s*\\([^)]*REVOKED_AT[^)]*\\).*"))
            .count();
    assertThat(columnScopedUpdateLines)
        .as(
            "expected exactly one column-scoped UPDATE (revoked_at) grant on user_roles: "
                + userRoleGrants)
        .isEqualTo(1);

    // No line may grant a bare, table-scoped UPDATE (UPDATE not immediately followed by a column
    // list) on user_roles -- a silent reversion to table-scoped UPDATE would pass assertions 1
    // and 3 above while quietly re-opening the R-1 load-mutate-save hazard D2 exists to close.
    boolean tableScopedUpdatePresent =
        userRoleGrants.stream()
            .anyMatch(g -> g.toUpperCase(Locale.ROOT).matches(".*\\bUPDATE\\b(?!\\s*\\().*"));
    assertThat(tableScopedUpdatePresent)
        .as("UPDATE on user_roles must never be table-scoped (bare UPDATE keyword): " + userRoleGrants)
        .isFalse();

    // Defense-in-depth: the table-level line must carry no write privilege beyond SELECT/INSERT.
    userRoleGrants.stream()
        .filter(g -> !g.toUpperCase(Locale.ROOT).contains("UPDATE ("))
        .forEach(
            g ->
                assertThat(g)
                    .doesNotContain("DELETE")
                    .doesNotContain("DROP")
                    .doesNotContain("ALTER")
                    .doesNotContain("GRANT OPTION")
                    .doesNotContain("ALL PRIVILEGES"));
  }

  private User seedUser(String tag) {
    String email = "urp-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag) {
    // is_system_role=false, randomized name: keeps RbacSchemaMigrationIT's scoped seed-role
    // count stable regardless of test execution order (see that class's Javadoc).
    return roleRepository.save(
        new Role(
            uuidGenerator.newId(),
            uuidGenerator.newId(),
            "URP-" + tag + "-" + UUID.randomUUID(),
            null,
            false));
  }

  private UserRole seedActiveAssignment(String tag) {
    User assignee = seedUser(tag + "-assignee");
    User assigner = seedUser(tag + "-assigner");
    Role role = seedRole(tag);
    return userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), assignee.getId(), role.getId(), TENANT_ID, assigner.getId()));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
