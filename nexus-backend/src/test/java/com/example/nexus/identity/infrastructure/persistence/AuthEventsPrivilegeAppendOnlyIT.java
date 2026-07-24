package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
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
 * US-008 T-08-11 (ADR 0012, closes threat-model T-T3/T-E1): proves append-only enforcement on
 * {@code auth_events} at the DB <b>privilege level</b> — distinct from {@link
 * AuthEventsAppendOnlyIT}, which proves denial via the {@code BEFORE UPDATE}/{@code BEFORE
 * DELETE} triggers. This test connects as {@code nexus_app} (the least-privilege runtime role
 * provisioned by T-08-10) rather than the default Testcontainers application user, so a denied
 * UPDATE/DELETE here fails on the {@code GRANT} check itself — before the trigger body ever
 * runs — and surfaces MySQL's access-denied SQLState class ({@code 42000}), not the trigger's
 * custom {@code SIGNAL SQLSTATE '45000'}.
 *
 * <p>Connects via a raw JDBC {@link Connection} against the shared {@link MySQLContainer} bean
 * (autowired from {@link TestcontainersConfiguration}), using {@code nexus_app}'s credentials —
 * mirroring how {@code TestcontainersConfiguration.nexusAppGrantsCallback} itself opens a
 * separate root connection to apply the grants. The autowired {@code JdbcTemplate}/{@code
 * DataSource} is deliberately NOT used here: it is wired to whatever {@code @ServiceConnection}
 * configured (the container's default application user, "test"), not {@code nexus_app}.
 *
 * <p>Password is a test-only, non-secret placeholder kept in sync with {@code
 * nexus-app-grants.sql} and {@code TestcontainersConfiguration.nexusAppGrantsCallback}.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class AuthEventsPrivilegeAppendOnlyIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";

  @Autowired private MySQLContainer<?> mysqlContainer;
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
  void should_insertAuthEvent_when_connectedAsNexusApp() throws SQLException {
    byte[] id = toBytes(uuidGenerator.newId());

    try (Statement statement = nexusAppConnection.createStatement()) {
      int rows =
          statement.executeUpdate(
              "INSERT INTO auth_events (id, event_type, outcome) VALUES ("
                  + toHexLiteral(id)
                  + ", 'PRIVILEGE_IT_INSERT', 'SUCCESS')");
      assertThat(rows).isEqualTo(1);
    }
  }

  @Test
  void should_selectAuthEvent_when_connectedAsNexusApp() throws SQLException {
    byte[] id = toBytes(uuidGenerator.newId());

    try (Statement insert = nexusAppConnection.createStatement()) {
      insert.executeUpdate(
          "INSERT INTO auth_events (id, event_type, outcome) VALUES ("
              + toHexLiteral(id)
              + ", 'PRIVILEGE_IT_SELECT', 'SUCCESS')");
    }

    try (Statement select = nexusAppConnection.createStatement();
        ResultSet rs =
            select.executeQuery(
                "SELECT outcome FROM auth_events WHERE id = " + toHexLiteral(id))) {
      assertThat(rs.next()).isTrue();
      assertThat(rs.getString("outcome")).isEqualTo("SUCCESS");
    }
  }

  @Test
  void should_denyUpdate_atPrivilegeLevel_when_connectedAsNexusApp() throws SQLException {
    byte[] id = toBytes(uuidGenerator.newId());
    try (Statement insert = nexusAppConnection.createStatement()) {
      insert.executeUpdate(
          "INSERT INTO auth_events (id, event_type, outcome) VALUES ("
              + toHexLiteral(id)
              + ", 'PRIVILEGE_IT_UPDATE', 'SUCCESS')");
    }

    // No UPDATE grant on auth_events for nexus_app at all -> MySQL denies the statement at the
    // privilege-check stage, before the append-only trigger body ever executes. This is the key
    // distinguishing assertion from AuthEventsAppendOnlyIT (SQLState 45000, the trigger's custom
    // SIGNAL): here we expect MySQL's own access-denied class, SQLState 42000.
    assertThatThrownBy(
            () -> {
              try (Statement update = nexusAppConnection.createStatement()) {
                update.executeUpdate(
                    "UPDATE auth_events SET outcome = 'FAILURE' WHERE id = " + toHexLiteral(id));
              }
            })
        .isInstanceOf(SQLException.class)
        .satisfies(
            ex -> {
              SQLException sqlEx = (SQLException) ex;
              assertThat(sqlEx.getSQLState()).isEqualTo("42000");
              assertThat(sqlEx.getMessage().toLowerCase(Locale.ROOT))
                  .contains("command denied");
            });
  }

  @Test
  void should_denyDelete_atPrivilegeLevel_when_connectedAsNexusApp() throws SQLException {
    byte[] id = toBytes(uuidGenerator.newId());
    try (Statement insert = nexusAppConnection.createStatement()) {
      insert.executeUpdate(
          "INSERT INTO auth_events (id, event_type, outcome) VALUES ("
              + toHexLiteral(id)
              + ", 'PRIVILEGE_IT_DELETE', 'SUCCESS')");
    }

    // Same reasoning as the UPDATE case above: no DELETE grant on auth_events for nexus_app,
    // so MySQL denies the statement before the trigger body runs. Expect SQLState 42000, not
    // the trigger's 45000.
    assertThatThrownBy(
            () -> {
              try (Statement delete = nexusAppConnection.createStatement()) {
                delete.executeUpdate("DELETE FROM auth_events WHERE id = " + toHexLiteral(id));
              }
            })
        .isInstanceOf(SQLException.class)
        .satisfies(
            ex -> {
              SQLException sqlEx = (SQLException) ex;
              assertThat(sqlEx.getSQLState()).isEqualTo("42000");
              assertThat(sqlEx.getMessage().toLowerCase(Locale.ROOT))
                  .contains("command denied");
            });
  }

  @Test
  void should_grantExactPrivileges_when_showGrantsForNexusApp() throws SQLException {
    List<String> grants = new ArrayList<>();
    try (Statement statement = nexusAppConnection.createStatement();
        ResultSet rs = statement.executeQuery("SHOW GRANTS FOR 'nexus_app'@'%'")) {
      while (rs.next()) {
        grants.add(rs.getString(1));
      }
    }

    String authEventsGrant =
        grants.stream()
            .filter(g -> g.contains("`auth_events`") || g.contains(".auth_events"))
            .findFirst()
            .orElseThrow(
                () -> new AssertionError("No GRANT line found for auth_events: " + grants));

    // Exactly INSERT, SELECT on auth_events -- no UPDATE/DELETE/DROP/ALTER/GRANT/CREATE.
    assertThat(authEventsGrant).contains("INSERT").contains("SELECT");
    assertThat(authEventsGrant)
        .doesNotContain("UPDATE")
        .doesNotContain("DELETE")
        .doesNotContain("DROP")
        .doesNotContain("ALTER")
        .doesNotContain("GRANT OPTION")
        .doesNotContain("CREATE")
        .doesNotContain("ALL PRIVILEGES");

    for (String table : List.of("users", "refresh_tokens", "auth_tokens")) {
      String tableGrant =
          grants.stream()
              .filter(g -> g.contains("`" + table + "`") || g.contains("." + table))
              .findFirst()
              .orElseThrow(
                  () -> new AssertionError("No GRANT line found for " + table + ": " + grants));

      assertThat(tableGrant)
          .contains("SELECT")
          .contains("INSERT")
          .contains("UPDATE")
          .contains("DELETE");
      assertThat(tableGrant)
          .doesNotContain("DROP")
          .doesNotContain("ALTER")
          .doesNotContain("GRANT OPTION")
          .doesNotContain("CREATE")
          .doesNotContain("ALL PRIVILEGES");
    }

    // No global (*.*) grant beyond USAGE -- i.e. no catch-all privilege was accidentally added.
    String globalGrant =
        grants.stream()
            .filter(g -> g.contains(" ON *.*"))
            .findFirst()
            .orElseThrow(() -> new AssertionError("No global GRANT line found: " + grants));
    assertThat(globalGrant).contains("USAGE");
    assertThat(globalGrant)
        .doesNotContain("ALL PRIVILEGES")
        .doesNotContain("GRANT OPTION")
        .doesNotContain("SUPER")
        .doesNotContain("FILE");
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  /** Renders a 16-byte UUID as a MySQL hex literal, e.g. {@code 0x0123...}. */
  private static String toHexLiteral(byte[] bytes) {
    StringBuilder sb = new StringBuilder("0x");
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
