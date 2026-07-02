package com.example.nexus.identity.infrastructure.audit;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * US-008 T-08-12 (ADR 0012 §5, threat model T-E2/T-T4) — a runtime self-check that detects
 * whether the application's live DB connection has drifted away from the intended least-privilege
 * {@code nexus_app} role (T-08-10/ADR 0012 §1).
 *
 * <p>This indicator is <b>observational only</b>: per the accepted residual documented in ADR
 * 0012 §4 (T-T4), it cannot constrain a DB superuser and does not attempt to. It never issues a
 * live {@code UPDATE}/{@code DELETE} against {@code auth_events} to "test" the grant — that would
 * be destructive against a real audit table. Instead it inspects {@code information_schema}
 * metadata for the currently connected user:
 *
 * <ul>
 *   <li>a fast-path check: is the connected user literally {@code root}?
 *   <li>{@code information_schema.TABLE_PRIVILEGES} — does the connected user hold a
 *       table-scoped {@code UPDATE} or {@code DELETE} grant on {@code auth_events}?
 *   <li>{@code information_schema.USER_PRIVILEGES} — does the connected user hold a global
 *       {@code UPDATE}, {@code DELETE}, or {@code ALL PRIVILEGES} grant (the {@code root}-style
 *       {@code GRANT ... ON *.*} shape, which never appears as a table-scoped row)?
 * </ul>
 *
 * <p>Registered as a plain, named {@link HealthIndicator} bean ({@code authEventDbPrivilege}) —
 * it is deliberately <b>excluded from the liveness/readiness groups</b> (see {@code
 * application.yml} {@code management.endpoint.health.group.*.include}) so a detected drift is
 * visible on {@code /actuator/health} and via the WARN log line below, without flipping the
 * aggregate health status and risking a pod restart over what is explicitly a non-fatal
 * security-observability signal, not an availability concern.
 */
@Component("authEventDbPrivilege")
public class AuthEventDbPrivilegeHealthIndicator implements HealthIndicator {

  private static final Logger log =
      LoggerFactory.getLogger(AuthEventDbPrivilegeHealthIndicator.class);

  private static final String AUDIT_TABLE = "auth_events";

  private final DataSource dataSource;

  public AuthEventDbPrivilegeHealthIndicator(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public Health health() {
    try (Connection connection = dataSource.getConnection()) {
      String currentUser = readCurrentUser(connection);
      String userName = usernamePart(currentUser);
      boolean isRoot = "root".equalsIgnoreCase(userName);
      boolean hasTablePrivilege = hasTableUpdateOrDeletePrivilege(connection, userName);
      boolean hasGlobalPrivilege = hasGlobalUpdateOrDeletePrivilege(connection, userName);
      boolean overPrivileged = isRoot || hasTablePrivilege || hasGlobalPrivilege;

      if (overPrivileged) {
        log.warn(
            "auth_events DB privilege drift detected dbUser={} isRoot={} "
                + "hasTableUpdateOrDeleteGrant={} hasGlobalUpdateOrDeleteGrant={}",
            currentUser,
            isRoot,
            hasTablePrivilege,
            hasGlobalPrivilege);
        return Health.down()
            .withDetail("dbUser", currentUser)
            .withDetail("isRoot", isRoot)
            .withDetail("hasTableUpdateOrDeleteGrant", hasTablePrivilege)
            .withDetail("hasGlobalUpdateOrDeleteGrant", hasGlobalPrivilege)
            .withDetail(
                "issue",
                "connected DB user can UPDATE/DELETE auth_events — least-privilege nexus_app"
                    + " provisioning (ADR 0012) has drifted or was never applied")
            .build();
      }
      return Health.up().withDetail("dbUser", currentUser).build();
    } catch (SQLException e) {
      // The self-check itself must never fail the app or throw — an inconclusive check is
      // reported as UNKNOWN, not treated as either a pass or a drift finding.
      log.warn("auth_events DB privilege self-check failed to execute: {}", e.getMessage());
      return Health.unknown()
          .withDetail("issue", "privilege self-check could not run: " + e.getMessage())
          .build();
    }
  }

  private String readCurrentUser(Connection connection) throws SQLException {
    try (Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery("SELECT CURRENT_USER()")) {
      if (resultSet.next()) {
        return resultSet.getString(1);
      }
      throw new SQLException("SELECT CURRENT_USER() returned no rows");
    }
  }

  private String usernamePart(String currentUser) {
    if (currentUser == null) {
      return "";
    }
    int at = currentUser.indexOf('@');
    return at >= 0 ? currentUser.substring(0, at) : currentUser;
  }

  /**
   * Table-scoped grant check via {@code information_schema.TABLE_PRIVILEGES}. Matches on the
   * quoted username substring within {@code GRANTEE} (e.g. {@code 'nexus_app'@'%'}) rather than
   * reconstructing the exact quoted-host string, which is fragile across host-wildcard forms.
   */
  private boolean hasTableUpdateOrDeletePrivilege(Connection connection, String userName)
      throws SQLException {
    String sql =
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = ? "
            + "AND PRIVILEGE_TYPE IN ('UPDATE', 'DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?";
    try (var preparedStatement = connection.prepareStatement(sql)) {
      preparedStatement.setString(1, AUDIT_TABLE);
      preparedStatement.setString(2, "'" + userName + "'@%");
      try (ResultSet resultSet = preparedStatement.executeQuery()) {
        return resultSet.next() && resultSet.getInt(1) > 0;
      }
    }
  }

  /**
   * Global grant check via {@code information_schema.USER_PRIVILEGES} — catches a
   * {@code root}-style {@code GRANT ... ON *.*} that never produces a table-scoped row.
   */
  private boolean hasGlobalUpdateOrDeletePrivilege(Connection connection, String userName)
      throws SQLException {
    String sql =
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES "
            + "WHERE PRIVILEGE_TYPE IN ('UPDATE', 'DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?";
    try (var preparedStatement = connection.prepareStatement(sql)) {
      preparedStatement.setString(1, "'" + userName + "'@%");
      try (ResultSet resultSet = preparedStatement.executeQuery()) {
        return resultSet.next() && resultSet.getInt(1) > 0;
      }
    }
  }
}
