package com.example.nexus.rbac.infrastructure.health;

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
 * US-010 AC10 (forward-tracked from US-009's Gate-2 threat model T-E3) — a runtime self-check
 * mirroring {@code AuthEventDbPrivilegeHealthIndicator}: detects whether the live DB connection
 * has drifted away from {@code nexus_app}'s intended least-privilege grants on {@code
 * user_roles}. Testcontainers ITs run as the container's default user, not {@code nexus_app}, so
 * this is the only runtime detection for a still-on-{@code root} environment or an over-grant.
 *
 * <p>Unlike the {@code auth_events} indicator (which checks {@code UPDATE} or {@code DELETE}),
 * this checks only {@code DELETE} — {@code nexus_app} intentionally holds a column-scoped {@code
 * UPDATE (revoked_at)} grant on {@code user_roles} (ADR-0015 D7), which must not itself trigger a
 * finding here.
 *
 * <p>Observational only (cannot constrain a DB superuser); never issues a live {@code DELETE}
 * against {@code user_roles} to "test" the grant. Registered as a named {@link HealthIndicator}
 * bean ({@code rbacDbPrivilege}), excluded from the liveness/readiness groups (not added to
 * {@code application.yml}'s {@code management.endpoint.health.group.*.include} lists) but left
 * visible on the aggregate {@code /actuator/health} — a DB-grant drift stays UP the overwhelming
 * majority of the time, so it is not treated like Redis's routine-absence exclusion.
 */
@Component("rbacDbPrivilege")
public class RbacDbPrivilegeHealthIndicator implements HealthIndicator {

  private static final Logger log = LoggerFactory.getLogger(RbacDbPrivilegeHealthIndicator.class);

  private static final String USER_ROLES_TABLE = "user_roles";

  private final DataSource dataSource;

  public RbacDbPrivilegeHealthIndicator(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public Health health() {
    try (Connection connection = dataSource.getConnection()) {
      String currentUser = readCurrentUser(connection);
      String userName = usernamePart(currentUser);
      boolean isRoot = "root".equalsIgnoreCase(userName);
      boolean hasTablePrivilege = hasTableDeletePrivilege(connection, userName);
      boolean hasGlobalPrivilege = hasGlobalDeletePrivilege(connection, userName);
      boolean overPrivileged = isRoot || hasTablePrivilege || hasGlobalPrivilege;

      if (overPrivileged) {
        log.warn(
            "user_roles DB privilege drift detected dbUser={} isRoot={} "
                + "hasTableDeleteGrant={} hasGlobalDeleteGrant={}",
            currentUser,
            isRoot,
            hasTablePrivilege,
            hasGlobalPrivilege);
        return Health.down()
            .withDetail("dbUser", currentUser)
            .withDetail("isRoot", isRoot)
            .withDetail("hasTableDeleteGrant", hasTablePrivilege)
            .withDetail("hasGlobalDeleteGrant", hasGlobalPrivilege)
            .withDetail(
                "issue",
                "connected DB user can DELETE from user_roles or holds ALL PRIVILEGES/root —"
                    + " least-privilege nexus_app provisioning (ADR-0014/ADR-0015) has drifted or"
                    + " was never applied")
            .build();
      }
      return Health.up().withDetail("dbUser", currentUser).build();
    } catch (SQLException e) {
      // The self-check itself must never fail the app or throw — an inconclusive check is
      // reported as UNKNOWN, not treated as either a pass or a drift finding.
      log.warn("user_roles DB privilege self-check failed to execute: {}", e.getMessage());
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
  private boolean hasTableDeletePrivilege(Connection connection, String userName)
      throws SQLException {
    String sql =
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = ? "
            + "AND PRIVILEGE_TYPE IN ('DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?";
    try (var preparedStatement = connection.prepareStatement(sql)) {
      preparedStatement.setString(1, USER_ROLES_TABLE);
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
  private boolean hasGlobalDeletePrivilege(Connection connection, String userName)
      throws SQLException {
    String sql =
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES "
            + "WHERE PRIVILEGE_TYPE IN ('DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?";
    try (var preparedStatement = connection.prepareStatement(sql)) {
      preparedStatement.setString(1, "'" + userName + "'@%");
      try (ResultSet resultSet = preparedStatement.executeQuery()) {
        return resultSet.next() && resultSet.getInt(1) > 0;
      }
    }
  }
}
