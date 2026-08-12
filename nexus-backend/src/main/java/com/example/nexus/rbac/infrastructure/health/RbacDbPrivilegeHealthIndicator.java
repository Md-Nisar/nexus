package com.example.nexus.rbac.infrastructure.health;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import com.example.nexus.common.security.DbUserUtil;
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
 * the over-grant check below looks only for {@code DELETE} — {@code nexus_app} intentionally
 * holds a column-scoped {@code UPDATE (revoked_at)} grant on {@code user_roles} (ADR-0015 D7),
 * which must not itself trigger that finding.
 *
 * <p><b>Positive grant-scope check (T-015 / {@code 03b-threat-model.md} T-E12).</b> The
 * over-grant check above cannot detect a <em>silent widening</em> of the {@code UPDATE} grant
 * itself: a future {@code GRANT UPDATE ON nexus.user_roles} (bare, table-scoped, no column list)
 * would quietly re-permit the multi-column {@code UPDATE} that R-1/D2 exists to prevent, and would
 * pass every existing check here (it is neither {@code DELETE} nor {@code ALL PRIVILEGES}). This
 * indicator therefore also flags DOWN when {@code information_schema.TABLE_PRIVILEGES} shows a
 * bare table-scoped {@code UPDATE} grant on {@code user_roles} for the current user — the signal
 * that the intended column scoping has been silently lost.
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
      String currentUser = DbUserUtil.readCurrentUser(connection);
      String userName = DbUserUtil.usernamePart(currentUser);
      boolean isRoot = "root".equalsIgnoreCase(userName);
      boolean hasTablePrivilege = hasTableDeletePrivilege(connection, userName);
      boolean hasGlobalPrivilege = hasGlobalDeletePrivilege(connection, userName);
      boolean overPrivileged = isRoot || hasTablePrivilege || hasGlobalPrivilege;
      boolean hasBareTableUpdateGrant = hasBareTableUpdatePrivilege(connection, userName);

      if (overPrivileged || hasBareTableUpdateGrant) {
        log.warn(
            "user_roles DB privilege drift detected dbUser={} isRoot={} "
                + "hasTableDeleteGrant={} hasGlobalDeleteGrant={} hasTableScopedUpdateGrant={}",
            currentUser,
            isRoot,
            hasTablePrivilege,
            hasGlobalPrivilege,
            hasBareTableUpdateGrant);
        return Health.down()
            .withDetail("dbUser", currentUser)
            .withDetail("isRoot", isRoot)
            .withDetail("hasTableDeleteGrant", hasTablePrivilege)
            .withDetail("hasGlobalDeleteGrant", hasGlobalPrivilege)
            .withDetail("hasTableScopedUpdateGrant", hasBareTableUpdateGrant)
            .withDetail(
                "issue",
                overPrivileged
                    ? "connected DB user can DELETE from user_roles or holds ALL PRIVILEGES/root —"
                        + " least-privilege nexus_app provisioning (ADR-0014/ADR-0015) has drifted"
                        + " or was never applied"
                    : "connected DB user holds a bare table-scoped UPDATE grant on user_roles —"
                        + " the intended column-scoped UPDATE (revoked_at) grant (ADR-0015 D7) has"
                        + " been silently widened, re-permitting the multi-column UPDATE R-1/D2"
                        + " exists to prevent")
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

  /**
   * T-015 / T-E12 positive grant-scope check via {@code information_schema.TABLE_PRIVILEGES}. A
   * column-scoped grant (the intended {@code GRANT UPDATE (revoked_at) ON nexus.user_roles})
   * never produces a row here — only in {@code COLUMN_PRIVILEGES} — so any row this query returns
   * for {@code PRIVILEGE_TYPE = 'UPDATE'} means a bare, table-scoped {@code UPDATE} grant exists,
   * i.e. the column scoping has been widened away. This is a distinct, additional check from
   * {@link #hasTableDeletePrivilege}/{@link #hasGlobalDeletePrivilege} above (which look for
   * {@code DELETE}/{@code ALL PRIVILEGES}), not a replacement for either.
   */
  private boolean hasBareTableUpdatePrivilege(Connection connection, String userName)
      throws SQLException {
    String sql =
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = ? "
            + "AND PRIVILEGE_TYPE = 'UPDATE' "
            + "AND GRANTEE LIKE ?";
    try (var preparedStatement = connection.prepareStatement(sql)) {
      preparedStatement.setString(1, USER_ROLES_TABLE);
      preparedStatement.setString(2, "'" + userName + "'@%");
      try (ResultSet resultSet = preparedStatement.executeQuery()) {
        return resultSet.next() && resultSet.getInt(1) > 0;
      }
    }
  }
}
