package com.example.nexus.rbac.infrastructure.health;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
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
 * <p><b>US-015 D9 (03-design.md §9.5).</b> {@code roles} and {@code role_permissions} became
 * active write targets in US-015, so this indicator also monitors them: both flag DOWN on any
 * {@code UPDATE} (table- <em>or</em> column-scoped — neither table has an intended column-scoped
 * grant the way {@code user_roles} does) or {@code ALL PRIVILEGES}; {@code roles} additionally
 * flags on {@code DELETE}. {@code role_permissions} deliberately never checks {@code DELETE} — it
 * is intentionally granted there (no soft-delete column, no trigger) — so replicating the {@code
 * user_roles}/{@code roles} DELETE check onto it would make this indicator permanently DOWN.
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

      // US-015 D9 (03-design.md §9.5): roles reacts to any UPDATE (table- or column-scoped),
      // DELETE or ALL PRIVILEGES. The global leg is shared with user_roles' own check above —
      // a global grant applies to every table, so it needs only one query.
      boolean rolesHasTableDeleteGrant =
          hasRolesTableDeleteOrAllPrivilegesGrant(connection, userName);
      boolean rolesHasGlobalDeleteGrant = hasGlobalPrivilege;
      boolean rolesHasTableScopedUpdateGrant =
          hasRolesTableScopedUpdateGrant(connection, userName);
      boolean rolesHasColumnScopedUpdateGrant =
          hasRolesColumnScopedUpdateGrant(connection, userName);
      boolean rolesDown =
          rolesHasTableDeleteGrant
              || rolesHasGlobalDeleteGrant
              || rolesHasTableScopedUpdateGrant
              || rolesHasColumnScopedUpdateGrant;

      // role_permissions reacts to any UPDATE or ALL PRIVILEGES but — unlike user_roles/roles —
      // never to DELETE: it intentionally grants DELETE (no soft-delete column, no trigger), and
      // checking for it would make this indicator permanently DOWN in production.
      boolean rolePermissionsHasTableAllPrivilegesGrant =
          hasRolePermissionsTableAllPrivilegesGrant(connection, userName);
      boolean rolePermissionsHasGlobalAllPrivilegesGrant =
          hasGlobalAllPrivilegesPrivilege(connection, userName);
      boolean rolePermissionsHasTableScopedUpdateGrant =
          hasRolePermissionsTableScopedUpdateGrant(connection, userName);
      boolean rolePermissionsHasColumnScopedUpdateGrant =
          hasRolePermissionsColumnScopedUpdateGrant(connection, userName);
      boolean rolePermissionsDown =
          rolePermissionsHasTableAllPrivilegesGrant
              || rolePermissionsHasGlobalAllPrivilegesGrant
              || rolePermissionsHasTableScopedUpdateGrant
              || rolePermissionsHasColumnScopedUpdateGrant;

      if (overPrivileged || hasBareTableUpdateGrant || rolesDown || rolePermissionsDown) {
        log.warn(
            "rbac DB privilege drift detected dbUser={} isRoot={} "
                + "hasTableDeleteGrant={} hasGlobalDeleteGrant={} hasTableScopedUpdateGrant={} "
                + "rolesDown={} rolePermissionsDown={}",
            currentUser,
            isRoot,
            hasTablePrivilege,
            hasGlobalPrivilege,
            hasBareTableUpdateGrant,
            rolesDown,
            rolePermissionsDown);
        return Health.down()
            .withDetail("dbUser", currentUser)
            .withDetail("isRoot", isRoot)
            .withDetail("hasTableDeleteGrant", hasTablePrivilege)
            .withDetail("hasGlobalDeleteGrant", hasGlobalPrivilege)
            .withDetail("hasTableScopedUpdateGrant", hasBareTableUpdateGrant)
            .withDetail("rolesHasTableDeleteGrant", rolesHasTableDeleteGrant)
            .withDetail("rolesHasGlobalDeleteGrant", rolesHasGlobalDeleteGrant)
            .withDetail("rolesHasTableScopedUpdateGrant", rolesHasTableScopedUpdateGrant)
            .withDetail("rolesHasColumnScopedUpdateGrant", rolesHasColumnScopedUpdateGrant)
            .withDetail(
                "rolePermissionsHasTableAllPrivilegesGrant",
                rolePermissionsHasTableAllPrivilegesGrant)
            .withDetail(
                "rolePermissionsHasGlobalAllPrivilegesGrant",
                rolePermissionsHasGlobalAllPrivilegesGrant)
            .withDetail(
                "rolePermissionsHasTableScopedUpdateGrant",
                rolePermissionsHasTableScopedUpdateGrant)
            .withDetail(
                "rolePermissionsHasColumnScopedUpdateGrant",
                rolePermissionsHasColumnScopedUpdateGrant)
            .withDetail(
                "issue",
                buildIssue(overPrivileged, hasBareTableUpdateGrant, rolesDown, rolePermissionsDown))
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

  private String buildIssue(
      boolean overPrivileged,
      boolean hasBareTableUpdateGrant,
      boolean rolesDown,
      boolean rolePermissionsDown) {
    List<String> issues = new ArrayList<>();
    if (overPrivileged) {
      issues.add(
          "connected DB user can DELETE from user_roles or holds ALL PRIVILEGES/root —"
              + " least-privilege nexus_app provisioning (ADR-0014/ADR-0015) has drifted"
              + " or was never applied");
    } else if (hasBareTableUpdateGrant) {
      issues.add(
          "connected DB user holds a bare table-scoped UPDATE grant on user_roles —"
              + " the intended column-scoped UPDATE (revoked_at) grant (ADR-0015 D7) has"
              + " been silently widened, re-permitting the multi-column UPDATE R-1/D2"
              + " exists to prevent");
    }
    if (rolesDown) {
      issues.add(
          "connected DB user holds an UPDATE, DELETE or ALL PRIVILEGES grant on roles —"
              + " a direct AC7 bypass below the application layer (US-015 D9)");
    }
    if (rolePermissionsDown) {
      issues.add(
          "connected DB user holds an UPDATE or ALL PRIVILEGES grant on role_permissions"
              + " (US-015 D9)");
    }
    return String.join("; ", issues);
  }



  /**
   * Shared execution plumbing for every grant-count check below: bind {@code userNamePattern} as
   * the query's sole {@code ?} parameter and report whether any row matched. {@code sql} is always
   * a call-site string literal (never built from a table-name variable) — deliberately, so
   * SpotBugs' {@code SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING} check, which cannot
   * tell an internal constant from untrusted input, has nothing to flag: this method itself
   * performs no string concatenation, it only forwards an already-complete literal.
   */
  private boolean countMatches(Connection connection, String sql, String userNamePattern)
      throws SQLException {
    try (var preparedStatement = connection.prepareStatement(sql)) {
      preparedStatement.setString(1, userNamePattern);
      try (ResultSet resultSet = preparedStatement.executeQuery()) {
        return resultSet.next() && resultSet.getInt(1) > 0;
      }
    }
  }

  private String grantee(String userName) {
    return "'" + userName + "'@%";
  }

  /**
   * Table-scoped grant check via {@code information_schema.TABLE_PRIVILEGES}. Matches on the
   * quoted username substring within {@code GRANTEE} (e.g. {@code 'nexus_app'@'%'}) rather than
   * reconstructing the exact quoted-host string, which is fragile across host-wildcard forms.
   */
  private boolean hasTableDeletePrivilege(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'user_roles' "
            + "AND PRIVILEGE_TYPE IN ('DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /**
   * Global grant check via {@code information_schema.USER_PRIVILEGES} — catches a
   * {@code root}-style {@code GRANT ... ON *.*} that never produces a table-scoped row.
   */
  private boolean hasGlobalDeletePrivilege(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES "
            + "WHERE PRIVILEGE_TYPE IN ('DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
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
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'user_roles' "
            + "AND PRIVILEGE_TYPE = 'UPDATE' "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /**
   * US-015 D9 (03-design.md §9.5) — table-scoped {@code DELETE}-or-{@code ALL PRIVILEGES} check
   * for {@code roles}, mirroring {@link #hasTableDeletePrivilege} on a second table.
   */
  private boolean hasRolesTableDeleteOrAllPrivilegesGrant(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'roles' "
            + "AND PRIVILEGE_TYPE IN ('DELETE', 'ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /** US-015 D9 — table-scoped {@code UPDATE} check for {@code roles}: any grant, unlike the
   *  column-scoped-only tolerance {@code user_roles} has (ADR-0015 D7). */
  private boolean hasRolesTableScopedUpdateGrant(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'roles' "
            + "AND PRIVILEGE_TYPE IN ('UPDATE') "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /**
   * US-015 D9 — positive grant-scope check via {@code information_schema.COLUMN_PRIVILEGES} for
   * {@code roles}: unlike {@code user_roles}, {@code roles} has no intended column-scoped grant,
   * so a column-scoped {@code UPDATE} here — which would produce no row in {@code
   * TABLE_PRIVILEGES} and so pass {@link #hasRolesTableScopedUpdateGrant} unnoticed — must itself
   * flag DOWN.
   */
  private boolean hasRolesColumnScopedUpdateGrant(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'roles' "
            + "AND PRIVILEGE_TYPE = 'UPDATE' "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /**
   * US-015 D9 — table-scoped {@code ALL PRIVILEGES} check for {@code role_permissions}. Deliberately
   * excludes {@code DELETE}: that privilege is intentionally granted on this table (no soft-delete
   * column, no trigger — 03-design.md §9.5), so checking for it would make this indicator
   * permanently DOWN in production.
   */
  private boolean hasRolePermissionsTableAllPrivilegesGrant(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'role_permissions' "
            + "AND PRIVILEGE_TYPE IN ('ALL PRIVILEGES') "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /** US-015 D9 — table-scoped {@code UPDATE} check for {@code role_permissions}. */
  private boolean hasRolePermissionsTableScopedUpdateGrant(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'role_permissions' "
            + "AND PRIVILEGE_TYPE IN ('UPDATE') "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /**
   * US-015 D9 — positive grant-scope check via {@code information_schema.COLUMN_PRIVILEGES} for
   * {@code role_permissions}: a column-scoped {@code UPDATE} would produce no row in {@code
   * TABLE_PRIVILEGES} and so pass {@link #hasRolePermissionsTableScopedUpdateGrant} unnoticed.
   */
  private boolean hasRolePermissionsColumnScopedUpdateGrant(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES "
            + "WHERE TABLE_SCHEMA = DATABASE() "
            + "AND TABLE_NAME = 'role_permissions' "
            + "AND PRIVILEGE_TYPE = 'UPDATE' "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }

  /**
   * US-015 D9 — global-grant check for {@code role_permissions}, mirroring {@link
   * #hasGlobalDeletePrivilege} but scoped to {@code ALL PRIVILEGES} only: {@code role_permissions}
   * intentionally grants {@code DELETE} (no soft-delete column, no trigger — 03-design.md §9.5),
   * so — unlike {@link #hasGlobalDeletePrivilege} — this must never react to a bare {@code
   * DELETE}.
   */
  private boolean hasGlobalAllPrivilegesPrivilege(Connection connection, String userName)
      throws SQLException {
    return countMatches(
        connection,
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES "
            + "WHERE PRIVILEGE_TYPE = 'ALL PRIVILEGES' "
            + "AND GRANTEE LIKE ?",
        grantee(userName));
  }
}
