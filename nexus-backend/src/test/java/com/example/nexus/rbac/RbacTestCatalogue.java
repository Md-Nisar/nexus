package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.domain.RbacAdministrators;
import com.example.nexus.rbac.domain.RolePermissionRef;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-019 T-001 (03-design.md §3.5): fixture helpers that build and check "an administrator" from
 * the live catalogue, never from hand-listed permission ids. The administrator definition is the
 * whole {@code permissions} table (ADR-0021 D3), so a fixture that lists ids silently stops
 * producing an administrator when a migration grows the catalogue (V11: eight to nine). Every
 * method reads the table at call time.
 */
public final class RbacTestCatalogue {

  private RbacTestCatalogue() {}

  /** Every row of {@code permissions}, read now. */
  public static Set<UUID> allPermissionIds(JdbcTemplate jdbc) {
    return Set.copyOf(
        jdbc.query(
            "SELECT BIN_TO_UUID(id) FROM permissions",
            (rs, rowNum) -> UUID.fromString(rs.getString(1))));
  }

  /**
   * Inserts a live, non-system role in {@code tenantId} carrying every row of {@code permissions}
   * as of this call, so it is admin-defining. Returns the role id.
   */
  public static UUID createAdministratorRole(JdbcTemplate jdbc, UUID tenantId, String name) {
    UUID roleId = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO roles (id, tenant_id, name, description, is_system_role) "
            + "VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, FALSE)",
        roleId.toString(),
        tenantId.toString(),
        name,
        "US-019 administrator fixture");
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        roleId.toString());
    return roleId;
  }

  /**
   * Whether {@code userId} is an administrator of {@code tenantId} under the production predicate
   * ({@link RbacAdministrators#isAdministrator}) over live reads: the user's active assignments on
   * live roles of that tenant, against the whole current catalogue.
   */
  public static boolean isAdministrator(JdbcTemplate jdbc, UUID userId, UUID tenantId) {
    List<RolePermissionRef> held =
        jdbc.query(
            "SELECT BIN_TO_UUID(ur.role_id), BIN_TO_UUID(rp.permission_id) "
                + "FROM user_roles ur "
                + "JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id "
                + "JOIN role_permissions rp ON rp.role_id = r.id "
                + "WHERE ur.user_id = UUID_TO_BIN(?) AND ur.tenant_id = UUID_TO_BIN(?) "
                + "AND ur.revoked_at IS NULL AND r.deleted_at IS NULL",
            (rs, rowNum) ->
                new RolePermissionRef(
                    UUID.fromString(rs.getString(1)), UUID.fromString(rs.getString(2))),
            userId.toString(),
            tenantId.toString());
    return RbacAdministrators.isAdministrator(held, allPermissionIds(jdbc));
  }

  /**
   * Fails at the fixture, not as a confusing 403 later, when the seeded user is not an
   * administrator of the tenant under the live catalogue.
   */
  public static void assertAdministrator(JdbcTemplate jdbc, UUID userId, UUID tenantId) {
    assertThat(isAdministrator(jdbc, userId, tenantId))
        .as("fixture user %s must be an administrator of tenant %s", userId, tenantId)
        .isTrue();
  }
}
