package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

/**
 * US-009 T-09-03 (AC1, AC2, AC3, AC7; Scenarios 1, 5, 6; T-E6): schema presence, seed data, and
 * join queries for the RBAC tables introduced by {@code V5__rbac_schema.sql}. Mirrors {@code
 * IdentitySchemaMigrationIT}'s structure exactly: raw {@code JdbcTemplate} +
 * {@code information_schema} assertions, no JPA layer.
 *
 * <p><strong>Seed-count scoping (deliberate):</strong> the {@code roles} and {@code
 * role_permissions} counts below are scoped ({@code is_system_role = TRUE}, and the two known
 * seeded role IDs, respectively) rather than raw unfiltered {@code COUNT(*)}. Under this
 * project's default Failsafe fork settings, every {@code *IT} class using the identical
 * {@code @SpringBootTest + @Import(TestcontainersConfiguration.class)} combination shares one
 * cached Spring context — and therefore one running Testcontainers MySQL schema — for the whole
 * test run. Sibling RBAC tests in this same story (e.g. {@code RoleUniquenessIT}, {@code
 * ActiveAssignmentIT}, {@code RbacRepositoryRoundTripIT}) insert their own fixture {@code roles}
 * rows into that shared schema. Every fixture role created by those classes passes {@code
 * is_system_role=false} explicitly, so the scoped counts here stay stable regardless of test
 * execution order. {@code permissions} is safe as a raw {@code COUNT(*)}: no task in this batch
 * ever inserts into it (read-only at runtime per ADR-0013 D1; {@code nexus_app} is granted
 * {@code SELECT} only on that table).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RbacSchemaMigrationIT {

  @Autowired private JdbcTemplate jdbc;

  private static final String TENANT_ADMIN_ID = "019f6839-1810-7000-8000-00000000000a";
  private static final String MEMBER_ID = "019f6839-1811-7000-8000-00000000000b";
  private static final String USER_ROLE_ASSIGN_ID = "019f6839-1807-7000-8000-000000000008";
  private static final String AUDIT_READ_ID = "019f6839-1806-7000-8000-000000000007";

  private static final String SEEDED_PERMISSION_NAMES_SQL =
      "('tenant:read','tenant:write','user:read','user:write',"
          + "'role:read','role:write','audit:read','user:role:assign')";

  private static final String V6_LOCATION =
      "db/migration/V6__rbac_user_role_assign_permission.sql";
  private static final String FOOTER_BEGIN = "-- B7-FOOTER-BEGIN";
  private static final String FOOTER_END = "-- B7-FOOTER-END";

  @Test
  void should_createAllRbacTables_when_v5MigrationApplied() {
    List<String> tables =
        jdbc.queryForList(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' "
                + "ORDER BY TABLE_NAME",
            String.class);

    assertThat(tables).contains("permissions", "roles", "role_permissions", "user_roles");
  }

  @Test
  void should_createExpectedColumns_when_v5MigrationApplied() {
    List<String> permissionColumns =
        jdbc.queryForList(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' "
                + "ORDER BY ORDINAL_POSITION",
            String.class);
    assertThat(permissionColumns).containsExactly("id", "name", "description", "created_at");

    List<String> roleColumns =
        jdbc.queryForList(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'roles' "
                + "ORDER BY ORDINAL_POSITION",
            String.class);
    assertThat(roleColumns)
        .containsExactly(
            "id", "tenant_id", "name", "description", "is_system_role", "created_at",
            "updated_at");

    List<String> rolePermissionColumns =
        jdbc.queryForList(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'role_permissions' "
                + "ORDER BY ORDINAL_POSITION",
            String.class);
    assertThat(rolePermissionColumns).containsExactly("role_id", "permission_id", "created_at");

    List<String> userRoleColumns =
        jdbc.queryForList(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_roles' "
                + "ORDER BY ORDINAL_POSITION",
            String.class);
    assertThat(userRoleColumns)
        .containsExactly(
            "id", "user_id", "role_id", "tenant_id", "assigned_by", "assigned_at", "revoked_at",
            "active_key");

    Map<String, Object> activeKeyColumn =
        jdbc.queryForMap(
            "SELECT IS_NULLABLE, DATA_TYPE FROM information_schema.COLUMNS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_roles' "
                + "AND COLUMN_NAME = 'active_key'");
    assertThat(activeKeyColumn.get("IS_NULLABLE")).isEqualTo("YES");
    assertThat(activeKeyColumn.get("DATA_TYPE")).isEqualTo("binary");
  }

  @Test
  void should_createExpectedIndexes_when_v5MigrationApplied() {
    List<String> permissionIndexes =
        jdbc.queryForList(
            "SELECT INDEX_NAME FROM information_schema.STATISTICS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' "
                + "GROUP BY INDEX_NAME",
            String.class);
    assertThat(permissionIndexes).contains("uq_permissions_name");

    List<String> roleIndexes =
        jdbc.queryForList(
            "SELECT INDEX_NAME FROM information_schema.STATISTICS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'roles' "
                + "GROUP BY INDEX_NAME",
            String.class);
    assertThat(roleIndexes).contains("uq_roles_tenant_name");

    List<String> userRoleIndexes =
        jdbc.queryForList(
            "SELECT INDEX_NAME FROM information_schema.STATISTICS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_roles' "
                + "GROUP BY INDEX_NAME",
            String.class);
    assertThat(userRoleIndexes).contains("uq_user_role_active");

    // InnoDB auto-creates an index on permission_id to support the FK constraint check -- this
    // corrects the impact doc's "table scan" assumption (03-design.md S2.2 note) and proves the
    // "which roles grant permission X" reverse lookup is in fact indexed.
    List<String> permissionIdIndexes =
        jdbc.queryForList(
            "SELECT INDEX_NAME FROM information_schema.STATISTICS "
                + "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'role_permissions' "
                + "AND COLUMN_NAME = 'permission_id' AND SEQ_IN_INDEX = 1",
            String.class);
    assertThat(permissionIdIndexes).isNotEmpty();
  }

  @Test
  void should_haveFlywayMigrationV5Applied_successfully() {
    List<String> versions =
        jdbc.queryForList(
            "SELECT version FROM flyway_schema_history "
                + "WHERE CAST(success AS UNSIGNED) = 1 ORDER BY installed_rank",
            String.class);

    assertThat(versions).contains("1", "2", "3", "4", "5", "6");
  }

  /**
   * Scoped to the 8 known migration-seeded names (V5's 7 plus V6's {@code user:role:assign}),
   * not a raw {@code COUNT(*)}: {@code
   * RbacRepositoryRoundTripIT} legitimately inserts its own fixture {@code Permission} rows into
   * this same shared Testcontainers schema, so an unscoped count is order-dependent across the
   * `*IT` suite. Mirrors the same scoping already applied to {@code roles} (via {@code
   * is_system_role}) and {@code role_permissions} (via the known role IDs) below.
   */
  @Test
  void should_seedExactly8Permissions_when_migrationApplied() {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM permissions WHERE name IN " + SEEDED_PERMISSION_NAMES_SQL,
            Integer.class);
    assertThat(count).isEqualTo(8);
  }

  @Test
  void should_seedExactly2SystemRoles_when_migrationApplied() {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM roles WHERE is_system_role = TRUE", Integer.class);
    assertThat(count).isEqualTo(2);
  }

  @Test
  void should_seedExactly9SystemRolePermissions_when_migrationApplied() {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id IN (UUID_TO_BIN(?), UUID_TO_BIN(?))",
            Integer.class,
            TENANT_ADMIN_ID,
            MEMBER_ID);
    assertThat(count).isEqualTo(9);
  }

  @Test
  void should_grantTenantAdminAllEightPermissions_when_joinQueried() {
    List<String> permissionNames =
        jdbc.queryForList(
            "SELECT p.name FROM permissions p "
                + "JOIN role_permissions rp ON rp.permission_id = p.id "
                + "WHERE rp.role_id = UUID_TO_BIN(?) ORDER BY p.name",
            String.class,
            TENANT_ADMIN_ID);

    assertThat(permissionNames)
        .containsExactlyInAnyOrder(
            "tenant:read", "tenant:write", "user:read", "user:write", "role:read", "role:write",
            "audit:read", "user:role:assign");
  }

  @Test
  void should_grantMemberOnlyUserRead_when_joinQueried() {
    List<String> permissionNames =
        jdbc.queryForList(
            "SELECT p.name FROM permissions p "
                + "JOIN role_permissions rp ON rp.permission_id = p.id "
                + "WHERE rp.role_id = UUID_TO_BIN(?)",
            String.class,
            MEMBER_ID);

    assertThat(permissionNames).containsExactly("user:read");
  }

  /**
   * T-E6 (03b-threat-model.md): TENANT_ADMIN must hold every row currently in {@code
   * permissions}. Convention (documented in V5's migration header and restated here): every
   * future permission-adding migration MUST also insert the matching {@code role_permissions}
   * row(s) for TENANT_ADMIN -- the {@code INSERT ... SELECT} in V5 runs once as a snapshot, not a
   * standing rule, so this assertion is what fails a future migration that forgets to re-grant
   * TENANT_ADMIN for a newly added permission.
   */
  @Test
  void should_grantTenantAdminEveryPermissionRow_when_migrationApplied() {
    // Scoped to the 8 known migration-seeded names, not a raw COUNT(*) -- see the comment on
    // should_seedExactly8Permissions_when_migrationApplied for why an unscoped count is unsafe in
    // this shared-schema `*IT` suite. This test's intent (T-E6) is "TENANT_ADMIN holds every
    // migration-seeded permission," not "every row that happens to exist in the table right now."
    Integer totalPermissions =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM permissions WHERE name IN " + SEEDED_PERMISSION_NAMES_SQL,
            Integer.class);
    Integer tenantAdminPermissions =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = UUID_TO_BIN(?)",
            Integer.class,
            TENANT_ADMIN_ID);

    assertThat(tenantAdminPermissions).isEqualTo(totalPermissions);
  }

  // ---------------------------------------------------------------------------------------
  // US-018 T-001: V6's B7 footer (03-design.md §4.7, §4.11; RC-27.1, RC-48.2). Each test seeds
  // fixture roles, re-executes the footer statements read from V6 itself, and asserts the
  // outcome. @Transactional: the test-managed transaction rolls back, so neither the fixtures nor
  // the footer's grants leak into the shared Testcontainers schema (other *IT classes, e.g.
  // RoleResolutionServiceIT, assert TENANT_ADMIN's exact permission set). The full-catalogue role
  // is seeded from the live permissions table, so fixture permission rows other *IT classes leave
  // behind (RbacRepositoryRoundTripIT) cannot make it one permission short.
  // ---------------------------------------------------------------------------------------

  @Test
  @Transactional
  void should_grantEverySystemTenantAdminEveryPermission_when_footerReRun() throws IOException {
    UUID secondTenantAdmin = insertRole(UUID.randomUUID(), "TENANT_ADMIN", true);

    runV6Footer();

    Integer totalPermissions =
        jdbc.queryForObject("SELECT COUNT(*) FROM permissions", Integer.class);
    Integer missingForAnySystemAdmin =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM roles r CROSS JOIN permissions p "
                + "WHERE r.is_system_role = TRUE AND r.name = 'TENANT_ADMIN' AND NOT EXISTS ("
                + "SELECT 1 FROM role_permissions rp "
                + "WHERE rp.role_id = r.id AND rp.permission_id = p.id)",
            Integer.class);
    assertThat(missingForAnySystemAdmin).isZero();
    assertThat(permissionCount(secondTenantAdmin)).isEqualTo(totalPermissions);
  }

  @Test
  @Transactional
  void should_attachNewPermission_when_customRoleCarriesFullPreMigrationCatalogue()
      throws IOException {
    UUID customAdmin = insertRole(UUID.randomUUID(), "CUSTOM_FULL_" + UUID.randomUUID(), false);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE id <> UUID_TO_BIN(?)",
        customAdmin.toString(),
        USER_ROLE_ASSIGN_ID);

    runV6Footer();

    assertThat(holds(customAdmin, USER_ROLE_ASSIGN_ID)).isTrue();
  }

  @Test
  @Transactional
  void should_attachNothing_when_customRoleOnePermissionShort() throws IOException {
    UUID oneShort = insertRole(UUID.randomUUID(), "CUSTOM_SHORT_" + UUID.randomUUID(), false);
    // Carries user:write and everything else except audit:read: one short of the catalogue.
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions "
            + "WHERE id NOT IN (UUID_TO_BIN(?), UUID_TO_BIN(?))",
        oneShort.toString(),
        USER_ROLE_ASSIGN_ID,
        AUDIT_READ_ID);
    int before = permissionCount(oneShort);

    runV6Footer();

    assertThat(holds(oneShort, USER_ROLE_ASSIGN_ID)).isFalse();
    assertThat(permissionCount(oneShort)).isEqualTo(before);
  }

  @Test
  @Transactional
  void should_changeNothing_when_footerRunTwice() throws IOException {
    insertRole(UUID.randomUUID(), "TENANT_ADMIN", true);
    UUID customAdmin = insertRole(UUID.randomUUID(), "CUSTOM_TWICE_" + UUID.randomUUID(), false);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE id <> UUID_TO_BIN(?)",
        customAdmin.toString(),
        USER_ROLE_ASSIGN_ID);
    runV6Footer();
    Integer afterFirstRun =
        jdbc.queryForObject("SELECT COUNT(*) FROM role_permissions", Integer.class);

    runV6Footer();

    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM role_permissions", Integer.class))
        .isEqualTo(afterFirstRun);
  }

  private UUID insertRole(UUID tenantId, String name, boolean systemRole) {
    UUID roleId = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO roles (id, tenant_id, name, description, is_system_role) "
            + "VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, ?)",
        roleId.toString(),
        tenantId.toString(),
        name,
        "US-018 footer fixture",
        systemRole);
    return roleId;
  }

  private int permissionCount(UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = UUID_TO_BIN(?)",
            Integer.class,
            roleId.toString());
    return count == null ? 0 : count;
  }

  private boolean holds(UUID roleId, String permissionId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions "
                + "WHERE role_id = UUID_TO_BIN(?) AND permission_id = UUID_TO_BIN(?)",
            Integer.class,
            roleId.toString(),
            permissionId);
    return count != null && count == 1;
  }

  /** Executes the statements between V6's footer markers, exactly as the migration ran them. */
  private void runV6Footer() throws IOException {
    String migration =
        new ClassPathResource(V6_LOCATION).getContentAsString(StandardCharsets.UTF_8);
    int begin = migration.indexOf(FOOTER_BEGIN);
    int end = migration.indexOf(FOOTER_END);
    assertThat(begin).as("V6 footer markers present and ordered").isNotNegative().isLessThan(end);
    String footerSql =
        migration
            .substring(begin + FOOTER_BEGIN.length(), end)
            .lines()
            .filter(line -> !line.strip().startsWith("--"))
            .collect(Collectors.joining("\n"));
    List<String> statements =
        Arrays.stream(footerSql.split(";")).map(String::strip).filter(s -> !s.isEmpty()).toList();
    assertThat(statements).as("V6 footer statements (a) and (b)").hasSize(2);
    statements.forEach(jdbc::execute);
  }
}
