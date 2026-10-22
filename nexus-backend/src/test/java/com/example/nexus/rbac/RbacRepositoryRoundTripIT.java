package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.Permission;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaPermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-009 T-09-07 (AC8): save/find round-trip for all 4 RBAC entities under {@code
 * ddl-auto=validate}, proving the {@code active_key byte[]} mapping and the {@code @IdClass}
 * composite key both boot and function correctly. All fixture roles pass {@code
 * is_system_role=false} explicitly, keeping {@code RbacSchemaMigrationIT}'s scoped seed-role
 * count stable regardless of test execution order (see that class's Javadoc).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RbacRepositoryRoundTripIT {

  @Autowired private JpaPermissionRepository permissionRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");

  @Test
  void should_roundTripPermission_when_savedAndReFetched() {
    Permission saved =
        permissionRepository.save(
            new Permission(
                uuidGenerator.newId(),
                "rt:read-" + UUID.randomUUID(),
                "round-trip test permission"));

    Permission found = permissionRepository.findById(saved.getId()).orElseThrow();

    assertThat(found.getName()).isEqualTo(saved.getName());
    assertThat(found.getCreatedAt()).isNotNull();
  }

  /**
   * Gap identified in Phase 8 test-validate: {@code permissions.description} is {@code NOT NULL}
   * (deliberately asymmetric with {@code roles.description}, which is nullable -- see {@code
   * should_allowNullDescription_when_constructedWithoutOne} in {@code RoleTest}) but nothing
   * proved the DB actually enforces that. The entity's Java field type ({@code String}) permits
   * {@code null} at compile time, so this is a genuine DB-level constraint, not just a
   * java-level habit.
   */
  @Test
  void should_rejectNullDescription_when_permissionSaved() {
    assertThatThrownBy(
            () ->
                permissionRepository.save(
                    new Permission(uuidGenerator.newId(), "rt:null-desc-" + UUID.randomUUID(), null)))
        .isInstanceOf(DataIntegrityViolationException.class);
  }

  @Test
  void should_roundTripRole_when_savedAndReFetched() {
    Role saved =
        roleRepository.save(
            new Role(
                uuidGenerator.newId(),
                uuidGenerator.newId(),
                "RT-ROLE-" + UUID.randomUUID(),
                "desc",
                false));

    Role found = roleRepository.findById(saved.getId()).orElseThrow();

    assertThat(found.getName()).isEqualTo(saved.getName());
    assertThat(found.getCreatedAt()).isNotNull();
    assertThat(found.getUpdatedAt()).isNotNull();
  }

  @Test
  void should_roundTripRolePermission_when_savedAndReFetchedByCompositeId() {
    Permission permission =
        permissionRepository.save(
            new Permission(
                uuidGenerator.newId(),
                "rt:join-" + UUID.randomUUID(),
                "round-trip join permission"));
    Role role =
        roleRepository.save(
            new Role(
                uuidGenerator.newId(),
                uuidGenerator.newId(),
                "RT-JOIN-ROLE-" + UUID.randomUUID(),
                null,
                false));

    rolePermissionRepository.save(new RolePermission(role.getId(), permission.getId()));

    RolePermission found =
        rolePermissionRepository
            .findById(new RolePermissionId(role.getId(), permission.getId()))
            .orElseThrow();

    assertThat(found.getRoleId()).isEqualTo(role.getId());
    assertThat(found.getPermissionId()).isEqualTo(permission.getId());
    assertThat(found.getCreatedAt()).isNotNull();
  }

  @Test
  void should_populateActiveKey_when_userRoleSavedAndReFetched() {
    User assignee = seedUser("rt-assignee");
    User assigner = seedUser("rt-assigner");
    Role role =
        roleRepository.save(
            new Role(
                uuidGenerator.newId(),
                TENANT_ID,
                "RT-UR-ROLE-" + UUID.randomUUID(),
                null,
                false));

    UserRole saved =
        userRoleRepository.save(
            new UserRole(
                uuidGenerator.newId(), assignee.getId(), role.getId(), TENANT_ID, assigner.getId()));

    UserRole found = userRoleRepository.findById(saved.getId()).orElseThrow();

    assertThat(found.getActiveKey())
        .as("active_key must be populated by the DB after INSERT (@Generated)")
        .isNotNull();
    assertThat(found.getActiveKey()).hasSize(32);
    assertThat(found.getRevokedAt()).isNull();
  }

  /**
   * Gap identified in Phase 8 test-validate: none of the 5 FK constraints this migration adds
   * (3 on {@code user_roles}, 2 on {@code role_permissions}) had a violation path exercised by
   * any test. {@code role_id} is exercised here as the single representative: it is the FK
   * closest to an actual RBAC security invariant (an orphaned assignment referencing no real
   * role would silently grant nothing while still occupying a {@code uq_user_role_active} slot).
   * The other 4 FKs (user_roles.user_id, user_roles.assigned_by, role_permissions.role_id,
   * role_permissions.permission_id) are deliberately NOT each given their own test: they are
   * created by the identical {@code FOREIGN KEY ... REFERENCES} DDL pattern and enforced by the
   * same InnoDB mechanism with no custom application logic layered on top, so one exercised path
   * is sufficient evidence the pattern is correctly wired; testing all 5 individually would be
   * re-testing InnoDB itself rather than this codebase.
   */
  @Test
  void should_rejectInsert_when_roleIdDoesNotExist() {
    User assignee = seedUser("fk-dangling");
    User assigner = seedUser("fk-dangling-by");
    UUID nonExistentRoleId = uuidGenerator.newId();

    assertThatThrownBy(
            () ->
                userRoleRepository.save(
                    new UserRole(
                        uuidGenerator.newId(),
                        assignee.getId(),
                        nonExistentRoleId,
                        TENANT_ID,
                        assigner.getId())))
        .isInstanceOf(DataIntegrityViolationException.class);
  }

  /**
   * M10' (US-018 T-016; replaces the name-returning M7/M10 reads this class used to prove) is the
   * comma-join JPQL form because {@code Role} has no mapped association to {@code RolePermission}.
   * Nothing but a real MySQL proves its RESULT: it must return exactly one {@code (roleId,
   * permissionId)} row per attached permission of the tenant's roles, with no duplication, no
   * cross-join fan-out, and nothing from another tenant's roles.
   */
  @Test
  void should_returnOneRowPerAttachedPermissionOfTheTenantsRolesOnly_when_findingM10Prime() {
    UUID tenantId = uuidGenerator.newId();
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "RT-M10-ROLE-" + UUID.randomUUID(), null, false));
    Permission p1 = savePermission("rt:m10-a-");
    Permission p2 = savePermission("rt:m10-b-");
    Permission p3 = savePermission("rt:m10-c-");
    rolePermissionRepository.save(new RolePermission(role.getId(), p1.getId()));
    rolePermissionRepository.save(new RolePermission(role.getId(), p2.getId()));
    rolePermissionRepository.save(new RolePermission(role.getId(), p3.getId()));

    // An unrelated role of ANOTHER tenant must not leak into the result: the tenant predicate, not
    // incidental non-overlap, must be what excludes it.
    Role otherTenantsRole =
        roleRepository.save(
            new Role(
                uuidGenerator.newId(),
                uuidGenerator.newId(),
                "RT-M10-OTHER-" + UUID.randomUUID(),
                null,
                false));
    rolePermissionRepository.save(
        new RolePermission(otherTenantsRole.getId(), savePermission("rt:m10-other-").getId()));

    assertThat(roleRepository.findRolePermissionIdsByTenantRoles(tenantId))
        .containsExactlyInAnyOrder(
            new RolePermissionRef(role.getId(), p1.getId()),
            new RolePermissionRef(role.getId(), p2.getId()),
            new RolePermissionRef(role.getId(), p3.getId()));
  }

  /**
   * Companion to the above: a role with zero attached permissions yields no row at all (it can
   * never be admin-defining), not a null row and not an error, from the real comma-join.
   */
  @Test
  void should_returnNoRows_when_theTenantsRoleHasNoPermissionsAttached() {
    UUID tenantId = uuidGenerator.newId();
    roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RT-M10-EMPTY-ROLE-" + UUID.randomUUID(), null, false));

    assertThat(roleRepository.findRolePermissionIdsByTenantRoles(tenantId)).isEmpty();
  }

  /**
   * This class inserts permissions into the GLOBAL catalogue. Since US-018 M3 "administrator" is
   * defined as carrying every permission of that catalogue, a row left behind would silently
   * demote every other IT's migration-seeded {@code TENANT_ADMIN} for the rest of the run. Remove
   * everything this class inserted (all are named {@code rt:...}), pairings first.
   */
  @AfterEach
  void removeCatalogueRowsThisClassInserted() {
    jdbc.update(
        "DELETE FROM role_permissions WHERE permission_id IN"
            + " (SELECT id FROM permissions WHERE name LIKE 'rt:%')");
    jdbc.update("DELETE FROM permissions WHERE name LIKE 'rt:%'");
  }

  // ── US-018 C2: Pageable variants -- stable order, tenant scoping, deleted roles excluded ─────

  @Test
  void should_pageRolesInANameThenIdOrderWithoutOverlapOrGap_when_severalSortAdjacently() {
    UUID tenantId = uuidGenerator.newId();
    for (String name : List.of("pg-same", "PG-SAME", "Pg-Same", "pg-other")) {
      roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name + "-" + UUID.randomUUID(), null, false));
    }

    Page<RoleView> first = roleRepository.findRoleViewsByTenantId(tenantId, PageRequest.of(0, 2));
    Page<RoleView> second = roleRepository.findRoleViewsByTenantId(tenantId, PageRequest.of(1, 2));

    assertThat(first.getTotalElements()).isEqualTo(4);
    assertThat(first.getTotalPages()).isEqualTo(2);
    List<UUID> ids = new ArrayList<>();
    first.forEach(v -> ids.add(v.id()));
    second.forEach(v -> ids.add(v.id()));
    assertThat(ids).doesNotHaveDuplicates().hasSize(4);
    List<String> names = new ArrayList<>();
    first.forEach(v -> names.add(v.name().toLowerCase(Locale.ROOT)));
    second.forEach(v -> names.add(v.name().toLowerCase(Locale.ROOT)));
    assertThat(names).isSorted();
  }

  @Test
  void should_pageOnlyTheTenantsLiveRoles_when_otherTenantsAndDeletedRolesExist() {
    UUID tenantId = uuidGenerator.newId();
    UUID otherTenantId = uuidGenerator.newId();
    Role live = roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "pg-live-" + UUID.randomUUID(), null, false));
    Role deleted = roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "pg-del-" + UUID.randomUUID(), null, false));
    roleRepository.save(new Role(uuidGenerator.newId(), otherTenantId, "pg-foreign-" + UUID.randomUUID(), null, false));
    jdbc.update("UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?", toBytes(deleted.getId()));

    Page<RoleView> page = roleRepository.findRoleViewsByTenantId(tenantId, PageRequest.of(0, 20));

    assertThat(page.getContent()).extracting(RoleView::id).containsExactly(live.getId());
    assertThat(page.getTotalElements()).as("the count query filters too").isEqualTo(1);
    assertThat(roleRepository.countByTenantIdAndDeletedAtIsNull(tenantId)).isEqualTo(1);
  }

  @Test
  void should_pageAssignmentsByAssignedAtThenId_andExcludeRevokedAndDeletedRoleRows() {
    UUID tenantId = uuidGenerator.newId();
    User user = seedUserIn(tenantId);
    Role a = roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "pga-" + UUID.randomUUID(), null, false));
    Role b = roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "pgb-" + UUID.randomUUID(), null, false));
    Role c = roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "pgc-" + UUID.randomUUID(), null, false));
    Role gone = roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "pgd-" + UUID.randomUUID(), null, false));
    for (Role role : List.of(a, b, c, gone)) {
      userRoleRepository.save(new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
    }
    jdbc.update("UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?", toBytes(gone.getId()));

    Page<ActiveRoleAssignment> first =
        userRoleRepository.findActiveAssignmentViews(user.getId(), tenantId, PageRequest.of(0, 2));
    Page<ActiveRoleAssignment> second =
        userRoleRepository.findActiveAssignmentViews(user.getId(), tenantId, PageRequest.of(1, 2));

    assertThat(first.getTotalElements()).isEqualTo(3);
    List<UUID> roleIds = new ArrayList<>();
    first.forEach(v -> roleIds.add(v.roleId()));
    second.forEach(v -> roleIds.add(v.roleId()));
    assertThat(roleIds).containsExactlyInAnyOrder(a.getId(), b.getId(), c.getId());
    assertThat(roleIds).doesNotContain(gone.getId());
    assertThat(userRoleRepository.findActiveAssignmentViews(user.getId(), uuidGenerator.newId(), PageRequest.of(0, 20)).getTotalElements())
        .as("another tenant sees none of this user's assignments")
        .isZero();
  }

  @Test
  void should_pagePermissionsByName_when_sortedAtTheRepository() {
    Page<Permission> first = permissionRepository.findAll(PageRequest.of(0, 3, Sort.by("name")));
    Page<Permission> second = permissionRepository.findAll(PageRequest.of(1, 3, Sort.by("name")));

    List<String> names = new ArrayList<>();
    first.forEach(p -> names.add(p.getName()));
    second.forEach(p -> names.add(p.getName()));
    assertThat(names).doesNotHaveDuplicates().isSorted();
    assertThat(first.getTotalElements()).isGreaterThanOrEqualTo(8);
  }

  private static byte[] toBytes(UUID uuid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  private User seedUserIn(UUID tenantId) {
    String email = "rt-pg-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Permission savePermission(String namePrefix) {
    return permissionRepository.save(
        new Permission(uuidGenerator.newId(), namePrefix + UUID.randomUUID(), "round-trip perm"));
  }

  private User seedUser(String tag) {
    String email = "rt-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }
}
