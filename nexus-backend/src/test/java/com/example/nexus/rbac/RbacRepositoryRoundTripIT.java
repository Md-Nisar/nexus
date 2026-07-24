package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Permission;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaPermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;

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
                uuidGenerator.newId(),
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

  private User seedUser(String tag) {
    String email = "rt-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }
}
