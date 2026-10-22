package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.RegisterUserUseCase;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.AccessReviewService;
import com.example.nexus.rbac.domain.EffectivePermission;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleHolder;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-018 TS-15 (T-029, C3 and the C5 pin): the access-review reads against real MySQL. Two tenants,
 * each endpoint returns only the caller's tenant; foreign ids are 404; a revoked holder disappears;
 * a deleted role is 404; {@code assignedBy} is redacted for a non-administrator {@code audit:read}
 * holder and present for an administrator; a user holding a permission through two roles appears
 * once with both role ids; a freshly registered user has no effective permissions.
 *
 * <p>Service level, as {@code RoleAssignmentIT}: the HTTP mapping is {@code
 * AccessReviewControllerTest}'s. Fixtures use fresh tenants and custom roles only.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class AccessReviewIT {

  private static final String AUDIT_READ = "audit:read";

  @Autowired private AccessReviewService accessReviewService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private RegisterUserUseCase registerUserUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_returnOnlyTheCallersTenant_andNotFoundForForeignIds_acrossAllThreeEndpoints() {
    Fixture a = fixture();
    Fixture b = fixture();

    PageResult<RoleHolder> holders =
        accessReviewService.listRoleHolders(a.reviewer, a.role.getId(), 0, 20);
    PageResult<PermissionHolder> permissionHolders =
        accessReviewService.listPermissionHolders(a.reviewer, a.auditReadId, 0, 20);

    assertThat(holders.items()).extracting(RoleHolder::userId).containsExactlyInAnyOrder(a.holder1.getId(), a.holder2.getId());
    assertThat(permissionHolders.items())
        .extracting(PermissionHolder::userId)
        .contains(a.holder1.getId(), a.holder2.getId())
        .doesNotContain(b.holder1.getId(), b.holder2.getId());

    assertThatThrownBy(() -> accessReviewService.listRoleHolders(a.reviewer, b.role.getId(), 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
    assertThatThrownBy(() -> accessReviewService.getEffectivePermissions(a.reviewer, b.holder1.getId()))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");
  }

  @Test
  void should_dropARevokedHolder_andAnswerNotFoundForADeletedRole() {
    Fixture a = fixture();
    UserRole second = a.assignments.get(1);
    jdbc.update("UPDATE user_roles SET revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ?", toBytes(second.getId()));

    assertThat(accessReviewService.listRoleHolders(a.reviewer, a.role.getId(), 0, 20).items())
        .extracting(RoleHolder::userId)
        .containsExactly(a.holder1.getId());
    assertThat(accessReviewService.getEffectivePermissions(a.reviewer, a.holder2.getId()))
        .as("the revoked holder no longer holds the permission")
        .isEmpty();

    jdbc.update("UPDATE user_roles SET revoked_at = CURRENT_TIMESTAMP(6) WHERE role_id = ?", toBytes(a.role.getId()));
    jdbc.update("UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?", toBytes(a.role.getId()));
    assertThatThrownBy(() -> accessReviewService.listRoleHolders(a.reviewer, a.role.getId(), 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_redactAssignedByForANonAdministrator_andShowItToAnAdministrator() {
    Fixture a = fixture();
    RoleChangeActor administrator = seedAdministrator(a.tenantId);

    List<RoleHolder> asReviewer =
        accessReviewService.listRoleHolders(a.reviewer, a.role.getId(), 0, 20).items();
    List<RoleHolder> asAdministrator =
        accessReviewService.listRoleHolders(administrator, a.role.getId(), 0, 20).items();

    assertThat(asReviewer).extracting(RoleHolder::assignedBy).containsOnlyNulls();
    assertThat(asAdministrator).extracting(RoleHolder::assignedBy).doesNotContainNull();
  }

  @Test
  void should_listAUserOnceWithBothRoles_when_theyHoldThePermissionThroughTwoRoles() {
    Fixture a = fixture();
    Role other = seedRole(a.tenantId, "AR-SECOND");
    grantByName(other, AUDIT_READ);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), a.holder1.getId(), other.getId(), a.tenantId, a.holder1.getId()));

    PageResult<PermissionHolder> result =
        accessReviewService.listPermissionHolders(a.reviewer, a.auditReadId, 0, 100);

    List<PermissionHolder> forHolder1 =
        result.items().stream().filter(h -> h.userId().equals(a.holder1.getId())).toList();
    assertThat(forHolder1).hasSize(1);
    assertThat(forHolder1.get(0).viaRoleIds()).containsExactlyInAnyOrder(a.role.getId(), other.getId());
    List<EffectivePermission> effective = accessReviewService.getEffectivePermissions(a.reviewer, a.holder1.getId());
    assertThat(effective).filteredOn(p -> p.name().equals(AUDIT_READ)).singleElement()
        .satisfies(p -> assertThat(p.viaRoleIds()).containsExactlyInAnyOrder(a.role.getId(), other.getId()));
  }

  @Test
  void should_pageDistinctUsersInUserIdOrder_withoutDroppingAnyone() {
    Fixture a = fixture();
    for (int i = 0; i < 5; i++) {
      User extra = seedUser(a.tenantId);
      userRoleRepository.save(
          new UserRole(uuidGenerator.newId(), extra.getId(), a.role.getId(), a.tenantId, extra.getId()));
    }

    PageResult<PermissionHolder> first = accessReviewService.listPermissionHolders(a.reviewer, a.auditReadId, 0, 4);
    PageResult<PermissionHolder> second = accessReviewService.listPermissionHolders(a.reviewer, a.auditReadId, 1, 4);

    // holder1, holder2, the five extras and the reviewer (whose own role carries audit:read).
    assertThat(first.totalElements()).isEqualTo(8);
    List<UUID> ids = new java.util.ArrayList<>();
    first.items().forEach(h -> ids.add(h.userId()));
    second.items().forEach(h -> ids.add(h.userId()));
    assertThat(ids).doesNotHaveDuplicates().hasSize(8).isSorted();
  }

  /** C5 pin: a newly registered user holds no role, so their effective permissions are empty. */
  @Test
  void should_haveNoEffectivePermissions_when_theUserJustRegistered() {
    UUID bootstrapTenant = UUID.fromString("00000000-0000-7000-8000-000000000001");
    String email = "ar-reg-" + UUID.randomUUID() + "@example.com";
    registerUserUseCase.register(bootstrapTenant, email, "ValidPassphrase_99!", RequestContext.UNKNOWN);
    User registered =
        userRegistrationPort
            .findByTenantAndEmailHmac(bootstrapTenant, emailBlindIndexService.blindIndex(email))
            .orElseThrow();
    RoleChangeActor reviewer = new RoleChangeActor(uuidGenerator.newId(), bootstrapTenant);

    assertThat(accessReviewService.getEffectivePermissions(reviewer, registered.getId())).isEmpty();
  }

  // ── fixtures ──────────────────────────────────────────────────────────────────────────

  private record Fixture(
      UUID tenantId,
      Role role,
      UUID auditReadId,
      User holder1,
      User holder2,
      List<UserRole> assignments,
      RoleChangeActor reviewer) {}

  /** A tenant with one role carrying audit:read, two holders, and a non-administrator reviewer. */
  private Fixture fixture() {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId, "AR-ROLE");
    grantByName(role, AUDIT_READ);
    User holder1 = seedUser(tenantId);
    User holder2 = seedUser(tenantId);
    UserRole r1 = userRoleRepository.save(new UserRole(uuidGenerator.newId(), holder1.getId(), role.getId(), tenantId, holder1.getId()));
    UserRole r2 = userRoleRepository.save(new UserRole(uuidGenerator.newId(), holder2.getId(), role.getId(), tenantId, holder1.getId()));
    User reviewerUser = seedUser(tenantId);
    Role reviewerRole = seedRole(tenantId, "AR-REVIEWER");
    grantByName(reviewerRole, AUDIT_READ);
    userRoleRepository.save(new UserRole(uuidGenerator.newId(), reviewerUser.getId(), reviewerRole.getId(), tenantId, reviewerUser.getId()));
    UUID auditReadId =
        fromBytes(jdbc.queryForObject("SELECT id FROM permissions WHERE name = ?", byte[].class, AUDIT_READ));
    return new Fixture(
        tenantId, role, auditReadId, holder1, holder2, List.of(r1, r2),
        new RoleChangeActor(reviewerUser.getId(), tenantId));
  }

  /** An administrator by the one definition: an active holder of a role carrying the whole catalogue. */
  private RoleChangeActor seedAdministrator(UUID tenantId) {
    User admin = seedUser(tenantId);
    Role adminRole = seedRole(tenantId, "AR-ADMIN");
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        (Object) toBytes(adminRole.getId()));
    userRoleRepository.save(new UserRole(uuidGenerator.newId(), admin.getId(), adminRole.getId(), tenantId, admin.getId()));
    return new RoleChangeActor(admin.getId(), tenantId);
  }

  private User seedUser(UUID tenantId) {
    String email = "ar-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(UUID tenantId, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, tag + "-" + UUID.randomUUID(), null, false));
  }

  private void grantByName(Role role, String permissionName) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?",
        toBytes(role.getId()),
        permissionName);
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  private static UUID fromBytes(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
