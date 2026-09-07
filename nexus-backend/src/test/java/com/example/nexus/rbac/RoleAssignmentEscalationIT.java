package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * US-015 T-010, RC-7 (03-design.md §9.2/§10.2; 03b-threat-model.md T-E16): the {@code
 * nexus.rbac.self_role_assignment} exploitation-side detection signal {@link RoleAssignmentService
 * #assign} emits unconditionally on every self-assignment, and its interaction with US-015's own
 * {@code nexus.rbac.dangerous_permission_granted} counter in the composed T-E16 escalation chain.
 *
 * <p>Service-layer test, both {@link RoleAssignmentService} and {@link RoleManagementService}
 * autowired directly — no HTTP layer needed for either counter assertion, mirroring {@code
 * RoleAssignmentSecurityIT}'s before/after {@link MeterRegistry} delta-assertion pattern.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleAssignmentEscalationIT {

  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private MeterRegistry meterRegistry;

  // ── (a) any self-assignment increments the counter, regardless of permissions ──────────

  @Test
  void should_incrementSelfRoleAssignmentCounter_when_selfAssigningRoleWithNoPermissionsAtAll() {
    UUID tenantId = uuidGenerator.newId();
    User user = seedUser("no-perms", tenantId);
    UUID userId = user.getId();
    // A plain custom role with zero attached permissions -- the counter must fire anyway.
    Role role = seedRole("NO-PERMS", tenantId);
    RoleChangeActor actor = new RoleChangeActor(userId, tenantId);
    double before = selfRoleAssignmentCount(tenantId);

    roleAssignmentService.assign(actor, userId, role.getId(), requestContext());

    assertThat(selfRoleAssignmentCount(tenantId))
        .as("nexus.rbac.self_role_assignment must increment on ANY self-assignment, "
            + "unconditionally on the role's permissions")
        .isEqualTo(before + 1.0);
  }

  // ── (b) composed T-E16 scenario: admin attaches a dangerous permission, then a non-admin ──
  // ── self-assigns that role -- both counters increment and the assignment still succeeds ───

  @Test
  void should_incrementBothCountersAndSucceed_when_adminAttachesDangerousPermissionAndNonAdminSelfAssigns() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole("ADMIN", tenantId, "TENANT_ADMIN");
    User adminUser = seedUser("admin", tenantId);
    UUID adminUserId = adminUser.getId();
    seedActiveAssignment(tenantId, adminRole.getId(), adminUserId, adminUserId);
    RoleChangeActor adminActor = new RoleChangeActor(adminUserId, tenantId);

    Role customRole = seedRole("CUSTOM-DANGEROUS", tenantId);
    double dangerousBefore = dangerousPermissionGrantedCount(tenantId, "role:write");

    roleManagementService.attachPermission(
        adminActor, customRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

    assertThat(dangerousPermissionGrantedCount(tenantId, "role:write"))
        .as("nexus.rbac.dangerous_permission_granted{permission=role:write} must increment")
        .isEqualTo(dangerousBefore + 1.0);

    // A non-admin user self-assigns the now-dangerous custom role. AC8 does NOT block this --
    // it matches only the role NAME "TENANT_ADMIN", and this custom role isn't named that
    // (the exact T-E16 gap this counter exists to give operators a signal for).
    User nonAdminUser = seedUser("non-admin", tenantId);
    UUID nonAdminUserId = nonAdminUser.getId();
    RoleChangeActor nonAdminActor = new RoleChangeActor(nonAdminUserId, tenantId);
    double selfAssignBefore = selfRoleAssignmentCount(tenantId);

    roleAssignmentService.assign(
        nonAdminActor, nonAdminUserId, customRole.getId(), requestContext());

    assertThat(selfRoleAssignmentCount(tenantId))
        .as("nexus.rbac.self_role_assignment must increment on the non-admin's self-assignment "
            + "of the now-dangerous role")
        .isEqualTo(selfAssignBefore + 1.0);
    // The assignment itself must have SUCCEEDED (no exception thrown above) -- AC8's name-only
    // match never fires for a role not literally named TENANT_ADMIN.
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "rae-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag, UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RAE-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  /** Overload for the literal {@code "TENANT_ADMIN"} name AC8 matches on. */
  private Role seedRole(String tag, UUID tenantId, String literalName) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, literalName, tag, false));
  }

  private UserRole seedActiveAssignment(UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleAssignmentEscalationIT");
  }

  // Both counters are now tagged by tenantId (security-review fix), so the search must scope
  // to this test's own tenant -- the shared *IT MeterRegistry otherwise holds one instance per
  // tenant ever seen in this run, and an unscoped find() would match an arbitrary one of them.

  private double selfRoleAssignmentCount(UUID tenantId) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.self_role_assignment")
            .tag("tenantId", tenantId.toString())
            .counter();
    return counter != null ? counter.count() : 0.0;
  }

  private double dangerousPermissionGrantedCount(UUID tenantId, String permission) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.dangerous_permission_granted")
            .tag("permission", permission)
            .tag("tenantId", tenantId.toString())
            .counter();
    return counter != null ? counter.count() : 0.0;
  }
}
