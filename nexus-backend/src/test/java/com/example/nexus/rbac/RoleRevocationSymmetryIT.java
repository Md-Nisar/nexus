package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-016 T-017 (04-tasks.md; 03-design.md §11.3): two proofs not covered by any existing test.
 *
 * <p><b>Revoke symmetry (T-E17 closure).</b> Prior to this story, {@link RoleAssignmentService
 * #revoke} had no privilege gate at all — this is the first revoke-side authorization denial the
 * platform has ever needed evidence for. A non-admin holding {@code user:write} (but not an active
 * {@code TENANT_ADMIN} assignment) cannot strip a dangerous custom-role assignment, nor a {@code
 * TENANT_ADMIN} assignment itself; an active admin still can revoke both — the positive half of
 * the pair (a denial-only proof could pass for the wrong reason, e.g. a missing bean denying
 * everyone, mirroring {@code RoleAssignmentSecurityIT}'s T-E11 pairing discipline).
 *
 * <p><b>Canary (FR-6/D7/D15).</b> {@link RoleAssignmentService#assign}'s {@code
 * nexus.rbac.self_role_assignment} counter carries {@code privileged}/{@code callerIsAdmin} tags.
 * An active admin self-assigning a dangerous custom role must increment {@code
 * privileged="true",callerIsAdmin="true"} and must NEVER produce {@code
 * privileged="true",callerIsAdmin="false"} — asserted against a REAL successful privileged
 * self-assignment by a real admin, not an empty registry, which is what makes the assertion a
 * genuine bypass canary rather than a tautology: if a future change ever let a non-admin succeed at
 * a privileged self-assignment, this exact tag combination would start appearing and this
 * assertion would catch it. A permission-less self-assignment separately increments {@code
 * privileged="false",callerIsAdmin="n_a"}.
 *
 * <p>Service-layer test (mirrors {@code LastAdminLockoutIT}/{@code RoleAssignmentEscalationIT}'s
 * house style) — {@link RoleAssignmentService} autowired directly, no HTTP layer needed for either
 * proof.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleRevocationSymmetryIT {

  // Seeded literals — V5__rbac_schema.sql header comment (same constants used elsewhere in this
  // package, e.g. RoleAssignmentSecurityIT/RoleAssignmentEscalationIT).
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private JdbcTemplate jdbc;

  // ═══════════════════════════════════════════════════════════════════
  // Revoke symmetry (T-E17 closure) — denial half
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_throwNotTenantAdmin_when_nonAdminAttemptsToRevokeDangerousCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User nonAdminCaller =
        seedUserWithRole(tenantId, "revsym-deny-dangerous-caller", "USER_WRITER",
            USER_WRITE_PERMISSION_ID);
    Role dangerousRole = seedRole(tenantId, "CUSTOM-DANGEROUS", "revsym-deny-dangerous");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User target = seedUser(tenantId, "revsym-deny-dangerous-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, dangerousRole.getId(), target.getId(), target.getId());
    RoleChangeActor actor = new RoleChangeActor(nonAdminCaller.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), dangerousRole.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(isActive(assignment.getId()))
        .as("a denied revoke must never touch the assignment row")
        .isTrue();
  }

  @Test
  void should_throwNotTenantAdmin_when_nonAdminAttemptsToRevokeTenantAdminAssignment() {
    UUID tenantId = uuidGenerator.newId();
    User nonAdminCaller =
        seedUserWithRole(tenantId, "revsym-deny-admin-caller", "USER_WRITER",
            USER_WRITE_PERMISSION_ID);
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "revsym-deny-admin");
    User target = seedUser(tenantId, "revsym-deny-admin-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, adminRole.getId(), target.getId(), target.getId());
    RoleChangeActor actor = new RoleChangeActor(nonAdminCaller.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), adminRole.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(isActive(assignment.getId()))
        .as("a denied revoke must never touch the assignment row")
        .isTrue();
  }

  // ═══════════════════════════════════════════════════════════════════
  // Revoke symmetry (T-E17 closure) — positive half: an active admin still can
  // (T-E11 pairing discipline: a denial-only proof could pass for the wrong reason)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_revokeSuccessfully_when_activeAdminRevokesDangerousCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "revsym-allow-dangerous");
    User adminCaller = seedUser(tenantId, "revsym-allow-dangerous-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), adminCaller.getId(), adminCaller.getId());
    Role dangerousRole = seedRole(tenantId, "CUSTOM-DANGEROUS", "revsym-allow-dangerous");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User target = seedUser(tenantId, "revsym-allow-dangerous-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, dangerousRole.getId(), target.getId(), target.getId());
    RoleChangeActor actor = new RoleChangeActor(adminCaller.getId(), tenantId);

    assertThatCode(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), dangerousRole.getId(), requestContext()))
        .as("an active TENANT_ADMIN must still be able to revoke a dangerous custom role")
        .doesNotThrowAnyException();

    assertThat(isActive(assignment.getId())).isFalse();
  }

  @Test
  void should_revokeSuccessfully_when_activeAdminRevokesTenantAdminAssignment() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "revsym-allow-admin");
    User adminCaller = seedUser(tenantId, "revsym-allow-admin-caller");
    seedActiveAssignment(tenantId, adminRole.getId(), adminCaller.getId(), adminCaller.getId());
    // A second active admin -- so revoking the target's assignment below leaves exactly one
    // active admin (the caller) and never trips AC5's last-admin lockout (409), which would
    // otherwise mask this test's actual proof (the privilege gate, not AC5).
    User targetAdmin = seedUser(tenantId, "revsym-allow-admin-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, adminRole.getId(), targetAdmin.getId(), targetAdmin.getId());
    RoleChangeActor actor = new RoleChangeActor(adminCaller.getId(), tenantId);

    assertThatCode(
            () ->
                roleAssignmentService.revoke(
                    actor, targetAdmin.getId(), adminRole.getId(), requestContext()))
        .as("an active TENANT_ADMIN must still be able to revoke another TENANT_ADMIN assignment")
        .doesNotThrowAnyException();

    assertThat(isActive(assignment.getId())).isFalse();
  }

  // ═══════════════════════════════════════════════════════════════════
  // Canary (FR-6/D7/D15)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_incrementPrivilegedTrueCallerIsAdminTrue_and_makeCallerIsAdminFalseUnreachable_when_activeAdminSelfAssignsDangerousCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "canary-admin-self");
    User adminUser = seedUser(tenantId, "canary-admin-self");
    seedActiveAssignment(tenantId, adminRole.getId(), adminUser.getId(), adminUser.getId());
    Role dangerousRole = seedRole(tenantId, "CUSTOM-DANGEROUS", "canary-admin-self");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    RoleChangeActor actor = new RoleChangeActor(adminUser.getId(), tenantId);
    double before = selfRoleAssignmentCount(tenantId, "true", "true");

    roleAssignmentService.assign(actor, adminUser.getId(), dangerousRole.getId(), requestContext());

    assertThat(selfRoleAssignmentCount(tenantId, "true", "true"))
        .as("nexus.rbac.self_role_assignment{privileged=true,callerIsAdmin=true} must increment"
            + " when an active admin self-assigns a dangerous custom role")
        .isEqualTo(before + 1.0);
    // The canary: driven against this SAME real, successful, privileged self-assignment by a
    // real admin -- not an empty registry -- this tag combination must never appear. If a future
    // change ever let a non-admin succeed at a privileged self-assignment, this combination would
    // start appearing and this assertion would catch it.
    assertThat(selfRoleAssignmentCounter(tenantId, "true", "false"))
        .as("nexus.rbac.self_role_assignment{privileged=true,callerIsAdmin=false} must be"
            + " unreachable on the success path (D7/D15 bypass canary)")
        .isNull();
  }

  @Test
  void should_incrementPrivilegedFalseCallerIsAdminNA_when_nonAdminSelfAssignsPermissionlessRole() {
    UUID tenantId = uuidGenerator.newId();
    User nonAdminUser = seedUser(tenantId, "canary-nonadmin-self");
    Role benignRole = seedRole(tenantId, "NO-PERMS", "canary-nonadmin-self");
    RoleChangeActor actor = new RoleChangeActor(nonAdminUser.getId(), tenantId);
    double before = selfRoleAssignmentCount(tenantId, "false", "n_a");

    roleAssignmentService.assign(
        actor, nonAdminUser.getId(), benignRole.getId(), requestContext());

    assertThat(selfRoleAssignmentCount(tenantId, "false", "n_a"))
        .as("nexus.rbac.self_role_assignment{privileged=false,callerIsAdmin=n_a} must increment"
            + " for a permission-less self-assignment")
        .isEqualTo(before + 1.0);
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "revsym-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(UUID tenantId, String name, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, tag, false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  private UserRole seedActiveAssignment(UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  /** Seeds a user holding exactly one permission, via a freshly created single-permission role. */
  private User seedUserWithRole(UUID tenantId, String tag, String roleName, UUID permissionId) {
    User user = seedUser(tenantId, tag);
    Role role = seedRole(tenantId, roleName, tag);
    grantPermission(role.getId(), permissionId);
    seedActiveAssignment(tenantId, role.getId(), user.getId(), user.getId());
    return user;
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleRevocationSymmetryIT");
  }

  private boolean isActive(UUID userRoleId) {
    Timestamp revokedAt =
        jdbc.queryForObject(
            "SELECT revoked_at FROM user_roles WHERE id = ?", Timestamp.class, toBytes(userRoleId));
    return revokedAt == null;
  }

  // The shared *IT MeterRegistry accumulates one counter instance per (tenantId, privileged,
  // callerIsAdmin) tuple ever seen in this run -- scope every lookup to this test's own tenantId
  // (mirrors RoleAssignmentEscalationIT's own rationale for the same counter).

  private double selfRoleAssignmentCount(UUID tenantId, String privileged, String callerIsAdmin) {
    Counter counter = selfRoleAssignmentCounter(tenantId, privileged, callerIsAdmin);
    return counter != null ? counter.count() : 0.0;
  }

  private Counter selfRoleAssignmentCounter(UUID tenantId, String privileged, String callerIsAdmin) {
    return meterRegistry
        .find("nexus.rbac.self_role_assignment")
        .tag("tenantId", tenantId.toString())
        .tag("privileged", privileged)
        .tag("callerIsAdmin", callerIsAdmin)
        .counter();
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
