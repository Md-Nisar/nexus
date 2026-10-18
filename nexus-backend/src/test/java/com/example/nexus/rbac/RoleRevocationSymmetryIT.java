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
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
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
import java.util.List;
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
 * <p><b>US-018 M3 (T-016, T-018) — revoke-subset and the replaced canary.</b> The four revoke
 * tests below are the T-E17 pairing and are kept as outcome assertions (the 403 and the success
 * stay); two fixtures change because the control that decides them changed:
 * {@code TENANT_ADMIN} now carries the whole catalogue as the real one does, since a role is an
 * administrator role by its permissions and not its name, and a caller with {@code user:write} only
 * revoking a {@code role:write}-only role is now denied by the live holdings check and the subset
 * rule instead of the name-or-ANY gate. New cases cover revoke-subset itself (a union-holder, a
 * caller missing one permission, a caller without {@code user:read} revoking a role that carries
 * it). The two canary tests of {@code nexus.rbac.self_role_assignment} are replaced by tests of
 * the meters that now exist: {@code nexus.rbac.admin_role_assigned{selfTarget}} (ticket, never
 * page) and the independent check's {@code nexus.rbac.self_assign_admin_disagreement}, which must
 * stay silent on a real successful self-assignment by a real administrator.
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
  private static final UUID USER_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");

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

  /**
   * T-E17, re-targeted. The role carries only {@code role:write}, so it is NOT admin-defining and
   * the name-or-ANY gate that used to deny this caller no longer exists. The caller holds {@code
   * user:write} only: the live holdings check (L-1) finds no {@code user:role:assign}, so the
   * revoke is denied with 403 {@code PERMISSION_ABSENT} and the row stays active. The 403 outcome
   * is unchanged; the reason is the control that now enforces it.
   */
  @Test
  void should_throwPermissionAbsent_when_callerWithoutUserRoleAssignAttemptsToRevokeRoleWriteRole() {
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
                    .isEqualTo(DenialReason.PERMISSION_ABSENT));

    assertThat(isActive(assignment.getId()))
        .as("a denied revoke must never touch the assignment row")
        .isTrue();
  }

  /**
   * Revoke-subset, union part: the caller holds {@code user:role:assign} but not {@code
   * role:write}, which the role carries. 403 {@code GRANT_EXCEEDS_CALLER}, the row stays active.
   */
  @Test
  void should_throwGrantExceedsCaller_when_callerLacksAPermissionOfTheRoleBeingRevoked() {
    UUID tenantId = uuidGenerator.newId();
    User delegate =
        seedUserWithRole(tenantId, "revsym-subset-caller", "ASSIGNER",
            RbacSeededPermissionIds.USER_ROLE_ASSIGN);
    Role dangerousRole = seedRole(tenantId, "CUSTOM-DANGEROUS", "revsym-subset");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User target = seedUser(tenantId, "revsym-subset-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, dangerousRole.getId(), target.getId(), target.getId());
    RoleChangeActor actor = new RoleChangeActor(delegate.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), dangerousRole.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    assertThat(isActive(assignment.getId())).isTrue();
  }

  /**
   * Behaviour change recorded in T-016: a caller without {@code user:read} can no longer revoke
   * {@code MEMBER}, because MEMBER carries it and revoke-subset requires the caller to hold every
   * permission of the role. The caller below holds {@code user:role:assign} only.
   */
  @Test
  void should_throwGrantExceedsCaller_when_callerWithoutUserReadRevokesMember() {
    UUID tenantId = uuidGenerator.newId();
    User delegate =
        seedUserWithRole(tenantId, "revsym-member-caller", "ASSIGNER",
            RbacSeededPermissionIds.USER_ROLE_ASSIGN);
    Role memberLikeRole = seedRole(tenantId, "MEMBER-LIKE", "revsym-member");
    grantPermission(memberLikeRole.getId(), USER_READ_PERMISSION_ID);
    User target = seedUser(tenantId, "revsym-member-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, memberLikeRole.getId(), target.getId(), target.getId());
    RoleChangeActor actor = new RoleChangeActor(delegate.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), memberLikeRole.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    assertThat(isActive(assignment.getId())).isTrue();
  }

  /**
   * T-E17, kept: a non-administrator cannot strip a {@code TENANT_ADMIN} assignment. The fixture
   * change is that {@code TENANT_ADMIN} carries the whole catalogue, as the real one does: it is an
   * administrator role by its permissions. The assertion (403 {@code NOT_TENANT_ADMIN}) is
   * unchanged.
   */
  @Test
  void should_throwNotTenantAdmin_when_nonAdminAttemptsToRevokeTenantAdminAssignment() {
    UUID tenantId = uuidGenerator.newId();
    User nonAdminCaller =
        seedUserWithRole(tenantId, "revsym-deny-admin-caller", "USER_WRITER",
            USER_WRITE_PERMISSION_ID);
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "revsym-deny-admin");
    grantWholeCatalogue(adminRole.getId());
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

  /**
   * RC-26.2 (T-E34): a UNION-holder -- someone who holds every catalogue permission only across
   * two partial roles -- passes the subset comparison on an administrator role but is not an
   * administrator, so they cannot strip one. 403 {@code NOT_TENANT_ADMIN}; the row stays active.
   */
  @Test
  void should_throwNotTenantAdmin_when_unionHolderAttemptsToRevokeTenantAdminAssignment() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "revsym-union");
    grantWholeCatalogue(adminRole.getId());
    User unionHolder = seedUser(tenantId, "revsym-union-caller");
    Role halfA = seedRole(tenantId, "HALF-A", "revsym-union");
    Role halfB = seedRole(tenantId, "HALF-B", "revsym-union");
    grantCatalogueHalf(halfA.getId(), 0);
    grantCatalogueHalf(halfB.getId(), 1);
    seedActiveAssignment(tenantId, halfA.getId(), unionHolder.getId(), unionHolder.getId());
    seedActiveAssignment(tenantId, halfB.getId(), unionHolder.getId(), unionHolder.getId());
    User target = seedUser(tenantId, "revsym-union-target");
    UserRole assignment =
        seedActiveAssignment(tenantId, adminRole.getId(), target.getId(), target.getId());
    RoleChangeActor actor = new RoleChangeActor(unionHolder.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), adminRole.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(isActive(assignment.getId())).isTrue();
  }

  // ═══════════════════════════════════════════════════════════════════
  // Revoke symmetry (T-E17 closure) — positive half: an active admin still can
  // (T-E11 pairing discipline: a denial-only proof could pass for the wrong reason)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_revokeSuccessfully_when_activeAdminRevokesDangerousCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "revsym-allow-dangerous");
    // US-018 07-security-review.md M-1/L-1: revoke-subset needs the admin to hold user:role:assign
    // and every permission of the revoked role (role:write): the admin role carries the catalogue.
    grantWholeCatalogue(adminRole.getId());
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
    // US-018 07-security-review.md M-1/L-1: the caller must hold user:role:assign and every
    // permission of the revoked role; both hold the same (whole-catalogue) admin role.
    grantWholeCatalogue(adminRole.getId());
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
  // Row 9 and row 7: admin_role_assigned{selfTarget}, and the independent check stays silent
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_countAdminRoleAssignedAndStaySilentOnDisagreement_when_administratorSelfAssignsAnAdminDefiningRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "canary-admin-self");
    grantWholeCatalogue(adminRole.getId());
    User adminUser = seedUser(tenantId, "canary-admin-self");
    seedActiveAssignment(tenantId, adminRole.getId(), adminUser.getId(), adminUser.getId());
    Role secondAdminRole = seedRole(tenantId, "ADMIN-DEFINING-2", "canary-admin-self");
    grantWholeCatalogue(secondAdminRole.getId());
    RoleChangeActor actor = new RoleChangeActor(adminUser.getId(), tenantId);
    double assignedBefore = counterValue("nexus.rbac.admin_role_assigned", "selfTarget", "true");
    double disagreementBefore = counterValue("nexus.rbac.self_assign_admin_disagreement", null, null);

    roleAssignmentService.assign(actor, adminUser.getId(), secondAdminRole.getId(), requestContext());

    assertThat(counterValue("nexus.rbac.admin_role_assigned", "selfTarget", "true"))
        .as("nexus.rbac.admin_role_assigned{selfTarget=true} must increment when an administrator"
            + " self-assigns an admin-defining role")
        .isEqualTo(assignedBefore + 1.0);
    assertThat(counterValue("nexus.rbac.self_assign_admin_disagreement", null, null))
        .as("the independent per-role check must AGREE with A4 on a real successful"
            + " self-assignment by a real administrator (RC-28.1)")
        .isEqualTo(disagreementBefore);
  }

  @Test
  void should_notCountAdminRoleAssigned_when_administratorSelfAssignsAPermissionlessRole() {
    UUID tenantId = uuidGenerator.newId();
    User adminUser = seedUser(tenantId, "canary-admin-self-benign");
    // A4: only an administrator may self-assign. The admin-defining role is a custom one, named
    // nothing like TENANT_ADMIN: names do not matter.
    Role adminDefiningRole = seedRole(tenantId, "ADMIN-DEFINING", "canary-admin-self-benign");
    grantWholeCatalogue(adminDefiningRole.getId());
    seedActiveAssignment(tenantId, adminDefiningRole.getId(), adminUser.getId(), adminUser.getId());
    Role benignRole = seedRole(tenantId, "NO-PERMS", "canary-admin-self-benign");
    RoleChangeActor actor = new RoleChangeActor(adminUser.getId(), tenantId);
    double assignedBefore = counterValue("nexus.rbac.admin_role_assigned", "selfTarget", "true");

    roleAssignmentService.assign(actor, adminUser.getId(), benignRole.getId(), requestContext());

    assertThat(counterValue("nexus.rbac.admin_role_assigned", "selfTarget", "true"))
        .as("a permission-less role is not admin-defining, so nothing is counted")
        .isEqualTo(assignedBefore);
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

  /**
   * Attaches half of the catalogue to {@code roleId}: the permissions whose position in id order
   * has the given parity. Two halves of opposite parity together cover the catalogue, but neither
   * role alone is admin-defining.
   */
  private void grantCatalogueHalf(UUID roleId, int parity) {
    List<UUID> ids =
        jdbc.query(
            "SELECT id FROM permissions ORDER BY id",
            (rs, rowNum) -> {
              ByteBuffer buf = ByteBuffer.wrap(rs.getBytes(1));
              return new UUID(buf.getLong(), buf.getLong());
            });
    for (int i = 0; i < ids.size(); i++) {
      if (i % 2 == parity) {
        grantPermission(roleId, ids.get(i));
      }
    }
  }

  /** Makes {@code roleId} admin-defining (US-018 §2.1): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        toBytes(roleId));
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

  /**
   * The shared *IT MeterRegistry accumulates counters across the whole run and these meters carry
   * no tenant tag (B3), so every assertion is a delta against a baseline read just before the
   * action. {@code tagKey} may be {@code null} for an untagged counter. A missing counter is 0.
   */
  private double counterValue(String name, String tagKey, String tagValue) {
    var search = meterRegistry.find(name);
    if (tagKey != null) {
      search = search.tag(tagKey, tagValue);
    }
    Counter counter = search.counter();
    return counter != null ? counter.count() : 0.0;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
