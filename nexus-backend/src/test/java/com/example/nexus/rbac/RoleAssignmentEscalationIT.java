package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
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
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-015 T-010, RC-7 (03b-threat-model.md T-E16), re-cast by US-018 T-018 (ledger rows 7 and 9).
 * The {@code nexus.rbac.self_role_assignment} exploitation-side signal and {@code
 * nexus.rbac.dangerous_permission_granted} are retired: after A4 every successful
 * self-assignment is an administrator's (so the untagged counter would fire only on legitimate
 * activity), and an attach is now bounded by A3 instead of counted. What this class still proves
 * is the composed T-E16 escalation chain, against the controls that replace those signals.
 *
 * <p>Service-layer test, both {@link RoleAssignmentService} and {@link RoleManagementService}
 * autowired directly — no HTTP layer needed, mirroring {@code RoleAssignmentSecurityIT}'s style.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleAssignmentEscalationIT {

  private static final UUID ROLE_WRITE_PERMISSION_ID = RbacSeededPermissionIds.ROLE_WRITE;

  /** Meters retired by M3 (ledger rows 7 and 9); none may reappear. */
  private static final List<String> RETIRED_METERS =
      List.of(
          "nexus.rbac.self_role_assignment",
          "nexus.rbac.dangerous_permission_granted",
          "nexus.rbac.privileged_role_change_allowed",
          "nexus.rbac.admin_minted_by_non_named_admin");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private JdbcTemplate jdbc;

  // ── (a) the self-assignment counter is gone; the audit row where actor = target is the record ──

  /**
   * Retired: {@code should_incrementSelfRoleAssignmentCounter_when_selfAssigningRoleWithNoPermissionsAtAll}.
   * The control that now enforces its intent is A4 (a self-assignment needs an administrator), the
   * independent check ({@code HeldPermissionPartitionIT} and the unit tests) and the durable
   * {@code ROLE_ASSIGNED} row. This replacement proves the successful administrator
   * self-assignment still happens, leaves the durable row, and registers none of the retired
   * meters.
   */
  @Test
  void should_assignAndLeaveTheDurableRowAndNoRetiredMeter_when_administratorSelfAssigns() {
    UUID tenantId = uuidGenerator.newId();
    User user = seedUser("no-perms", tenantId);
    UUID userId = user.getId();
    // US-018 A4: only an administrator may self-assign, so the caller holds an admin-defining
    // role (the whole catalogue).
    Role adminDefiningRole = seedRole("ADMIN-DEFINING", tenantId);
    grantWholeCatalogue(adminDefiningRole.getId());
    seedActiveAssignment(tenantId, adminDefiningRole.getId(), userId, userId);
    Role role = seedRole("NO-PERMS", tenantId);
    RoleChangeActor actor = new RoleChangeActor(userId, tenantId);

    roleAssignmentService.assign(actor, userId, role.getId(), requestContext());

    assertThat(
            jdbc.queryForObject(
                "SELECT COUNT(*) FROM auth_events WHERE user_id = ? AND event_type ="
                    + " 'ROLE_ASSIGNED' AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleId')) = ?",
                Integer.class,
                toBytes(userId),
                role.getId().toString()))
        .as("the durable ROLE_ASSIGNED row where actor = target is the record of a self-assignment")
        .isEqualTo(1);
    assertThat(meterRegistry.getMeters().stream().map(m -> m.getId().getName()))
        .as("none of the meters M3 retired may be registered")
        .doesNotContainAnyElementsOf(RETIRED_METERS);
  }

  // ── (b) T-016: the T-E16 escalation chain, now closed by A3 and A4 ──────────────────────────

  /**
   * US-016 T-016 (§4.2's corrected M-3/T-E9 note), re-cast. An administrator attaches {@code
   * role:write} to a custom role (the mint side: A3 requires the administrator to hold it, and
   * does). A non-administrator then attempts to self-assign that now-powerful role: A4 denies it
   * with 403 {@code SELF_ASSIGNMENT} (the name-or-ANY gate that used to deny it, with {@code
   * NOT_TENANT_ADMIN}, is retired), and the denial is durably audited with {@code
   * operation="assign"} in its {@code ROLE_ASSIGNMENT_DENIED} metadata (D17).
   *
   * <p><b>Explicitly NOT evidence for T-E21 / RES-26</b> (the attach-after-assign residual, now
   * through a SECOND account): here the permission is attached BEFORE the self-assign is attempted.
   * The opposite ordering (a non-administrator assigns a BENIGN role to a second account first, and
   * an administrator only makes it powerful afterward) remains open by design and is detected, not
   * prevented, by the row 13 signal and the narrow {@code RBAC_010} rule (see {@code
   * AttachEscalationSignalIT}).
   */
  @Test
  void should_denyAndAudit_when_nonAdminSelfAssignsANowPowerfulRole() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole("ADMIN", tenantId, "TENANT_ADMIN");
    // US-018 A3: the administrator must also hold the permission they attach: the whole catalogue.
    grantWholeCatalogue(adminRole.getId());
    User adminUser = seedUser("admin", tenantId);
    UUID adminUserId = adminUser.getId();
    seedActiveAssignment(tenantId, adminRole.getId(), adminUserId, adminUserId);
    RoleChangeActor adminActor = new RoleChangeActor(adminUserId, tenantId);

    Role customRole = seedRole("CUSTOM-POWERFUL", tenantId);

    roleManagementService.attachPermission(
        adminActor, customRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

    // A non-administrator user attempts to self-assign the now-powerful custom role. They hold
    // user:role:assign (so the endpoint check passes) and nothing that makes them an administrator.
    User nonAdminUser = seedUser("non-admin", tenantId);
    UUID nonAdminUserId = nonAdminUser.getId();
    Role assignerRole = seedRole("ASSIGNER", tenantId);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
        toBytes(assignerRole.getId()),
        toBytes(RbacSeededPermissionIds.USER_ROLE_ASSIGN));
    seedActiveAssignment(tenantId, assignerRole.getId(), nonAdminUserId, adminUserId);
    RoleChangeActor nonAdminActor = new RoleChangeActor(nonAdminUserId, tenantId);
    RequestContext ctx = requestContext();

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    nonAdminActor, nonAdminUserId, customRole.getId(), ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.SELF_ASSIGNMENT));

    Map<String, Object> deniedRow = findLatestDenialAuditRow(nonAdminUserId);
    assertThat(deniedRow.get("reason")).isEqualTo("SELF_ASSIGNMENT");
    assertThat(deniedRow.get("operation"))
        .as("D17: the durable denial row must carry operation=\"assign\" for this self-assign "
            + "attempt")
        .isEqualTo("assign");
    assertThat(deniedRow.get("trace_id")).isEqualTo(ctx.traceId());
    assertThat(meterRegistry.getMeters().stream().map(m -> m.getId().getName()))
        .doesNotContainAnyElementsOf(RETIRED_METERS);
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

  /** Makes {@code roleId} admin-defining (US-018 §2.1): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        toBytes(roleId));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleAssignmentEscalationIT");
  }

  /**
   * D17: reads the durable {@code ROLE_ASSIGNMENT_DENIED} row's {@code reason}/{@code
   * operation}/{@code traceId} metadata fields, mirroring {@code
   * RoleAssignmentAuditIT#findLatestDenialAuditRow}.
   */
  private Map<String, Object> findLatestDenialAuditRow(UUID targetUserId) {
    return jdbc.queryForMap(
        "SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation')) AS operation, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.traceId')) AS trace_id "
            + "FROM auth_events WHERE user_id = ? AND event_type = 'ROLE_ASSIGNMENT_DENIED' "
            + "ORDER BY created_at DESC LIMIT 1",
        toBytes(targetUserId));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
