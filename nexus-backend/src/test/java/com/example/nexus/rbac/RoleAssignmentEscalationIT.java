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
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

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
  @Autowired private JdbcTemplate jdbc;

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

  // ── (b) T-016: formerly the T-E16 escalation PoC -- now its closure proof ──────────────────

  /**
   * US-016 T-016 (03-design.md §11.3; §4.2's corrected M-3/T-E9 note): proves the T-E16-direct-path
   * and T-E17 closure. An admin attaches a dangerous permission ({@code role:write}) to a custom
   * role -- the mint side, unchanged by this story, still fires {@code
   * nexus.rbac.dangerous_permission_granted} exactly as before (asserted below). A non-admin then
   * attempts to self-assign that now-dangerous role: the unified privilege-based gate (D4) denies
   * it with 403 {@code NOT_TENANT_ADMIN}, the denial is durably audited with {@code
   * operation="assign"} in its {@code ROLE_ASSIGNMENT_DENIED} metadata (D17), and {@code
   * nexus.rbac.self_role_assignment} does NOT increment -- it only fires from the post-commit
   * success path, which this denial never reaches.
   *
   * <p><b>Explicitly NOT evidence for T-E21</b> (the attach-after-assign residual, US-016 D13):
   * here the dangerous permission is attached to the role BEFORE the self-assign is attempted, so
   * the gate evaluates against an already-dangerous role at assign time -- T-E16's direct
   * propagate path. T-E21 is the opposite ordering (a non-admin self-assigns a BENIGN role first,
   * and an admin only makes it dangerous afterward, with no gate re-evaluation at that later
   * moment) and remains open by design; its own standing evidence is US-016 T-018.
   *
   * <p>Formerly {@code
   * should_incrementBothCountersAndSucceed_when_adminAttachesDangerousPermissionAndNonAdminSelfAssigns}
   * -- this test used to assert the vulnerability itself (both counters incremented AND the
   * self-assignment succeeded). Inverted here, not deleted, per US-015's "replace, never delete"
   * discipline applied to a test rather than to prose: this remains the epic's only executable
   * record of what the vulnerability was, and now proves it is closed.
   */
  @Test
  void should_denyAndAudit_when_nonAdminSelfAssignsANowDangerousRole() {
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

    // A non-admin user attempts to self-assign the now-dangerous custom role. Before US-016 the
    // name-only AC8 match let this through; the unified privilege-based gate (D4) now denies it
    // just like a literally-named TENANT_ADMIN grant would be.
    User nonAdminUser = seedUser("non-admin", tenantId);
    UUID nonAdminUserId = nonAdminUser.getId();
    RoleChangeActor nonAdminActor = new RoleChangeActor(nonAdminUserId, tenantId);
    double selfAssignBefore = selfRoleAssignmentCount(tenantId, "true", "true");
    RequestContext ctx = requestContext();

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    nonAdminActor, nonAdminUserId, customRole.getId(), ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(selfRoleAssignmentCount(tenantId, "true", "true"))
        .as("a DENIED self-assignment must never increment nexus.rbac.self_role_assignment -- "
            + "the counter only fires from the post-commit success path")
        .isEqualTo(selfAssignBefore);

    Map<String, Object> deniedRow = findLatestDenialAuditRow(nonAdminUserId);
    assertThat(deniedRow.get("reason")).isEqualTo("NOT_TENANT_ADMIN");
    assertThat(deniedRow.get("operation"))
        .as("D17: the durable denial row must carry operation=\"assign\" for this self-assign "
            + "attempt")
        .isEqualTo("assign");
    assertThat(deniedRow.get("trace_id")).isEqualTo(ctx.traceId());
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

  // T-016: self_role_assignment now carries privileged/callerIsAdmin tags too (T-010/D15) --
  // an absence proof must match the FULL tag set the scenario would have produced had it
  // succeeded, not just tenantId, to be unambiguous (03-design.md §11.3 risk callout).
  private double selfRoleAssignmentCount(UUID tenantId, String privileged, String callerIsAdmin) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.self_role_assignment")
            .tag("tenantId", tenantId.toString())
            .tag("privileged", privileged)
            .tag("callerIsAdmin", callerIsAdmin)
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
