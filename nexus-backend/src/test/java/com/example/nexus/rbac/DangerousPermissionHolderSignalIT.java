package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-016 T-018 (03-design.md §4.7/D13, §12.3; 03b-threat-model.md T-E21; 04-tasks.md T-018):
 * standing evidence for RES-1(b), the pre-positioning primitive.
 *
 * <p><b>This is the residual, made visible — not closed.</b> A non-admin self-assigning a benign
 * role today, followed by an administrator legitimately attaching {@code role:write} to that same
 * role tomorrow, is a silent, permanent, race-free escalation primitive that D13's mint-side
 * holder-count signal does not block and was never meant to block (§4.7: "it does not do... it
 * does not add a gate, and does not change any status code"). Both steps below are legitimate,
 * correctly-ungated actions and both MUST succeed. This test proves only that the resulting
 * escalation is now <b>visible</b> — via the {@code holderCount} audit metadata, the bounded
 * {@code holders} metric bucket, and the {@code
 * RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS} WARN — not that it is prevented.
 *
 * <p><b>This test must never be rewritten to assert a denial.</b> T-E21 survives US-016 by design
 * (03-design.md §3.4, §4.7's "what this does and does not buy"; 03b-threat-model.md T-E21,
 * RES-1(b)). If a future story closes T-E21 by re-validating assignments at attach time, this test
 * is rewritten <b>with</b> that story and its Javadoc rewritten with it — never before, and never
 * as a silent diff. Doing so here, absent that story, would misrepresent an accepted, open
 * residual risk as fixed.
 *
 * <p>Service-layer test, both {@link RoleAssignmentService} and {@link RoleManagementService}
 * autowired directly against real Testcontainers MySQL — no HTTP layer needed, mirroring {@code
 * RoleAssignmentEscalationIT}'s and {@code RoleManagementAuditIT}'s pattern (that pattern's own
 * Javadoc already disclaims T-E21 and points here as its standing evidence).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class DangerousPermissionHolderSignalIT {

  // role:write — one of RbacDangerousPermissions.NAMES, same literal id used throughout this
  // package's other ITs (e.g. RoleAssignmentEscalationIT, RoleManagementAuditIT).
  private static final UUID DANGEROUS_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_makeSoleHolderVisibleViaSignal_when_adminRetroactivelyAttachesDangerousPermissionToSelfAssignedBenignRole() {
    UUID tenantId = uuidGenerator.newId();

    // Step 1: a non-admin self-assigns a BENIGN role. No permission is attached yet, so
    // carriesDangerousPermission is false and the gate does not apply -- this MUST succeed.
    // Legitimate, correctly ungated; asserting a denial here would contradict the design.
    User nonAdminUser = seedUser("holder", tenantId);
    UUID nonAdminUserId = nonAdminUser.getId();
    Role benignRole = seedRole("BENIGN", tenantId);
    RoleChangeActor nonAdminActor = new RoleChangeActor(nonAdminUserId, tenantId);

    assertThatCode(
            () ->
                roleAssignmentService.assign(
                    nonAdminActor, nonAdminUserId, benignRole.getId(), requestContext()))
        .as("step 1 is a legitimate benign self-assignment; the gate must not fire")
        .doesNotThrowAnyException();

    // Step 2: an active admin attaches role:write to that SAME role -- a legitimate,
    // Epic-3-required administrative action (AC11 passes). This retroactively makes the
    // existing holder's assignment dangerous, with no gate re-evaluation at this moment.
    Role adminRole = seedRole("ADMIN", tenantId, "TENANT_ADMIN");
    User adminUser = seedUser("admin", tenantId);
    UUID adminUserId = adminUser.getId();
    seedActiveAssignment(tenantId, adminRole.getId(), adminUserId, adminUserId);
    RoleChangeActor adminActor = new RoleChangeActor(adminUserId, tenantId);
    RequestContext ctx = requestContext();

    Logger logger = (Logger) LoggerFactory.getLogger(RoleManagementService.class);
    ListAppender<ILoggingEvent> appender = startLogCapture(logger);
    PermissionView granted;
    try {
      granted =
          roleManagementService.attachPermission(
              adminActor, benignRole.getId(), DANGEROUS_PERMISSION_ID, ctx);

      // Step 3: assert the signal fired -- not a denial.
      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents)
          .as("D13's alertable WARN must fire because holderCount > 0")
          .hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsEntry("event", "RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS")
          .containsEntry("holderCount", 1)
          .containsEntry("grantedBy", adminUserId);
    } finally {
      stopLogCapture(logger, appender);
    }

    assertThat(granted).as("step 2 is a legitimate admin attach; it must succeed").isNotNull();

    Map<String, Object> row = findLatestRolePermissionGrantedRow(tenantId);
    assertThat(row.get("holder_count"))
        .as("D13: holderCount == 1 must be threaded through the ROLE_PERMISSION_GRANTED"
            + " audit metadata")
        .isEqualTo("1");

    Counter counter =
        meterRegistry
            .find("nexus.rbac.dangerous_permission_granted")
            .tag("permission", "role:write")
            .tag("tenantId", tenantId.toString())
            .tag("holders", "1")
            .counter();
    assertThat(counter)
        .as("the bounded holders=\"1\" bucket tag must be present -- never the raw count, "
            + "which is unbounded cardinality")
        .isNotNull();
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "dphs-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag, UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "DPHS-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  /** Overload for the literal {@code "TENANT_ADMIN"} name AC11's admin gate resolves by. */
  private Role seedRole(String tag, UUID tenantId, String literalName) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, literalName, tag, false));
  }

  private UserRole seedActiveAssignment(UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private RequestContext requestContext() {
    return RequestContext.of(
        "127.0.0.1", "trace-" + UUID.randomUUID(), "DangerousPermissionHolderSignalIT");
  }

  private Map<String, Object> findLatestRolePermissionGrantedRow(UUID tenantId) {
    return jdbc.queryForMap(
        "SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.holderCount')) AS holder_count "
            + "FROM auth_events WHERE tenant_id = ? AND event_type = 'ROLE_PERMISSION_GRANTED' "
            + "ORDER BY created_at DESC LIMIT 1",
        toBytes(tenantId));
  }

  private ListAppender<ILoggingEvent> startLogCapture(Logger logger) {
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(Logger logger, ListAppender<ILoggingEvent> listAppender) {
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    return map;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
