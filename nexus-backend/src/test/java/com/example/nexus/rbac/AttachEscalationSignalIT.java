package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.AttachProvenanceConflictException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
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
 * US-018 T-017 (03-design.md §5.1 rows 13 and 14, §5.6; 03b-threat-model.md T-E21, T-E32, RC-23.2,
 * R1-1; 04-tasks.md T-017): replaces {@code DangerousPermissionHolderSignalIT} (US-016 T-018, the
 * standing evidence for RES-1(b)), re-targeted from the name-based D13 holder-count signal to the
 * provenance signals of the attach.
 *
 * <p><b>Two things this class proves, and one it must never do.</b>
 *
 * <ul>
 *   <li><b>The residual stays visible (RES-26, detective).</b> An administrator attaching {@code
 *       role:write} to a benign role that a NON-administrator account assigned to someone (the
 *       second-account form of RES-1(b)) is a legitimate, ungated action and it SUCCEEDS; the
 *       evidence is the paging WARN {@code RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS} and
 *       the bucketed counter. <b>That test must never be rewritten to assert a denial</b>: partial
 *       escalations are detective only, by design (ADR-0021 D7, D8).
 *   <li><b>The payoff step is preventive (R1-1).</b> An attach that would make the role
 *       admin-defining is refused with 409 {@code RBAC_010} while a holder was assigned by a
 *       non-administrator, writes nothing, and the same attach with only administrator-assigned
 *       holders succeeds and pages row 14.
 * </ul>
 *
 * <p>Service-layer test, {@link RoleManagementService} autowired directly against real
 * Testcontainers MySQL, mirroring the sibling ITs. Counters carry no tenant tag (B3), so every
 * assertion on a counter is a delta against a baseline read just before the action.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class AttachEscalationSignalIT {

  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  private static final String ESCALATION_COUNTER = "nexus.rbac.attach_escalates_non_admin_assigned";
  private static final String BECAME_ADMIN_DEFINING_COUNTER = "nexus.rbac.role_became_admin_defining";

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private JdbcTemplate jdbc;

  // ── RES-26: the partial escalation is detected, never blocked ──────────────────────────────

  @Test
  void should_pageViaSignalAndStillAttach_when_adminAttachesRoleWriteToABenignRoleHeldViaASecondAccount() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedWholeCatalogueRole(tenantId, "TENANT_ADMIN");
    User admin = seedUser("admin", tenantId);
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    // Step 1 (RES-26's shape): a non-administrator second account assigned a BENIGN role to a
    // holder. Since A4 a non-administrator can no longer self-assign it; seeded directly.
    User holder = seedUser("holder", tenantId);
    User secondAccount = seedUser("second-account", tenantId);
    Role benignRole = seedRole("BENIGN", tenantId);
    seedActiveAssignment(tenantId, benignRole.getId(), holder.getId(), secondAccount.getId());

    // Step 2: the administrator attaches role:write to that SAME role -- legitimate and ungated.
    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);
    double before = counterValue(ESCALATION_COUNTER, "holders", "1", "page", "true");

    Logger logger = (Logger) LoggerFactory.getLogger(RoleManagementService.class);
    ListAppender<ILoggingEvent> appender = startLogCapture(logger);
    PermissionView granted;
    try {
      granted =
          roleManagementService.attachPermission(
              adminActor, benignRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

      var warnEvents =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(
                  e ->
                      "RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS"
                          .equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warnEvents).as("row 13's WARN must fire: a holder has a non-admin assigner").hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsEntry("tenantId", tenantId)
          .containsEntry("roleId", benignRole.getId())
          .containsEntry("permissionId", ROLE_WRITE_PERMISSION_ID)
          .containsEntry("holderCount", 1)
          .containsEntry("nonAdminAssignedCount", 1);
    } finally {
      stopLogCapture(logger, appender);
    }

    assertThat(granted).as("the attach is a legitimate administrative action: it must succeed").isNotNull();
    assertThat(counterValue(ESCALATION_COUNTER, "holders", "1", "page", "true"))
        .as("role:write is a paging permission, so the bounded counter carries page=true")
        .isEqualTo(before + 1.0);
  }

  // ── R1-1: the payoff step is refused ──────────────────────────────────────────────────────

  @Test
  void should_refuseWithRbac010AndWriteNothing_when_completingTheCatalogueOnARoleHeldViaANonAdministrator() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedWholeCatalogueRole(tenantId, "TENANT_ADMIN");
    User admin = seedUser("admin", tenantId);
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role nearlyAdminRole = seedAlmostWholeCatalogueRole(tenantId, "NEARLY-ADMIN");
    User holder = seedUser("holder", tenantId);
    User nonAdminAssigner = seedUser("second-account", tenantId);
    seedActiveAssignment(tenantId, nearlyAdminRole.getId(), holder.getId(), nonAdminAssigner.getId());
    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);
    double deniedBefore =
        counterValue(
            "nexus.rbac.permission_denied", "permission", "role:write", "reason", "ATTACH_PROVENANCE");

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    adminActor, nearlyAdminRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext()))
        .isInstanceOf(AttachProvenanceConflictException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_010")
        .satisfies(
            e ->
                assertThat(e.getMessage())
                    .doesNotContain(holder.getId().toString())
                    .doesNotContain(nonAdminAssigner.getId().toString()));

    assertThat(rolePermissionCount(nearlyAdminRole.getId(), ROLE_WRITE_PERMISSION_ID))
        .as("a refused attach must leave no role_permissions row")
        .isZero();
    assertThat(
            counterValue(
                "nexus.rbac.permission_denied", "permission", "role:write", "reason", "ATTACH_PROVENANCE"))
        .isEqualTo(deniedBefore + 1.0);
    assertThat(countAuditRows(tenantId, "ROLE_PERMISSION_GRANTED"))
        .as("a refusal writes no audit row, like every A3-class denial (Decision 7)")
        .isZero();
  }

  /** The same attach with only administrator-assigned holders succeeds and pages row 14. */
  @Test
  void should_attachAndPageRow14_when_completingTheCatalogueOnARoleHeldViaAnAdministrator() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedWholeCatalogueRole(tenantId, "TENANT_ADMIN");
    User admin = seedUser("admin", tenantId);
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role nearlyAdminRole = seedAlmostWholeCatalogueRole(tenantId, "NEARLY-ADMIN-2");
    User holder = seedUser("holder", tenantId);
    seedActiveAssignment(tenantId, nearlyAdminRole.getId(), holder.getId(), admin.getId());
    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);
    double before = counterValue(BECAME_ADMIN_DEFINING_COUNTER, "holders", "1");

    roleManagementService.attachPermission(
        adminActor, nearlyAdminRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

    assertThat(rolePermissionCount(nearlyAdminRole.getId(), ROLE_WRITE_PERMISSION_ID)).isEqualTo(1);
    assertThat(counterValue(BECAME_ADMIN_DEFINING_COUNTER, "holders", "1"))
        .as("row 14: the role became admin-defining with one holder; paged when holders > 0")
        .isEqualTo(before + 1.0);
  }

  /** A break-glass style holder (assigned_by = the holder, who is an administrator) never trips it. */
  @Test
  void should_attach_when_theHolderAssignedThemselvesAndIsAnAdministrator() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedWholeCatalogueRole(tenantId, "TENANT_ADMIN");
    User admin = seedUser("admin", tenantId);
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role nearlyAdminRole = seedAlmostWholeCatalogueRole(tenantId, "NEARLY-ADMIN-3");
    // The holder is ALSO an administrator (TENANT_ADMIN, seeded above) and assigned the role to
    // themselves, as a break-glass grant does (assigned_by = the target).
    seedActiveAssignment(tenantId, nearlyAdminRole.getId(), admin.getId(), admin.getId());
    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);

    roleManagementService.attachPermission(
        adminActor, nearlyAdminRole.getId(), ROLE_WRITE_PERMISSION_ID, requestContext());

    assertThat(rolePermissionCount(nearlyAdminRole.getId(), ROLE_WRITE_PERMISSION_ID)).isEqualTo(1);
  }

  /** RC-50(a): a duplicate attach to an already admin-defining role is RBAC_005, not RBAC_010. */
  @Test
  void should_answerRbac005NotRbac010_when_attachingAPermissionAnAdminDefiningRoleAlreadyHas() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedWholeCatalogueRole(tenantId, "TENANT_ADMIN");
    User admin = seedUser("admin", tenantId);
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role alreadyAdminDefining = seedWholeCatalogueRole(tenantId, "ALREADY-ADMIN-DEFINING");
    User nonAdminAssigner = seedUser("second-account", tenantId);
    User holder = seedUser("holder", tenantId);
    seedActiveAssignment(tenantId, alreadyAdminDefining.getId(), holder.getId(), nonAdminAssigner.getId());
    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    adminActor,
                    alreadyAdminDefining.getId(),
                    ROLE_WRITE_PERMISSION_ID,
                    requestContext()))
        .isInstanceOf(DuplicateRolePermissionException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_005");
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "aes-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag, UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "AES-" + tag + "-" + UUID.randomUUID(), null, false));
  }

  /** A role carrying the whole catalogue: admin-defining. */
  private Role seedWholeCatalogueRole(UUID tenantId, String name) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, nameFor(name), "aes", false));
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        role.getId().toString());
    return role;
  }

  /** A role carrying every catalogue permission except {@code role:write}. */
  private Role seedAlmostWholeCatalogueRole(UUID tenantId, String name) {
    Role role =
        roleRepository.save(new Role(uuidGenerator.newId(), tenantId, nameFor(name), "aes", false));
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE id <> UUID_TO_BIN(?)",
        role.getId().toString(),
        ROLE_WRITE_PERMISSION_ID.toString());
    return role;
  }

  /** {@code TENANT_ADMIN} is unique per tenant; every other name gets a random suffix. */
  private static String nameFor(String name) {
    return "TENANT_ADMIN".equals(name) ? name : name + "-" + UUID.randomUUID();
  }

  private UserRole seedActiveAssignment(
      UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "AttachEscalationSignalIT");
  }

  private double counterValue(String name, String... tagKeyValues) {
    var search = meterRegistry.find(name);
    for (int i = 0; i < tagKeyValues.length; i += 2) {
      search = search.tag(tagKeyValues[i], tagKeyValues[i + 1]);
    }
    Counter counter = search.counter();
    return counter != null ? counter.count() : 0.0;
  }

  private int rolePermissionCount(UUID roleId, UUID permissionId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            Integer.class,
            toBytes(roleId),
            toBytes(permissionId));
    return count == null ? 0 : count;
  }

  private int countAuditRows(UUID tenantId, String eventType) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ? AND event_type = ?",
            Integer.class,
            toBytes(tenantId),
            eventType);
    return count == null ? 0 : count;
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
