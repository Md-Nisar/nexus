package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-017 T-007(b) / US-018 T-019 (row 15; 04-tasks.md, 03-design.md §5.1): proves the zero-active-
 * administrators detection against a real, shared Testcontainers MySQL instance, because {@link
 * RbacZeroActiveAdminsHealthIndicatorTest} is Mockito-only.
 *
 * <p><b>Re-seeded under the new definition (US-018 T-019).</b> A tenant enters the driving set iff
 * it has a role carrying EVERY permission of the catalogue ({@link #grantWholeCatalogue}); the
 * name {@code TENANT_ADMIN} no longer matters, and a role one permission short is not counted
 * ({@link #grantCatalogueMinusOne}). This replaces the caller-qualifying scenarios (literal name or
 * all three dangerous permissions) and the H-1 scenario, whose population no longer exists.
 *
 * <p><b>Contamination-safe by construction.</b> {@link RbacZeroActiveAdminsHealthIndicator#health}
 * scans EVERY tenant in the database, and this Testcontainers MySQL instance is shared across the
 * whole IT suite. Asserting the AGGREGATE {@link org.springframework.boot.health.contributor.Health}
 * status would therefore be order-dependent. Every scenario below instead (1) calls {@link
 * com.example.nexus.rbac.infrastructure.persistence.ZeroAdminTenantReader}'s two queries directly,
 * scoped to a fresh tenant id, and (2) inspects the indicator's own WARN log line, which always
 * names every affected tenant, for the presence or absence of THIS test's own tenant id. The one
 * exception is the "zeroed" scenario, where asserting the aggregate status IS safe: if this test's
 * own tenant is genuinely zeroed, the aggregate can never read anything but DOWN.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RbacZeroActiveAdminsHealthIndicatorIT {

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private RbacZeroActiveAdminsHealthIndicator indicator() {
    // The real repository bean also implements ZeroAdminTenantReader (US-017 D25) -- this
    // constructs the production indicator around the SAME bean the running application wires,
    // rather than re-deriving a mock, so this exercises the real SQL end to end.
    return new RbacZeroActiveAdminsHealthIndicator(userRoleRepository);
  }

  // -- Scenario 1: DOWN -- the only admin-defining role is a custom one whose holder is gone ----

  @Test
  void should_report_down_and_logTenantId_when_aCustomAdminDefiningRoleHasZeroHolders() {
    UUID tenantId = uuidGenerator.newId();
    Role adminDefiningRole = seedRole(tenantId, "ZERO-1-CUSTOM-ADMIN", "zero1");
    grantWholeCatalogue(adminDefiningRole.getId());
    User holder = seedUser(tenantId, "zero1-holder");
    UserRole assignment =
        seedActiveAssignment(tenantId, adminDefiningRole.getId(), holder.getId(), holder.getId());
    forceRevokeDirectly(assignment.getId());

    assertThat(userRoleRepository.findTenantsWithAnAdminDefiningRole())
        .as("the tenant has an admin-defining role and must enter the driving set")
        .contains(tenantId);
    assertThat(userRoleRepository.findTenantsWithActiveAdminDefiningHolders())
        .as("the tenant's only admin-defining role has zero active holders")
        .doesNotContain(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    org.springframework.boot.health.contributor.Health health;
    try {
      health = indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    // Safe direction: this test's own tenant being genuinely zeroed forces DOWN regardless of
    // what else is present elsewhere in the shared database (see class Javadoc).
    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails())
        .as("07-security-review.md M-1: count-only disclosure, reconfirmed against a real DB")
        .doesNotContainKey("tenantIds");
    assertThat(warnMessages(appender)).anyMatch(message -> message.contains(tenantId.toString()));
  }

  // -- US-018 T-026 / RC-36.4: an active assignment on a soft-deleted role pages, count only -----

  @Test
  void should_report_down_withCountOnly_when_anActiveAssignmentReferencesASoftDeletedRole() {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId, "DELROLE-" + UUID.randomUUID(), "deleted");
    User holder = seedUser(tenantId, "deleted-role-holder");
    UserRole forged = seedActiveAssignment(tenantId, role.getId(), holder.getId(), holder.getId());
    jdbc.update(
        "UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?", toBytes(role.getId()));

    org.springframework.boot.health.contributor.Health health;
    try {
      health = indicator().health();
    } finally {
      // The forged row breaks the invariant for the whole shared database: restore it so the
      // other tests of this class (and the suite) do not see a DOWN they did not cause.
      forceRevokeDirectly(forged.getId());
    }

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails())
        .extractingByKey("deletedRoleActiveAssignments")
        .satisfies(count -> assertThat(((Number) count).longValue()).isGreaterThanOrEqualTo(1L));
    assertThat(health.getDetails().toString())
        .as("count only: no role, user or tenant id")
        .doesNotContain(role.getId().toString())
        .doesNotContain(holder.getId().toString())
        .doesNotContain(tenantId.toString());
  }

  // -- Scenario 2: UP -- TENANT_ADMIN (carrying the whole catalogue) has a holder ---------------

  @Test
  void should_report_up_when_tenantAdminCarryingTheWholeCatalogueStillHasAHolder() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "up2");
    grantWholeCatalogue(adminRole.getId());
    User holder = seedUser(tenantId, "up2-holder");
    seedActiveAssignment(tenantId, adminRole.getId(), holder.getId(), holder.getId());

    assertThat(userRoleRepository.findTenantsWithAnAdminDefiningRole()).contains(tenantId);
    assertThat(userRoleRepository.findTenantsWithActiveAdminDefiningHolders())
        .as("the admin-defining role's one holder is still active")
        .contains(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(warnMessages(appender))
        .as("this tenant must never be reported as affected while its admin-defining role still"
            + " has an active holder, regardless of unrelated tenants in the shared DB")
        .noneMatch(message -> message.contains(tenantId.toString()));
  }

  // -- Scenario 3: UP -- one admin-defining role has holders, another does not (tenant level) ---

  /**
   * The question is tenant-level, not role-level (§8.2): a tenant with TWO admin-defining roles
   * where only one currently has holders is healthy overall, the exact case a role-level {@code NOT
   * EXISTS} would get wrong.
   */
  @Test
  void should_report_up_when_oneAdminDefiningRoleHasHoldersButAnotherDoesNot() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "up3");
    grantWholeCatalogue(adminRole.getId());
    User admin = seedUser(tenantId, "up3-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role customAdminRole = seedRole(tenantId, "UP-3-CUSTOM-ADMIN", "up3");
    grantWholeCatalogue(customAdminRole.getId());
    User customHolder = seedUser(tenantId, "up3-custom-holder");
    UserRole customAssignment =
        seedActiveAssignment(tenantId, customAdminRole.getId(), customHolder.getId(), admin.getId());
    forceRevokeDirectly(customAssignment.getId());

    assertThat(userRoleRepository.findTenantsWithAnAdminDefiningRole()).contains(tenantId);
    assertThat(userRoleRepository.findTenantsWithActiveAdminDefiningHolders())
        .as("TENANT_ADMIN still has an active holder, so the TENANT-LEVEL question is healthy")
        .contains(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(warnMessages(appender)).noneMatch(message -> message.contains(tenantId.toString()));
  }

  // -- Scenario 4: invisible -- no admin-defining role, even one permission short ---------------

  @Test
  void should_neverEnterTheDrivingSet_when_aRoleIsOnePermissionShortOfTheCatalogue() {
    UUID tenantId = uuidGenerator.newId();
    Role almostRole = seedRole(tenantId, "UP-4-ALMOST-ADMIN", "up4");
    grantCatalogueMinusOne(almostRole.getId());
    User holder = seedUser(tenantId, "up4-holder");
    UserRole assignment =
        seedActiveAssignment(tenantId, almostRole.getId(), holder.getId(), holder.getId());
    forceRevokeDirectly(assignment.getId());

    assertThat(userRoleRepository.findTenantsWithAnAdminDefiningRole())
        .as("a role one permission short is not admin-defining: not counted")
        .doesNotContain(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(warnMessages(appender)).noneMatch(message -> message.contains(tenantId.toString()));
  }

  // -- Scenario 5: invisible -- the name TENANT_ADMIN alone no longer matters -------------------

  @Test
  void should_neverEnterTheDrivingSet_when_aRoleNamedTenantAdminCarriesNothing() {
    UUID tenantId = uuidGenerator.newId();
    Role namedOnly = seedRole(tenantId, "TENANT_ADMIN", "up5");
    User holder = seedUser(tenantId, "up5-holder");
    UserRole assignment =
        seedActiveAssignment(tenantId, namedOnly.getId(), holder.getId(), holder.getId());
    forceRevokeDirectly(assignment.getId());

    assertThat(userRoleRepository.findTenantsWithAnAdminDefiningRole())
        .as("ADR-0021 D3: names stop mattering, the catalogue defines an administrator")
        .doesNotContain(tenantId);
  }

  // ── Seeding helpers (mirrors LastAdminLockoutIT's identically-named helpers) ─────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "zaahi-" + tag + "-" + UUID.randomUUID() + "@example.com";
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

  /** The one definition (ADR-0021 D3): an admin-defining role carries EVERY catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    catalogueIds().forEach(permissionId -> grantPermission(roleId, permissionId));
  }

  /** Every catalogue permission except the first one: one permission short of admin-defining. */
  private void grantCatalogueMinusOne(UUID roleId) {
    List<UUID> ids = catalogueIds();
    ids.subList(1, ids.size()).forEach(permissionId -> grantPermission(roleId, permissionId));
  }

  private List<UUID> catalogueIds() {
    return jdbc.query(
        "SELECT id FROM permissions ORDER BY id",
        (rs, rowNum) -> {
          ByteBuffer buf = ByteBuffer.wrap(rs.getBytes(1));
          return new UUID(buf.getLong(), buf.getLong());
        });
  }

  private UserRole seedActiveAssignment(
      UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  /** Test-cleanup-style bypass of the guard under test: force-revokes a row directly via JDBC. */
  private void forceRevokeDirectly(UUID userRoleId) {
    jdbc.update(
        "UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ? AND revoked_at IS NULL",
        toBytes(userRoleId));
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(RbacZeroActiveAdminsHealthIndicator.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    Logger logger = (Logger) LoggerFactory.getLogger(RbacZeroActiveAdminsHealthIndicator.class);
    logger.detachAppender(appender);
    appender.stop();
  }

  private List<String> warnMessages(ListAppender<ILoggingEvent> appender) {
    return appender.list.stream()
        .filter(event -> event.getLevel() == ch.qos.logback.classic.Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
