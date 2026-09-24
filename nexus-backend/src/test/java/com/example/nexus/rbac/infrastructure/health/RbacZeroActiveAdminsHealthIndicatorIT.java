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
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
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
 * US-017 T-007(b) (04-tasks.md; 03-design.md §11.3, §8.2): no IT exists today for {@link
 * RbacZeroActiveAdminsHealthIndicator} — {@link RbacZeroActiveAdminsHealthIndicatorTest} is
 * Mockito-only. This class proves the scenarios against a real, shared Testcontainers MySQL
 * instance instead.
 *
 * <p><b>Re-scoped post-06-code-review.md H-1 (2026-09-24)</b> from the ANY-admin-equivalent
 * predicate to the caller-qualifying (literal {@code TENANT_ADMIN} OR ALL THREE dangerous
 * permissions) predicate — a custom role now needs all three grants ({@link
 * #grantAllDangerousPermissions}), not one, to enter the driving set at all. {@link
 * #should_report_down_when_theOnlyCallerQualifyingRoleIsAnAnyOnlyHolderAndTheNamedAdminIsZeroed_H1}
 * is new: it reproduces the exact H-1 regression (an ANY-only holder previously kept this
 * indicator falsely UP after the tenant's last caller-qualifying holder was removed).
 *
 * <p><b>Contamination-safe by construction.</b> {@link RbacZeroActiveAdminsHealthIndicator#health}
 * scans EVERY tenant in the database, and this Testcontainers MySQL instance is shared across the
 * whole IT suite (other classes' fixtures persist past their own test methods — e.g. the migration
 * seed itself never gives the bootstrap tenant a permanently-held {@code TENANT_ADMIN} holder).
 * Asserting the AGGREGATE {@link org.springframework.boot.health.contributor.Health} status would
 * therefore be order-dependent: a stray zeroed-out tenant left by an unrelated class would force
 * DOWN regardless of what THIS test seeded. Every scenario below instead (1) calls {@link
 * com.example.nexus.rbac.infrastructure.persistence.ZeroAdminTenantReader}'s two queries directly,
 * scoped to a fresh tenant id, and (2) inspects the indicator's own WARN log line — which always
 * names every affected tenant, unlike the actuator detail's count-only disclosure (07-security-
 * review.md M-1) — for the presence/absence of THIS test's own tenant id specifically. The one
 * exception is the "zeroed" scenario, where asserting the aggregate status IS safe: if this test's
 * own tenant is genuinely zeroed, the aggregate can never read anything but DOWN, regardless of
 * what else is going on elsewhere in the shared database.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RbacZeroActiveAdminsHealthIndicatorIT {

  // Seeded literals — V5__rbac_schema.sql header comment.
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID TENANT_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1801-7000-8000-000000000002");
  private static final long DANGEROUS_NAMES_COUNT = RbacDangerousPermissions.NAMES.size();

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

  // ── Scenario 1: DOWN -- the only admin-equivalent role in the tenant is a zeroed custom one ──

  @Test
  void should_report_down_and_logTenantId_when_theOnlyCallerQualifyingRoleIsACustomOneThatHasBeenZeroed() {
    UUID tenantId = uuidGenerator.newId();
    Role dangerousRole = seedRole(tenantId, "ZERO-1-DANGEROUS", "zero1");
    grantAllDangerousPermissions(dangerousRole.getId());
    User holder = seedUser(tenantId, "zero1-holder");
    UserRole assignment = seedActiveAssignment(tenantId, dangerousRole.getId(), holder.getId(), holder.getId());
    forceRevokeDirectly(assignment.getId());

    assertThat(
            userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("the tenant has a caller-qualifying role and must enter the driving set")
        .contains(tenantId);
    assertThat(
            userRoleRepository.findTenantsWithActiveFullyAdminEquivalentHolders(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("the tenant's only caller-qualifying role has zero active holders")
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

  // ── Scenario 2: UP -- a dangerous custom role still has holders ──────────────────────────

  @Test
  void should_report_up_when_aFullyDangerousCustomRoleStillHasHolders() {
    UUID tenantId = uuidGenerator.newId();
    Role dangerousRole = seedRole(tenantId, "UP-2-DANGEROUS", "up2");
    grantAllDangerousPermissions(dangerousRole.getId());
    User holder = seedUser(tenantId, "up2-holder");
    seedActiveAssignment(tenantId, dangerousRole.getId(), holder.getId(), holder.getId());

    assertThat(
            userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .contains(tenantId);
    assertThat(
            userRoleRepository.findTenantsWithActiveFullyAdminEquivalentHolders(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("the fully-dangerous role's one holder is still active")
        .contains(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(warnMessages(appender))
        .as("this tenant must never be reported as affected while its dangerous role still has"
            + " an active holder, regardless of unrelated tenants elsewhere in the shared DB")
        .noneMatch(message -> message.contains(tenantId.toString()));
  }

  // ── Scenario 3: UP -- TENANT_ADMIN has holders, a DIFFERENT admin-equivalent role does not ──

  /**
   * FR-2's tenant-level, not role-level, question (§8.2): a tenant with TWO caller-qualifying
   * roles where only one currently has holders is healthy overall — the exact case a role-level
   * {@code NOT EXISTS} would get wrong.
   */
  @Test
  void should_report_up_when_theLiteralTenantAdminHasHoldersButADifferentCallerQualifyingRoleDoesNot() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "up3");
    User admin = seedUser(tenantId, "up3-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role dangerousRole = seedRole(tenantId, "UP-3-DANGEROUS", "up3");
    grantAllDangerousPermissions(dangerousRole.getId());
    User dangerousHolder = seedUser(tenantId, "up3-dangerous-holder");
    UserRole dangerousAssignment =
        seedActiveAssignment(tenantId, dangerousRole.getId(), dangerousHolder.getId(), admin.getId());
    forceRevokeDirectly(dangerousAssignment.getId());

    assertThat(
            userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("the tenant has (at least) a caller-qualifying role and must enter the driving set")
        .contains(tenantId);
    assertThat(
            userRoleRepository.findTenantsWithActiveFullyAdminEquivalentHolders(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("TENANT_ADMIN still has an active holder, so the TENANT-LEVEL question is healthy"
            + " even though the OTHER caller-qualifying role in this tenant has zero holders")
        .contains(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(warnMessages(appender))
        .as("a tenant-level holder via TENANT_ADMIN must keep this tenant out of the affected"
            + " set even though one of its two admin-equivalent roles individually has none")
        .noneMatch(message -> message.contains(tenantId.toString()));
  }

  // ── Scenario 4: invisible -- the tenant has no caller-qualifying role at all (D11, RES-14) ──

  @Test
  void should_neverEnterTheDrivingSet_when_theTenantHasNoCallerQualifyingRoleAtAll() {
    UUID tenantId = uuidGenerator.newId();
    Role benignRole = seedRole(tenantId, "UP-4-BENIGN", "up4");
    User holder = seedUser(tenantId, "up4-holder");
    seedActiveAssignment(tenantId, benignRole.getId(), holder.getId(), holder.getId());

    assertThat(
            userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("a tenant with no caller-qualifying role at all must never enter the driving set")
        .doesNotContain(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(warnMessages(appender)).noneMatch(message -> message.contains(tenantId.toString()));
  }

  // ── Scenario 5 (H-1 regression, 06-code-review.md, 2026-09-24): invisible -- an ANY-only role ─
  // never enters the driving set, even though the tenant's literal TENANT_ADMIN is zeroed ──────

  /**
   * Reproduces the exact H-1 finding: before this fix, an ANY-only holder (a role carrying just
   * ONE dangerous permission) kept this indicator's SQL "admin-equivalent" driving set entry
   * alive, which — combined with the OLD lockout guard checking the same ANY population — could
   * let a tenant be revoked down to zero CALLER-QUALIFYING holders while both the lockout guard
   * and this indicator kept reporting healthy. Now, an ANY-only role never enters the driving set
   * at all, so a tenant whose only caller-qualifying role (the literal {@code TENANT_ADMIN}) has
   * been zeroed correctly reports DOWN regardless of any ANY-only role's holder count.
   */
  @Test
  void should_report_down_when_theOnlyCallerQualifyingRoleIsAnAnyOnlyHolderAndTheNamedAdminIsZeroed_H1() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedRole(tenantId, "TENANT_ADMIN", "h1");
    User admin = seedUser(tenantId, "h1-admin");
    UserRole adminAssignment = seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());
    forceRevokeDirectly(adminAssignment.getId());

    Role anyOnlyRole = seedRole(tenantId, "H1-ANY-ONLY", "h1");
    grantPermission(anyOnlyRole.getId(), USER_WRITE_PERMISSION_ID); // ONE permission only -- ANY, not ALL
    User anyOnlyHolder = seedUser(tenantId, "h1-any-only-holder");
    seedActiveAssignment(tenantId, anyOnlyRole.getId(), anyOnlyHolder.getId(), anyOnlyHolder.getId());

    assertThat(
            userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("the ANY-only role must never enter the driving set -- only the (now-zeroed) literal"
            + " TENANT_ADMIN makes this tenant caller-qualifying at all")
        .contains(tenantId);
    assertThat(
            userRoleRepository.findTenantsWithActiveFullyAdminEquivalentHolders(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .as("the ANY-only holder must never count as a caller-qualifying holder")
        .doesNotContain(tenantId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    org.springframework.boot.health.contributor.Health health;
    try {
      health = indicator().health();
    } finally {
      stopLogCapture(appender);
    }

    // Safe direction (class Javadoc): this test's own tenant being genuinely zeroed forces DOWN.
    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(warnMessages(appender)).anyMatch(message -> message.contains(tenantId.toString()));
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

  /** H-1: only a role carrying ALL THREE dangerous permissions is caller-qualifying. */
  private void grantAllDangerousPermissions(UUID roleId) {
    grantPermission(roleId, ROLE_WRITE_PERMISSION_ID);
    grantPermission(roleId, USER_WRITE_PERMISSION_ID);
    grantPermission(roleId, TENANT_WRITE_PERMISSION_ID);
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
