package com.example.nexus.identity.infrastructure.seed;

import com.example.nexus.rbac.domain.RbacRoleNames;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds the dev personas on startup when the {@code dev} profile is active (US-019 C1): the E2E
 * administrator, a second administrator, a member, a Role Manager, a User Manager, a locked user
 * and a pending user in the bootstrap tenant, plus a fixture-only second tenant whose administrator
 * holds a custom role built from the whole permission catalogue.
 *
 * <p>US-020 T-014 (design §19.4) adds a role-reader user manager (never an administrator) and an
 * auditor, who sign in, and two ACTIVE assignment targets nobody signs in as: target A holds no
 * role, target B holds one dedicated custom role so its read expectations never move.
 *
 * <p>Runs as one transaction: a partial seed rolls back and completes on the next start. Idempotent
 * through {@link DevUserSeeder} and {@link DevRbacSeeder}. Every persona assignment records the
 * seeded E2E administrator as {@code assigned_by}, never the persona itself, because a
 * self-reference is the break-glass signature (RC-63(g)). The E2E administrator's own {@code
 * TENANT_ADMIN} assignment is the root of that chain and keeps its self-reference.
 *
 * <p>Never active under {@code break-glass} or {@code prod}: a process in either must not create
 * known-password administrators through this unchecked path. All personas share one dev-only
 * password (see {@link DevUserSeeder}); no email or password is logged.
 */
@Component
@Profile("dev & !break-glass & !prod")
public class DevDataInitializer implements ApplicationRunner {

  static final String ROLE_MANAGER_ROLE = "Role Manager";
  static final String USER_MANAGER_ROLE = "User Manager";
  static final String DEV_ADMIN_ROLE = "Dev Administrator";
  static final String ROLE_READER_USER_MANAGER_ROLE = "Role-reader User Manager";
  static final String AUDITOR_ROLE = "Auditor";
  static final String TARGET_ROLE = "Target Reader";

  private static final Logger log = LoggerFactory.getLogger(DevDataInitializer.class);

  private final DevUserSeeder userSeeder;
  private final DevRbacSeeder rbacSeeder;
  private final Environment environment;
  private final UUID defaultTenantId;

  public DevDataInitializer(
      DevUserSeeder userSeeder,
      DevRbacSeeder rbacSeeder,
      Environment environment,
      @Value("${nexus.identity.default-tenant-id}") UUID defaultTenantId) {
    this.userSeeder = userSeeder;
    this.rbacSeeder = rbacSeeder;
    this.environment = environment;
    this.defaultTenantId = defaultTenantId;
  }

  @Override
  @Transactional
  public void run(ApplicationArguments args) {
    log.warn(
        "DEV_SEED_ACTIVE profiles={} known-password accounts are being seeded",
        Arrays.toString(environment.getActiveProfiles()));
    SeedReport report = new SeedReport();

    UUID admin = userSeeder.ensureUser(
        defaultTenantId, DevUserSeeder.E2E_EMAIL, DevUserSeeder.State.ACTIVE, report);
    rbacSeeder.ensureAssignment(
        defaultTenantId, admin, RbacRoleNames.TENANT_ADMIN, admin, report);

    seedBootstrapTenantPersonas(admin, report);
    seedSecondTenant(admin, report);

    log.info(
        "DEV_SEED_COMPLETED created={} skipped={}", report.createdCount(), report.skippedCount());
  }

  private void seedBootstrapTenantPersonas(UUID admin, SeedReport report) {
    String roleManager = rbacSeeder.ensureRole(
        defaultTenantId, ROLE_MANAGER_ROLE, "Dev persona: manages roles",
        Set.of("role:read", "role:write"), report);
    String userManager = rbacSeeder.ensureRole(
        defaultTenantId, USER_MANAGER_ROLE, "Dev persona: manages user role assignments",
        Set.of("user:read", "user:role:assign", "user:directory:read"), report);
    String roleReaderUserManager = rbacSeeder.ensureRole(
        defaultTenantId, ROLE_READER_USER_MANAGER_ROLE,
        "Dev persona: reads roles and manages user role assignments",
        Set.of("role:read", "user:read", "user:role:assign", "user:directory:read"), report);
    String auditor = rbacSeeder.ensureRole(
        defaultTenantId, AUDITOR_ROLE, "Dev persona: reads roles and the audit trail",
        Set.of("role:read", "audit:read"), report);
    String targetRole = rbacSeeder.ensureRole(
        defaultTenantId, TARGET_ROLE, "Dev fixture: the one role held by assignment target B",
        Set.of("role:read"), report);

    persona(DevUserSeeder.SECOND_ADMIN_EMAIL, DevUserSeeder.State.ACTIVE,
        RbacRoleNames.TENANT_ADMIN, admin, report);
    persona(DevUserSeeder.MEMBER_EMAIL, DevUserSeeder.State.ACTIVE,
        RbacRoleNames.MEMBER, admin, report);
    persona(DevUserSeeder.ROLE_MANAGER_EMAIL, DevUserSeeder.State.ACTIVE,
        roleManager, admin, report);
    persona(DevUserSeeder.USER_MANAGER_EMAIL, DevUserSeeder.State.ACTIVE,
        userManager, admin, report);
    persona(DevUserSeeder.LOCKED_EMAIL, DevUserSeeder.State.LOCKED,
        RbacRoleNames.MEMBER, admin, report);
    userSeeder.ensureUser(
        defaultTenantId, DevUserSeeder.PENDING_EMAIL, DevUserSeeder.State.PENDING, report);
    persona(DevUserSeeder.ROLE_READER_USER_MANAGER_EMAIL, DevUserSeeder.State.ACTIVE,
        roleReaderUserManager, admin, report);
    persona(DevUserSeeder.AUDITOR_EMAIL, DevUserSeeder.State.ACTIVE, auditor, admin, report);
    userSeeder.ensureUser(
        defaultTenantId, DevUserSeeder.TARGET_A_EMAIL, DevUserSeeder.State.ACTIVE, report);
    persona(DevUserSeeder.TARGET_B_EMAIL, DevUserSeeder.State.ACTIVE, targetRole, admin, report);
  }

  private void persona(
      String email, DevUserSeeder.State state, String roleName, UUID admin, SeedReport report) {
    UUID userId = userSeeder.ensureUser(defaultTenantId, email, state, report);
    rbacSeeder.ensureAssignment(defaultTenantId, userId, roleName, admin, report);
  }

  private void seedSecondTenant(UUID admin, SeedReport report) {
    String role = rbacSeeder.ensureRoleWithEveryPermission(
        DevUserSeeder.SECOND_TENANT_ID, DEV_ADMIN_ROLE,
        "Dev fixture: every permission, second tenant", report);
    UUID userId = userSeeder.ensureUser(
        DevUserSeeder.SECOND_TENANT_ID, DevUserSeeder.SECOND_TENANT_ADMIN_ID,
        DevUserSeeder.SECOND_TENANT_ADMIN_EMAIL, DevUserSeeder.State.ACTIVE, report);
    rbacSeeder.ensureAssignment(DevUserSeeder.SECOND_TENANT_ID, userId, role, admin, report);
  }
}
