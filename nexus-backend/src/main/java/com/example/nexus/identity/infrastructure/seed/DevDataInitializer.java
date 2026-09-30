package com.example.nexus.identity.infrastructure.seed;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.RbacRoleNames;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds a pre-verified E2E test user on startup when the {@code dev} profile is active.
 *
 * <p>The user is created in ACTIVE status (email verification bypassed) so Playwright E2E
 * tests can log in immediately without a verification email flow. Idempotent — skips
 * insertion if the user already exists.
 *
 * <p>The user is also assigned the seeded {@code TENANT_ADMIN} system role (all permissions), so
 * E2E and performance tests can exercise the RBAC endpoints. This is dev-only: it goes through
 * {@link UserRoleAssignmentPort}, the same persistence path as a real assignment, but skips the
 * caller-permission checks that would otherwise make the first admin impossible to create.
 *
 * <p>Credentials: {@code test@example.com} / {@code TestPass99!}
 */
@Component
@Profile("dev")
public class DevDataInitializer implements ApplicationRunner {

  private static final Logger log = LoggerFactory.getLogger(DevDataInitializer.class);

  private static final String E2E_EMAIL = "test@example.com";
  private static final String E2E_PASSWORD = "TestPass99!";

  private final UserRegistrationPort userRegistrationPort;
  private final EmailBlindIndexService emailBlindIndexService;
  private final PasswordHasherPort passwordHasherPort;
  private final UuidGenerator uuidGenerator;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final UUID defaultTenantId;

  public DevDataInitializer(
      UserRegistrationPort userRegistrationPort,
      EmailBlindIndexService emailBlindIndexService,
      PasswordHasherPort passwordHasherPort,
      UuidGenerator uuidGenerator,
      UserRoleAssignmentPort userRoleAssignmentPort,
      @Value("${nexus.identity.default-tenant-id}") UUID defaultTenantId) {
    this.userRegistrationPort = userRegistrationPort;
    this.emailBlindIndexService = emailBlindIndexService;
    this.passwordHasherPort = passwordHasherPort;
    this.uuidGenerator = uuidGenerator;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.defaultTenantId = defaultTenantId;
  }

  @Override
  @Transactional
  public void run(ApplicationArguments args) {
    String emailHmac = emailBlindIndexService.blindIndex(E2E_EMAIL);

    Optional<User> existing =
        userRegistrationPort.findByTenantAndEmailHmac(defaultTenantId, emailHmac);
    if (existing.isPresent()) {
      log.debug("E2E test user already exists — skipping seed");
      grantTenantAdmin(existing.get());
      return;
    }

    String passwordHash = passwordHasherPort.hash(E2E_PASSWORD);
    Instant now = Instant.now();

    User user = new User(
        uuidGenerator.newId(),
        defaultTenantId,
        new EmailCipher(E2E_EMAIL),
        emailHmac,
        passwordHash,
        now);
    user = userRegistrationPort.save(user);

    // Bypass the email verification flow — mark ACTIVE immediately for E2E use.
    user.verify(now);
    userRegistrationPort.save(user);

    log.info("E2E test user seeded: {} (tenant {})", E2E_EMAIL, defaultTenantId);
    grantTenantAdmin(user);
  }

  /** Idempotent: also runs for a user seeded by an earlier version, before this role existed. */
  private void grantTenantAdmin(User user) {
    Optional<UUID> roleId =
        userRoleAssignmentPort.findRoleIdByName(defaultTenantId, RbacRoleNames.TENANT_ADMIN);
    if (roleId.isEmpty()) {
      log.warn("{} role not found for tenant {} — test user left without roles",
          RbacRoleNames.TENANT_ADMIN, defaultTenantId);
      return;
    }
    if (userRoleAssignmentPort.hasActiveAssignment(user.getId(), roleId.get())) {
      return;
    }
    userRoleAssignmentPort.assign(user.getId(), roleId.get(), defaultTenantId, user.getId());
    log.info("E2E test user assigned {}", RbacRoleNames.TENANT_ADMIN);
  }
}
