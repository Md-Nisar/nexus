package com.example.nexus.identity.infrastructure.seed;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Instant;
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
  private final UUID defaultTenantId;

  public DevDataInitializer(
      UserRegistrationPort userRegistrationPort,
      EmailBlindIndexService emailBlindIndexService,
      PasswordHasherPort passwordHasherPort,
      UuidGenerator uuidGenerator,
      @Value("${nexus.identity.default-tenant-id}") UUID defaultTenantId) {
    this.userRegistrationPort = userRegistrationPort;
    this.emailBlindIndexService = emailBlindIndexService;
    this.passwordHasherPort = passwordHasherPort;
    this.uuidGenerator = uuidGenerator;
    this.defaultTenantId = defaultTenantId;
  }

  @Override
  @Transactional
  public void run(ApplicationArguments args) {
    String emailHmac = emailBlindIndexService.blindIndex(E2E_EMAIL);

    if (userRegistrationPort.findByTenantAndEmailHmac(defaultTenantId, emailHmac).isPresent()) {
      log.debug("E2E test user already exists — skipping seed");
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
  }
}
