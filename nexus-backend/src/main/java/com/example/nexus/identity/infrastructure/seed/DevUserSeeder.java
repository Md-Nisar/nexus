package com.example.nexus.identity.infrastructure.seed;

import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Creates the dev persona users (US-019 C1). Dev only: every persona shares one well-known
 * password, so the {@code dev & !break-glass & !prod} guard is the control that keeps these
 * accounts out of shared environments (RC-63(g), T-E52).
 *
 * <p>Idempotent: a user is looked up by its blind index and created only when absent. No email and
 * no password is ever logged.
 *
 * <p>Credentials: every persona signs in with {@code TestPass99!}.
 */
@Component
@Profile("dev & !break-glass & !prod")
public class DevUserSeeder {

  /** How a seeded user ends up: verified, locked far into the future, or never verified. */
  enum State {
    ACTIVE,
    LOCKED,
    PENDING
  }

  static final String E2E_EMAIL = "test@example.com";
  static final String SECOND_ADMIN_EMAIL = "admin2@example.com";
  static final String MEMBER_EMAIL = "member@example.com";
  static final String ROLE_MANAGER_EMAIL = "role-manager@example.com";
  static final String USER_MANAGER_EMAIL = "user-manager@example.com";
  static final String LOCKED_EMAIL = "locked@example.com";
  static final String PENDING_EMAIL = "pending@example.com";
  static final String SECOND_TENANT_ADMIN_EMAIL = "other-tenant-admin@example.com";
  static final String ROLE_READER_USER_MANAGER_EMAIL = "role-reader-user-manager@example.com";
  static final String AUDITOR_EMAIL = "auditor@example.com";
  static final String TARGET_A_EMAIL = "target-a@example.com";
  static final String TARGET_B_EMAIL = "target-b@example.com";

  /**
   * US-020 RC-68 item 4: a never-verified target whose synthetic {@code .invalid} address carries
   * U+202E RIGHT-TO-LEFT OVERRIDE in its local part, for the console's hidden-character e2e. Seeded
   * here, below the registration validation, so the e2e does not depend on registration accepting
   * the address: once F-5 rejects such addresses at registration, this row stays and the e2e stays
   * green. Written with a code point, so the source holds no invisible character.
   */
  static final String HIDDEN_CHARACTER_TARGET_EMAIL =
      "e2e-rc68-seeded" + Character.toString(0x202E) + "txt@hidden-characters.invalid";

  /**
   * Fixture-only second tenant. Login resolves its tenant from the configured default, so these
   * users can never authenticate; they exist for cross-tenant negative tests.
   */
  public static final UUID SECOND_TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000002");

  public static final UUID SECOND_TENANT_ADMIN_ID =
      UUID.fromString("00000000-0000-7000-8000-0000000000a2");

  private static final String PASSWORD = "TestPass99!";
  private static final Duration LOCK_DURATION = Duration.ofDays(365L * 100);

  private final UserRegistrationPort userRegistrationPort;
  private final EmailBlindIndexService emailBlindIndexService;
  private final PasswordHasherPort passwordHasherPort;
  private final UuidGenerator uuidGenerator;

  public DevUserSeeder(
      UserRegistrationPort userRegistrationPort,
      EmailBlindIndexService emailBlindIndexService,
      PasswordHasherPort passwordHasherPort,
      UuidGenerator uuidGenerator) {
    this.userRegistrationPort = userRegistrationPort;
    this.emailBlindIndexService = emailBlindIndexService;
    this.passwordHasherPort = passwordHasherPort;
    this.uuidGenerator = uuidGenerator;
  }

  /** Ensures a user with a generated id exists in the tenant and returns its id. */
  UUID ensureUser(UUID tenantId, String email, State state, SeedReport report) {
    return ensure(tenantId, email, state, uuidGenerator::newId, report);
  }

  /** Ensures a user with a fixed id exists in the tenant and returns its id. */
  UUID ensureUser(UUID tenantId, UUID userId, String email, State state, SeedReport report) {
    return ensure(tenantId, email, state, () -> userId, report);
  }

  private UUID ensure(
      UUID tenantId, String email, State state, Supplier<UUID> idSource, SeedReport report) {
    String emailHmac = emailBlindIndexService.blindIndex(email);
    Optional<User> existing = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac);
    if (existing.isPresent()) {
      report.skipped();
      return existing.get().getId();
    }

    Instant now = Instant.now();
    User user =
        new User(
            idSource.get(),
            tenantId,
            new EmailCipher(email),
            emailHmac,
            passwordHasherPort.hash(PASSWORD),
            now);
    user = userRegistrationPort.save(user);

    if (state != State.PENDING) {
      // Bypass the email verification flow: the persona is usable immediately.
      user.verify(now);
    }
    if (state == State.LOCKED) {
      user.lockAccount(now.plus(LOCK_DURATION));
    }
    if (state != State.PENDING) {
      user = userRegistrationPort.save(user);
    }
    report.created();
    return user.getId();
  }
}
