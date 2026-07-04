package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.RegisterUserUseCase;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Integration tests for {@link RegisterUserUseCase} exercising the full call chain
 * through persistence against a real MySQL container (Testcontainers, see ADR 0003).
 *
 * <p>Test strategy:
 * <ul>
 *   <li>Happy path: registration persists a PENDING user with exactly one verification token
 *   <li>Anti-enumeration: duplicate registration is silently acknowledged with no new user/token
 * </ul>
 *
 * <p>Uses a full Spring context so port implementations, encryption, and blind-index hashing
 * behave exactly as in production.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class RegistrationIT {

  @Autowired private RegisterUserUseCase registerUserUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private AuthTokenPort authTokenPort;

  private static final UUID TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!"; // EXAMPLE

  /**
   * Verifies happy path end-to-end: new user registration creates a PENDING user record
   * with exactly one verification token persisted in the MySQL database.
   *
   * <p>Given: new unique email and valid password
   * When: RegisterUserUseCase.register() called with full Spring context (real database)
   * Then: User persisted as PENDING with null emailVerifiedAt; exactly one VERIFICATION token created
   */
  @Test
  void register_newUser_createsPendingUserAndVerificationToken() {
    String email = "reg-new-" + UUID.randomUUID() + "@example.com";

    registerUserUseCase.register(TENANT_ID, email, STRONG_PASS, RequestContext.UNKNOWN);

    String hmac = emailBlindIndexService.blindIndex(email);
    User user = userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac).orElseThrow();

    assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING);
    assertThat(user.getEmailVerifiedAt()).isNull();

    int tokenCount = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        user.getId(), AuthTokenType.VERIFICATION, Instant.now().minusSeconds(3600));
    assertThat(tokenCount).isEqualTo(1);
  }

  /**
   * Verifies anti-enumeration end-to-end: duplicate registration requests return normally
   * without throwing exceptions, do not create new users or tokens, and only the original
   * token persists in the database. This prevents attackers from enumerating emails via exception handling.
   *
   * <p>Given: email already registered in database
   * When: RegisterUserUseCase.register() called twice with same email
   * Then: second call returns normally without exception; no new user created; exactly one token exists
   */
  @Test
  void register_duplicateEmail_silentlyAcknowledgesWithoutNewUser() {
    String email = "reg-dup-" + UUID.randomUUID() + "@example.com";

    registerUserUseCase.register(TENANT_ID, email, STRONG_PASS, RequestContext.UNKNOWN);
    registerUserUseCase.register(TENANT_ID, email, STRONG_PASS, RequestContext.UNKNOWN);

    String hmac = emailBlindIndexService.blindIndex(email);
    User user = userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac).orElseThrow();

    int tokenCount = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        user.getId(), AuthTokenType.VERIFICATION, Instant.now().minusSeconds(3600));
    assertThat(tokenCount).isEqualTo(1);
  }
}
