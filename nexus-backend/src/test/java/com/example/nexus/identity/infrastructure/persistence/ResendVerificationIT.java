package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.ResendVerificationUseCase;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Integration tests for {@link ResendVerificationUseCase}: successful resend,
 * 60-second cooldown window, and 24-hour daily limit.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class ResendVerificationIT {

  @Autowired private ResendVerificationUseCase resendVerificationUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private AuthTokenPort authTokenPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private TokenGenerator tokenGenerator;
  @Autowired private TokenHasher tokenHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private static final UUID TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");

  private User createPendingUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    User user = new User(
        uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRegistrationPort.save(user);
  }

  @Test
  void resend_pendingUser_createsNewVerificationToken() {
    String email = "resend-ok-" + UUID.randomUUID() + "@example.com";
    createPendingUser(email);

    resendVerificationUseCase.resend(TENANT_ID, email, RequestContext.UNKNOWN);

    String hmac = emailBlindIndexService.blindIndex(email);
    User user = userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac).orElseThrow();
    int count = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        user.getId(), AuthTokenType.VERIFICATION, Instant.now().minusSeconds(3600));
    assertThat(count).isEqualTo(1);
  }

  @Test
  void resend_withinCooldown_throwsRateLimitException() {
    String email = "resend-cool-" + UUID.randomUUID() + "@example.com";
    createPendingUser(email);

    resendVerificationUseCase.resend(TENANT_ID, email, RequestContext.UNKNOWN); // first resend — succeeds

    assertThatThrownBy(() -> resendVerificationUseCase.resend(TENANT_ID, email, RequestContext.UNKNOWN))
        .isInstanceOf(RateLimitException.class);
  }

  @Test
  void resend_exceed24hLimit_throwsRateLimitException() {
    String email = "resend-24h-" + UUID.randomUUID() + "@example.com";
    User user = createPendingUser(email);

    // Create 5 tokens via the port (DB sets created_at = NOW())
    for (int i = 0; i < 5; i++) {
      String rawToken = tokenGenerator.generate();
      AuthToken token = AuthToken.forVerification(
          uuidGenerator.newId(), user.getId(), tokenHasher.hash(rawToken),
          Instant.now().plus(Duration.ofHours(24)));
      authTokenPort.save(token);
    }

    // Backdate all tokens to 2 minutes ago:
    // - outside the 60s cooldown window → first rate-limit check passes
    // - inside the 24h window → second rate-limit check fires (5 ≥ 5 → 429)
    String hmac = emailBlindIndexService.blindIndex(email);
    jdbc.update(
        "UPDATE auth_tokens at "
            + "INNER JOIN users u ON at.user_id = u.id "
            + "SET at.created_at = ? "
            + "WHERE u.email_hmac = ? AND at.type = 'VERIFICATION'",
        Timestamp.from(Instant.now().minusSeconds(120)),
        hmac);

    assertThatThrownBy(() -> resendVerificationUseCase.resend(TENANT_ID, email, RequestContext.UNKNOWN))
        .isInstanceOf(RateLimitException.class);
  }

  @Test
  void resend_unknownEmail_returnsVoidWithoutError() {
    String email = "resend-unknown-" + UUID.randomUUID() + "@example.com";

    // No user exists — anti-enumeration: must return silently, never throw
    assertThatNoException()
        .isThrownBy(() -> resendVerificationUseCase.resend(TENANT_ID, email, RequestContext.UNKNOWN));
  }
}
