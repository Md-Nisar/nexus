package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.TokenExpiredException;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.VerifyEmailUseCase;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Integration tests for {@link VerifyEmailUseCase}: valid token, expired, consumed,
 * and concurrent consumption (SEC-6 optimistic-lock enforcement).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class VerificationTokenIT {

  @Autowired private VerifyEmailUseCase verifyEmailUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private AuthTokenPort authTokenPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private TokenGenerator tokenGenerator;
  @Autowired private TokenHasher tokenHasher;
  @Autowired private UuidGenerator uuidGenerator;

  private static final UUID TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");

  private User createPendingUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    User user = new User(
        uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRegistrationPort.save(user);
  }

  private String createToken(UUID userId, Duration ttl) {
    String rawToken = tokenGenerator.generate();
    AuthToken token = AuthToken.forVerification(
        uuidGenerator.newId(), userId, tokenHasher.hash(rawToken),
        Instant.now().plus(ttl));
    authTokenPort.save(token);
    return rawToken;
  }

  @Test
  void verify_validToken_activatesUserAndSetsConsumedAt() {
    String email = "verif-ok-" + UUID.randomUUID() + "@example.com";
    User user = createPendingUser(email);
    String rawToken = createToken(user.getId(), Duration.ofHours(24));

    verifyEmailUseCase.verify(rawToken, RequestContext.UNKNOWN);

    User activated = userRegistrationPort.findById(user.getId()).orElseThrow();
    assertThat(activated.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(activated.getEmailVerifiedAt()).isNotNull();

    AuthToken consumed = authTokenPort.findByTokenHash(tokenHasher.hash(rawToken)).orElseThrow();
    assertThat(consumed.getConsumedAt()).isNotNull();
  }

  @Test
  void verify_expiredToken_throwsTokenExpiredException() {
    String email = "verif-exp-" + UUID.randomUUID() + "@example.com";
    User user = createPendingUser(email);
    String rawToken = createToken(user.getId(), Duration.ofSeconds(-1)); // already expired

    assertThatThrownBy(() -> verifyEmailUseCase.verify(rawToken, RequestContext.UNKNOWN))
        .isInstanceOf(TokenExpiredException.class);
  }

  @Test
  void verify_consumedToken_throwsTokenExpiredException() {
    String email = "verif-cons-" + UUID.randomUUID() + "@example.com";
    User user = createPendingUser(email);
    String rawToken = createToken(user.getId(), Duration.ofHours(24));

    verifyEmailUseCase.verify(rawToken, RequestContext.UNKNOWN); // first call succeeds

    assertThatThrownBy(() -> verifyEmailUseCase.verify(rawToken, RequestContext.UNKNOWN))
        .isInstanceOf(TokenExpiredException.class); // second call rejected
  }

  /** SEC-6: concurrent consumption — exactly one transaction wins; the other gets 410. */
  @Test
  void verify_concurrentConsumption_exactlyOneSucceeds() throws InterruptedException {
    String email = "verif-concurrent-" + UUID.randomUUID() + "@example.com";
    User user = createPendingUser(email);
    String rawToken = createToken(user.getId(), Duration.ofHours(24));

    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(2);
    AtomicInteger successCount = new AtomicInteger(0);
    AtomicInteger failCount = new AtomicInteger(0);

    Runnable task = () -> {
      try {
        startLatch.await();
        verifyEmailUseCase.verify(rawToken, RequestContext.UNKNOWN);
        successCount.incrementAndGet();
      } catch (TokenExpiredException e) {
        failCount.incrementAndGet();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } finally {
        doneLatch.countDown();
      }
    };

    new Thread(task).start();
    new Thread(task).start();
    startLatch.countDown();

    boolean completed = doneLatch.await(10, TimeUnit.SECONDS);
    assertThat(completed).as("Both threads completed within timeout").isTrue();

    assertThat(successCount.get()).isEqualTo(1);
    assertThat(failCount.get()).isEqualTo(1);
  }
}
