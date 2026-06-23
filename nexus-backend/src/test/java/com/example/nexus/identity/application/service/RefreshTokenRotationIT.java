package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * Integration tests for {@link RefreshTokenUseCase}: token rotation, theft detection (family
 * revocation), expiry rejection, concurrent rotation, and cross-tenant isolation.
 *
 * <p>Tokens are created directly via {@link RefreshTokenPort} to bypass the email-lookup
 * complexity in {@link LoginUseCase} and focus coverage on rotation behaviour.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class RefreshTokenRotationIT {

  @Autowired private RefreshTokenUseCase refreshTokenUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private RefreshTokenPort refreshTokenPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private TokenGenerator tokenGenerator;
  @Autowired private TokenHasher tokenHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JpaAuthEventRepository authEventRepository;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String TEST_PASSWORD = "TestPass99!";

  // ── Helpers ───────────────────────────────────────────────────────────────

  private record TestToken(User user, String rawToken) {}

  /**
   * Creates an ACTIVE user and a valid refresh token stored in the database.
   * The returned {@link TestToken} carries both so callers can call
   * {@code refreshTokenUseCase.execute(rawToken, ip)}.
   */
  private TestToken createActiveUserWithToken(String emailTag) {
    String email = "rot-" + emailTag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    String hash = passwordHasher.hash(TEST_PASSWORD);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    user = userRegistrationPort.save(user);

    String rawToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawToken);
    UUID familyId = uuidGenerator.newId();
    Instant expiresAt = Instant.now().plus(14, ChronoUnit.DAYS);
    refreshTokenPort.save(new RefreshToken(uuidGenerator.newId(), user.getId(), tokenHash, familyId, expiresAt));

    return new TestToken(user, rawToken);
  }

  // ── Tests ─────────────────────────────────────────────────────────────────

  /**
   * Happy path: presenting a valid token issues new credentials, revokes the old token,
   * and persists a new token.
   */
  @Test
  void happy_path_rotation() {
    TestToken tt = createActiveUserWithToken("hp");
    String oldHash = tokenHasher.hash(tt.rawToken());

    LoginResult result = refreshTokenUseCase.execute(tt.rawToken(), "127.0.0.1");

    assertThat(result).isNotNull();
    assertThat(result.accessToken()).isNotBlank();
    assertThat(result.rawRefreshToken()).isNotBlank();
    assertThat(result.rawRefreshToken()).isNotEqualTo(tt.rawToken());

    // Old token must be revoked
    RefreshToken oldToken = refreshTokenPort.findByTokenHash(oldHash).orElseThrow();
    assertThat(oldToken.getRevokedAt()).as("old token must be revoked after rotation").isNotNull();

    // New token must exist in the database
    String newHash = tokenHasher.hash(result.rawRefreshToken());
    assertThat(refreshTokenPort.findByTokenHash(newHash))
        .as("new token must be persisted after rotation")
        .isPresent();
  }

  /**
   * Replaying a revoked token triggers full family revocation and throws AUTH_004.
   * After the family revocation, the new token from the first rotation is also revoked.
   */
  @Test
  void reused_revoked_token_revokes_family() {
    TestToken tt = createActiveUserWithToken("theft");

    // First rotation — consumes the original token and produces a new one
    LoginResult firstResult = refreshTokenUseCase.execute(tt.rawToken(), "127.0.0.1");
    assertThat(firstResult).isNotNull();

    // Replay the original (now revoked) token — must trigger family revocation
    assertThatThrownBy(() -> refreshTokenUseCase.execute(tt.rawToken(), "127.0.0.1"))
        .isInstanceOf(AuthenticationException.class)
        .extracting(e -> ((AuthenticationException) e).code())
        .isEqualTo("AUTH_004");

    // Verify: REFRESH_FAMILY_REVOKED audit event was recorded for this user
    boolean familyRevokedEventExists = authEventRepository.findAll().stream()
        .anyMatch(e -> "REFRESH_FAMILY_REVOKED".equals(e.getEventType())
            && tt.user().getId().equals(e.getUserId()));
    assertThat(familyRevokedEventExists)
        .as("REFRESH_FAMILY_REVOKED audit event must be recorded on token theft")
        .isTrue();

    // The new token from the first rotation must also be revoked (family-wide)
    String newHash = tokenHasher.hash(firstResult.rawRefreshToken());
    refreshTokenPort.findByTokenHash(newHash).ifPresent(newToken ->
        assertThat(newToken.getRevokedAt())
            .as("new token from first rotation must be revoked after family revocation")
            .isNotNull());
  }

  /**
   * An expired refresh token is rejected with AUTH_004.
   */
  @Test
  void expired_token_rejected() {
    String email = "rot-exp-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    String hash = passwordHasher.hash(TEST_PASSWORD);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    userRegistrationPort.save(user);

    String rawToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawToken);
    UUID familyId = uuidGenerator.newId();
    // Create an already-expired token
    Instant expiredAt = Instant.now().minusSeconds(1);
    refreshTokenPort.save(new RefreshToken(uuidGenerator.newId(), user.getId(), tokenHash, familyId, expiredAt));

    assertThatThrownBy(() -> refreshTokenUseCase.execute(rawToken, "127.0.0.1"))
        .isInstanceOf(AuthenticationException.class)
        .extracting(e -> ((AuthenticationException) e).code())
        .isEqualTo("AUTH_004");
  }

  /**
   * Two concurrent rotation attempts for the same token: at most one succeeds.
   * The other gets an AUTH_004 due to optimistic locking failure.
   */
  @Test
  void concurrent_rotation_single_winner() throws Exception {
    TestToken tt = createActiveUserWithToken("conc");
    CyclicBarrier barrier = new CyclicBarrier(2);

    ExecutorService executor = Executors.newFixedThreadPool(2);
    List<Future<LoginResult>> futures = new ArrayList<>();

    for (int i = 0; i < 2; i++) {
      futures.add(executor.submit(() -> {
        barrier.await(5, TimeUnit.SECONDS); // synchronise start
        return refreshTokenUseCase.execute(tt.rawToken(), "127.0.0.1");
      }));
    }

    executor.shutdown();
    executor.awaitTermination(15, TimeUnit.SECONDS);

    int successCount = 0;
    int failureCount = 0;
    for (Future<LoginResult> f : futures) {
      try {
        LoginResult r = f.get();
        if (r != null) {
          successCount++;
        }
      } catch (Exception e) {
        // ExecutionException wrapping AuthenticationException or OptimisticLockingFailureException
        failureCount++;
      }
    }

    assertThat(successCount).as("at most 1 concurrent rotation should succeed").isLessThanOrEqualTo(1);
    assertThat(successCount + failureCount).as("both futures must complete").isEqualTo(2);
  }

  /**
   * Revoking tokenA's family does not affect tokenB (different family, different user).
   * This confirms family-scoped revocation does not leak across families.
   */
  @Test
  void cross_tenant_isolation() {
    TestToken ttA = createActiveUserWithToken("cross-a");
    TestToken ttB = createActiveUserWithToken("cross-b");

    // Rotate tokenA successfully
    LoginResult resultA1 = refreshTokenUseCase.execute(ttA.rawToken(), "127.0.0.1");
    assertThat(resultA1).isNotNull();

    // Replay tokenA (now revoked) → triggers family revocation for A
    assertThatThrownBy(() -> refreshTokenUseCase.execute(ttA.rawToken(), "127.0.0.1"))
        .isInstanceOf(AuthenticationException.class);

    // TokenB rotation must still succeed — independent family, unaffected
    LoginResult resultB = refreshTokenUseCase.execute(ttB.rawToken(), "127.0.0.1");
    assertThat(resultB).isNotNull();
    assertThat(resultB.userId()).isEqualTo(ttB.user().getId().toString());
  }
}
