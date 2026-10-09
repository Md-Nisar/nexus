package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.RefreshThrottledException;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
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
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-018 T-013 (RC-43, RC-51): the per-IP refresh failure bucket against the real Redis
 * {@code RateLimitStore} (atomic Lua consume) and MySQL audit table. The test profile raises every
 * refresh bucket to 1000; this class pins the production values (30/60 s) so the limits are
 * observable. Each test uses its own IP so buckets and audit rows never overlap.
 */
@SpringBootTest(
    properties = {
      "nexus.security.rate-limit.store-type=redis",
      "nexus.security.rate-limit.ip-window-seconds=60",
      "nexus.security.rate-limit.refresh-family-max-attempts=30",
      "nexus.security.rate-limit.refresh-fail-max-attempts=30"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RefreshFailureThrottleIT {

  private static final int FAIL_MAX = 30;
  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");

  @Autowired private RefreshTokenUseCase useCase;
  @Autowired private SecureEventService secureEventService;
  @Autowired private RefreshTokenPort refreshTokenPort;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private TokenGenerator tokenGenerator;
  @Autowired private TokenHasher tokenHasher;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_writeAtMostThirtyFailureRows_when_manyConcurrentInvalidRefreshesFromOneIp()
      throws Exception {
    String ip = "198.51.100.1";
    // 4 racing threads x 20 attempts. Each in-flight refresh holds one pooled connection and its
    // failure audit write (REQUIRES_NEW) needs a second, so the thread count stays below half the
    // default Hikari pool of 10; more would starve the pool, not test the bucket.
    int threads = 4;
    int perThread = 20;
    int attempts = threads * perThread;
    AtomicInteger unauthorized = new AtomicInteger();
    AtomicInteger throttled = new AtomicInteger();
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CyclicBarrier barrier = new CyclicBarrier(threads);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int t = 0; t < threads; t++) {
        futures.add(pool.submit(() -> {
          barrier.await(30, TimeUnit.SECONDS);
          for (int i = 0; i < perThread; i++) {
            try {
              useCase.execute(tokenGenerator.generate(), ip); // valid hex, no row in the DB
            } catch (RefreshThrottledException e) {
              throttled.incrementAndGet();
            } catch (AuthenticationException e) {
              unauthorized.incrementAndGet();
            }
          }
          return null;
        }));
      }
      for (Future<?> f : futures) {
        f.get(120, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }

    assertThat(countEvents("TOKEN_REFRESH_FAILURE", ip)).isLessThanOrEqualTo(FAIL_MAX);
    assertThat(unauthorized.get()).isEqualTo(FAIL_MAX);
    assertThat(throttled.get()).isEqualTo(attempts - FAIL_MAX);
  }

  @Test
  void should_stillRevokeFamilyAndWriteOneReuseRow_when_replayArrivesWithFailureBucketExhausted() {
    String ip = "198.51.100.2";
    exhaustFailureBucket(ip);
    User user = createUser();
    UUID familyId = uuidGenerator.newId();
    String rotatedRaw = saveRotatedPair(user, familyId);

    assertThatThrownBy(() -> useCase.execute(rotatedRaw, ip))
        .isInstanceOf(AuthenticationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_004");

    assertThat(countEvents("TOKEN_REFRESH_REUSE", ip)).isEqualTo(1);
    assertThat(unrevokedInFamily(familyId)).isZero();
  }

  @Test
  void should_throttleWithNoRow_when_secondReplayRevokesNothingAndBucketExhausted() {
    String ip = "198.51.100.3";
    exhaustFailureBucket(ip);
    User user = createUser();
    UUID familyId = uuidGenerator.newId();
    String rotatedRaw = saveRotatedPair(user, familyId);
    assertThatThrownBy(() -> useCase.execute(rotatedRaw, ip))
        .isInstanceOf(AuthenticationException.class);

    assertThatThrownBy(() -> useCase.execute(rotatedRaw, ip))
        .isInstanceOf(RefreshThrottledException.class);

    assertThat(countEvents("TOKEN_REFRESH_REUSE", ip)).isEqualTo(1);
    assertThat(countEvents("TOKEN_REFRESH_FAILURE", ip)).isEqualTo(FAIL_MAX);
  }

  @Test
  void should_letExactlyOneConcurrentReplaySeeTheCount_when_twoReplaysRaceOnOneFamily()
      throws Exception {
    User user = createUser();
    UUID familyId = uuidGenerator.newId();
    saveRotatedPair(user, familyId);
    saveRotatedPair(user, familyId); // family now holds two unrevoked successors
    ExecutorService pool = Executors.newFixedThreadPool(2);
    CyclicBarrier barrier = new CyclicBarrier(2);
    try {
      List<Future<Integer>> counts = new ArrayList<>();
      for (int i = 0; i < 2; i++) {
        counts.add(pool.submit(() -> {
          barrier.await(30, TimeUnit.SECONDS);
          return secureEventService.revokeFamily(familyId, Instant.now());
        }));
      }
      int total = counts.get(0).get(60, TimeUnit.SECONDS) + counts.get(1).get(60, TimeUnit.SECONDS);

      assertThat(total).isEqualTo(2);
    } finally {
      pool.shutdownNow();
    }
  }

  private void exhaustFailureBucket(String ip) {
    for (int i = 0; i < FAIL_MAX; i++) {
      String unknownCookie = tokenGenerator.generate();
      assertThatThrownBy(() -> useCase.execute(unknownCookie, ip))
          .isInstanceOf(AuthenticationException.class);
    }
    assertThatThrownBy(() -> useCase.execute(tokenGenerator.generate(), ip))
        .isInstanceOf(RefreshThrottledException.class);
  }

  /** Saves a revoked token plus its unrevoked successor; returns the revoked token's raw value. */
  private String saveRotatedPair(User user, UUID familyId) {
    Instant expiry = Instant.now().plus(14, ChronoUnit.DAYS);
    String rotatedRaw = tokenGenerator.generate();
    RefreshToken rotated = new RefreshToken(
        uuidGenerator.newId(), user.getId(), tokenHasher.hash(rotatedRaw), familyId, expiry);
    rotated.revoke(Instant.now().minusSeconds(5));
    refreshTokenPort.save(rotated);
    refreshTokenPort.save(new RefreshToken(
        uuidGenerator.newId(), user.getId(), tokenHasher.hash(tokenGenerator.generate()),
        familyId, expiry));
    return rotatedRaw;
  }

  private User createUser() {
    String email = "rf-throttle-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRegistrationPort.save(new User(
        uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "dummy-hash", null));
  }

  private int countEvents(String eventType, String ip) {
    Integer n = jdbc.queryForObject(
        "SELECT COUNT(*) FROM auth_events WHERE event_type = ? AND ip_address = ?",
        Integer.class, eventType, ip);
    return n == null ? 0 : n;
  }

  private int unrevokedInFamily(UUID familyId) {
    Integer n = jdbc.queryForObject(
        "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = ? AND revoked_at IS NULL",
        Integer.class, (Object) uuidBytes(familyId));
    return n == null ? 0 : n;
  }

  private static byte[] uuidBytes(UUID id) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits());
    return bb.array();
  }
}
