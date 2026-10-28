package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.application.port.out.ThrottleStatus;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests for {@link RedisRoleChangeThrottleAdapter} against a real Redis (US-018 T-024,
 * B8, RC-45.1). The adapter holds no state of its own, so two instances over the same Redis stand
 * in for two replicas (the "two application contexts" case): a throttle tripped through one is
 * seen by the other, which is what the per-JVM map of the memory adapter could not do (RES-11).
 */
@Testcontainers
@Tag("IT")
class RedisRoleChangeThrottleAdapterIT {

  private static final String KEY_PREFIX = "nexus-test";
  private static final int MAX_DENIALS = 3;
  private static final int WINDOW_SECONDS = 60;

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);

  private static LettuceConnectionFactory connectionFactory;
  private static StringRedisTemplate redisTemplate;

  @BeforeAll
  static void setUpRedis() {
    connectionFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
    connectionFactory.afterPropertiesSet();
    redisTemplate = new StringRedisTemplate(connectionFactory);
    redisTemplate.afterPropertiesSet();
  }

  @AfterAll
  static void tearDownRedis() {
    connectionFactory.destroy();
  }

  private RedisRoleChangeThrottleAdapter newReplica() {
    return new RedisRoleChangeThrottleAdapter(redisTemplate, KEY_PREFIX, MAX_DENIALS, WINDOW_SECONDS);
  }

  private static void denyTimes(RedisRoleChangeThrottleAdapter replica, UUID tenantId, UUID actorId, int n) {
    for (int i = 0; i < n; i++) {
      replica.recordDenial(tenantId, actorId);
    }
  }

  @Test
  void should_notBeThrottled_when_noDenialWasRecorded() {
    assertThat(newReplica().throttleStatus(UUID.randomUUID(), UUID.randomUUID()).throttled()).isFalse();
  }

  @Test
  void should_notBeThrottled_when_denialsStayWithinTheBound() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();

    denyTimes(replica, tenantId, actorId, MAX_DENIALS);

    assertThat(replica.throttleStatus(tenantId, actorId).throttled()).isFalse();
  }

  @Test
  void should_reportTheTransitionExactlyOnce_when_theBoundIsCrossed() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();
    denyTimes(replica, tenantId, actorId, MAX_DENIALS);

    boolean first = replica.recordDenial(tenantId, actorId);
    boolean second = replica.recordDenial(tenantId, actorId);

    assertThat(first).as("the denial that crosses the bound").isTrue();
    assertThat(second).as("a denial while already throttled").isFalse();
    assertThat(replica.throttleStatus(tenantId, actorId).throttled()).isTrue();
  }

  @Test
  void should_shareTheThrottleAcrossReplicas_when_oneReplicaTripsIt() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replicaA = newReplica();
    RedisRoleChangeThrottleAdapter replicaB = newReplica();

    denyTimes(replicaA, tenantId, actorId, MAX_DENIALS + 1);

    assertThat(replicaB.throttleStatus(tenantId, actorId).throttled())
        .as("tripped on replica A, blocked on replica B")
        .isTrue();
  }

  @Test
  void should_countDenialsAcrossReplicasTowardsOneBound() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replicaA = newReplica();
    RedisRoleChangeThrottleAdapter replicaB = newReplica();

    replicaA.recordDenial(tenantId, actorId);
    replicaB.recordDenial(tenantId, actorId);
    replicaA.recordDenial(tenantId, actorId);
    boolean crossed = replicaB.recordDenial(tenantId, actorId);

    assertThat(crossed).as("the 4th denial overall crosses a bound of 3, whichever replica").isTrue();
    assertThat(replicaA.throttleStatus(tenantId, actorId).throttled()).isTrue();
  }

  @Test
  void should_keepActorsAndTenantsIndependent() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();

    denyTimes(replica, tenantId, actorId, MAX_DENIALS + 1);

    assertThat(replica.throttleStatus(tenantId, UUID.randomUUID()).throttled()).isFalse();
    assertThat(replica.throttleStatus(UUID.randomUUID(), actorId).throttled()).isFalse();
  }

  @Test
  void should_keepTheDocumentedKeyShapeAndExpire() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();

    denyTimes(replica, tenantId, actorId, MAX_DENIALS + 1);

    String windowKey = "nexus-test:rbac:throttle:{" + tenantId + "}:" + actorId;
    assertThat(redisTemplate.hasKey(windowKey)).isTrue();
    assertThat(redisTemplate.getExpire(windowKey)).isBetween(1L, (long) WINDOW_SECONDS);
    assertThat(redisTemplate.getExpire(windowKey + ":until")).isBetween(1L, (long) WINDOW_SECONDS);
  }

  @Test
  void should_countSuppressedDenialsPerEpisodeAcrossReplicas() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replicaA = newReplica();
    RedisRoleChangeThrottleAdapter replicaB = newReplica();
    denyTimes(replicaA, tenantId, actorId, MAX_DENIALS + 1);

    assertThat(replicaA.recordSuppressedDenial(tenantId, actorId)).isEqualTo(1);
    assertThat(replicaB.recordSuppressedDenial(tenantId, actorId))
        .as("the second suppressed denial in the window, on another replica, does not log")
        .isEqualTo(2);
    assertThat(redisTemplate.getExpire("nexus-test:rbac:throttle:{" + tenantId + "}:" + actorId + ":suppressed"))
        .isBetween(1L, (long) WINDOW_SECONDS);
  }

  // US-019 B7 (design §9.3): one PTTL on the throttled-until marker answers both questions.

  private static String untilKey(UUID tenantId, UUID actorId) {
    return KEY_PREFIX + ":rbac:throttle:{" + tenantId + "}:" + actorId + ":until";
  }

  @Test
  void should_reportNotThrottled_when_theMarkerIsAbsent() {
    assertThat(newReplica().throttleStatus(UUID.randomUUID(), UUID.randomUUID()))
        .isEqualTo(ThrottleStatus.NOT_THROTTLED);
  }

  @Test
  void should_reportARetryAfterWithinOneSecondAndTheWindow_when_throttled() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();
    denyTimes(replica, tenantId, actorId, MAX_DENIALS + 1);

    ThrottleStatus status = replica.throttleStatus(tenantId, actorId);

    assertThat(status.throttled()).isTrue();
    assertThat(status.retryAfterSeconds()).isBetween(1L, (long) WINDOW_SECONDS);
  }

  @Test
  void should_roundThePttlUp_when_theMarkerHasAFractionalSecondLeft() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    redisTemplate.opsForValue().set(untilKey(tenantId, actorId), "1", Duration.ofMillis(12_900));

    ThrottleStatus status = newReplica().throttleStatus(tenantId, actorId);

    assertThat(status.throttled()).isTrue();
    assertThat(status.retryAfterSeconds()).isEqualTo(13L);
  }

  @Test
  void should_reportTheWholeWindow_when_theMarkerHasNoExpiry() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    redisTemplate.opsForValue().set(untilKey(tenantId, actorId), "1");

    assertThat(newReplica().throttleStatus(tenantId, actorId))
        .isEqualTo(new ThrottleStatus(true, WINDOW_SECONDS));
  }

  @Test
  void should_failSafeToNotThrottledWithoutThrowing_when_redisIsUnreachable() {
    LettuceConnectionFactory deadFactory =
        new LettuceConnectionFactory(
            new RedisStandaloneConfiguration("127.0.0.1", 1),
            LettuceClientConfiguration.builder().commandTimeout(Duration.ofMillis(500)).build());
    deadFactory.afterPropertiesSet();
    try {
      StringRedisTemplate deadTemplate = new StringRedisTemplate(deadFactory);
      deadTemplate.afterPropertiesSet();
      RedisRoleChangeThrottleAdapter replica =
          new RedisRoleChangeThrottleAdapter(deadTemplate, KEY_PREFIX, MAX_DENIALS, WINDOW_SECONDS);

      assertThat(replica.throttleStatus(UUID.randomUUID(), UUID.randomUUID()))
          .isEqualTo(ThrottleStatus.NOT_THROTTLED);
    } finally {
      deadFactory.destroy();
    }
  }

  @Test
  void should_use_server_time_to_prevent_clock_drift() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replicaA = newReplica();
    RedisRoleChangeThrottleAdapter replicaB = newReplica();

    replicaA.recordDenial(tenantId, actorId);
    replicaB.recordDenial(tenantId, actorId);

    String windowKey = "nexus-test:rbac:throttle:{" + tenantId + "}:" + actorId;
    var scores = redisTemplate.opsForZSet().rangeWithScores(windowKey, 0, -1);
    assertThat(scores).hasSize(2);
    for (var score : scores) {
      assertThat(score.getScore()).isNotNull().isGreaterThan(1_700_000_000_000.0);
    }
  }
}
