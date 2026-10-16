package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
    assertThat(newReplica().isThrottled(UUID.randomUUID(), UUID.randomUUID())).isFalse();
  }

  @Test
  void should_notBeThrottled_when_denialsStayWithinTheBound() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();

    denyTimes(replica, tenantId, actorId, MAX_DENIALS);

    assertThat(replica.isThrottled(tenantId, actorId)).isFalse();
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
    assertThat(replica.isThrottled(tenantId, actorId)).isTrue();
  }

  @Test
  void should_shareTheThrottleAcrossReplicas_when_oneReplicaTripsIt() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replicaA = newReplica();
    RedisRoleChangeThrottleAdapter replicaB = newReplica();

    denyTimes(replicaA, tenantId, actorId, MAX_DENIALS + 1);

    assertThat(replicaB.isThrottled(tenantId, actorId))
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
    assertThat(replicaA.isThrottled(tenantId, actorId)).isTrue();
  }

  @Test
  void should_keepActorsAndTenantsIndependent() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();

    denyTimes(replica, tenantId, actorId, MAX_DENIALS + 1);

    assertThat(replica.isThrottled(tenantId, UUID.randomUUID())).isFalse();
    assertThat(replica.isThrottled(UUID.randomUUID(), actorId)).isFalse();
  }

  @Test
  void should_keepTheDocumentedKeyShapeAndExpire() {
    UUID tenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    RedisRoleChangeThrottleAdapter replica = newReplica();

    denyTimes(replica, tenantId, actorId, MAX_DENIALS + 1);

    String windowKey = "nexus-test:rbac:throttle:" + tenantId + ":" + actorId;
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
    assertThat(redisTemplate.getExpire("nexus-test:rbac:throttle:" + tenantId + ":" + actorId + ":suppressed"))
        .isBetween(1L, (long) WINDOW_SECONDS);
  }
}
