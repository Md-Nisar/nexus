package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import java.time.Duration;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests for the T-014 Redis authentication startup assertion against a real Redis
 * with {@code requirepass} and an ACL user scoped to the key prefix (US-018 RC-34.1, RC-45.2). The
 * application wiring is {@link DataRedisAutoConfiguration}, {@link EpochRedisConfig} and {@link
 * RedisPermissionEpochAdapter}, so the epoch read and bump go through both dedicated factories.
 * Both passwords are random per run; none is committed.
 */
@Testcontainers
@Tag("IT")
class AuthenticatedRedisIT {

  private static final String ACL_USER = "nexus-it";
  private static final String KEY_PREFIX = "nexus-it";
  private static final String DEFAULT_PASSWORD = UUID.randomUUID().toString();
  private static final String ACL_PASSWORD = UUID.randomUUID().toString();

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
          .withExposedPorts(6379)
          .withCommand(
              "redis-server",
              "--requirepass", DEFAULT_PASSWORD,
              "--user", ACL_USER, "on", ">" + ACL_PASSWORD,
              "~" + KEY_PREFIX + ":*", "+@all", "-@dangerous");

  private final ApplicationContextRunner runner = new ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class))
      .withUserConfiguration(EpochRedisConfig.class, RedisPermissionEpochAdapter.class)
      .withInitializer(context -> context.getBeanFactory()
          .setConversionService(ApplicationConversionService.getSharedInstance()))
      .withPropertyValues(
          "nexus.rbac.epoch.command-timeout=500ms",
          "nexus.rbac.epoch.bump-timeout=500ms",
          "nexus.rbac.epoch.key-ttl-seconds=960",
          "nexus.jwt.access-token-ttl-seconds=900",
          "nexus.rbac.permission-cache-ttl-seconds=900",
          "nexus.redis.key-prefix=" + KEY_PREFIX);

  private static String host() {
    return "spring.data.redis.host=" + REDIS.getHost();
  }

  private static String port() {
    return "spring.data.redis.port=" + REDIS.getMappedPort(6379);
  }

  @Test
  void should_readAndBumpThroughBothDedicatedFactories_when_aclUserConfigured() {
    runner
        .withPropertyValues(host(), port(),
            "spring.data.redis.username=" + ACL_USER,
            "spring.data.redis.password=" + ACL_PASSWORD,
            "nexus.rbac.redis.require-auth=true")
        .run(context -> assertBumpVisibleToRead(context));
  }

  @Test
  void should_readAndBumpThroughBothDedicatedFactories_when_requirepassOnly() {
    runner
        .withPropertyValues(host(), port(),
            "spring.data.redis.password=" + DEFAULT_PASSWORD,
            "nexus.rbac.redis.require-auth=true")
        .run(context -> assertBumpVisibleToRead(context));
  }

  @Test
  void should_authenticate_when_credentialsSuppliedOnlyThroughRedisUrl() {
    runner
        .withPropertyValues(
            "spring.data.redis.url=redis://" + ACL_USER + ":" + ACL_PASSWORD + "@"
                + REDIS.getHost() + ":" + REDIS.getMappedPort(6379),
            "nexus.rbac.redis.require-auth=true")
        .run(context -> assertBumpVisibleToRead(context));
  }

  @Test
  void should_failStartup_when_passwordRemovedAndRequireAuthTrue() {
    runner
        .withPropertyValues(host(), port(),
            "spring.data.redis.username=" + ACL_USER,
            "nexus.rbac.redis.require-auth=true")
        .run(context -> {
          assertThat(context).hasFailed();
          Throwable failure = context.getStartupFailure();
          Throwable root = failure;
          StringBuilder text = new StringBuilder();
          for (Throwable t = failure; t != null; t = t.getCause()) {
            text.append(t).append('\n');
            root = t;
          }
          assertThat(root).isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("nexus.rbac.redis.require-auth");
          assertThat(text.toString())
              .doesNotContain(DEFAULT_PASSWORD)
              .doesNotContain(ACL_PASSWORD);
        });
  }

  @Test
  void should_neverBecomeReady_when_passwordRemovedAndRequireAuthFalse() {
    runner
        .withPropertyValues(host(), port(),
            "spring.data.redis.username=" + ACL_USER,
            "nexus.rbac.redis.require-auth=false")
        .run(context -> {
          assertThat(context).hasNotFailed();
          EpochTemplates templates = context.getBean(EpochTemplates.class);
          long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
          while (System.nanoTime() < deadline) {
            assertThat(templates.readReady()).isFalse();
            assertThat(templates.bumpReady()).isFalse();
            Thread.sleep(100);
          }
          assertThat(context.getBean(RedisPermissionEpochAdapter.class)
              .current(UUID.randomUUID(), UUID.randomUUID())).isEmpty();
        });
  }

  @Test
  void should_denyKeyOutsidePrefix_when_aclUserScopedToNexusKeys() {
    runner
        .withPropertyValues(host(), port(),
            "spring.data.redis.username=" + ACL_USER,
            "spring.data.redis.password=" + ACL_PASSWORD,
            "nexus.rbac.redis.require-auth=true")
        .run(context -> {
          EpochTemplates templates = context.getBean(EpochTemplates.class);
          awaitReady(templates);

          assertThatThrownBy(() -> templates.read().opsForValue().get("other:rbac:epoch:x"))
              .rootCause()
              .hasMessageContaining("NOPERM");
        });
  }

  private static void assertBumpVisibleToRead(ApplicationContext context) {
    assertThat(context.getBean(EpochTemplates.class)).isNotNull();
    awaitReady(context.getBean(EpochTemplates.class));
    RedisPermissionEpochAdapter adapter = context.getBean(RedisPermissionEpochAdapter.class);
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.bump(tenantId, List.of(userId));

    OptionalLong epoch = adapter.current(tenantId, userId);
    assertThat(epoch).isPresent();
    assertThat(epoch.getAsLong()).isPositive();
  }

  /** The first connection is opened off-thread, so wait for it before using the templates. */
  private static void awaitReady(EpochTemplates templates) {
    long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
    while (!(templates.readReady() && templates.bumpReady())) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("epoch templates not ready within 15 s");
      }
      try {
        Thread.sleep(25);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError("interrupted while waiting for epoch templates", e);
      }
    }
  }
}
