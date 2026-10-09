package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/**
 * {@link RedisPermissionEpochAdapter} while no connection could be opened (H-1): it must answer
 * "unavailable" at once, never connect on the calling thread.
 */
@Tag("UnitTest")
class RedisPermissionEpochAdapterNotReadyTest {

  private ClientResources clientResources;
  private EpochTemplates templates;
  private RedisPermissionEpochAdapter adapter;

  @BeforeEach
  void setUp() throws Exception {
    int closedPort;
    try (ServerSocket socket = new ServerSocket(0)) {
      closedPort = socket.getLocalPort();
    }
    clientResources = DefaultClientResources.create();
    DataRedisConnectionDetails details = new DataRedisConnectionDetails() {
      @Override
      public Standalone getStandalone() {
        return Standalone.of("localhost", closedPort);
      }
    };
    LettuceConnectionFactory main =
        new LettuceConnectionFactory(new RedisStandaloneConfiguration("localhost", closedPort));
    templates = new EpochTemplates(
        EpochRedisConfig.dedicatedFactory(details, main, clientResources, Duration.ofMillis(50)),
        EpochRedisConfig.dedicatedFactory(details, main, clientResources, Duration.ofMillis(500)));
    adapter = new RedisPermissionEpochAdapter(templates, "nexus-test", 960L);
    warmUpCallPaths();
  }

  /**
   * Runs each not-ready path once before the timed assertions. First in a cold JVM (a single class
   * from the IDE or {@code -Dtest}), the first call paid class loading and JIT while the warm-up
   * threads competed for the class-loading locks, and measured 22 to 56 ms against the 20 ms bound
   * in 1 run of about 20. That says nothing about connecting on the caller thread, which {@link
   * RedisPermissionEpochAdapterNeverConnectsTest} pins without a clock.
   */
  private void warmUpCallPaths() {
    adapter.current(UUID.randomUUID(), UUID.randomUUID());
    adapter.probe();
    catchThrowable(() -> adapter.bump(UUID.randomUUID(), List.of(UUID.randomUUID())));
  }

  @AfterEach
  void tearDown() {
    templates.destroy();
    clientResources.shutdown();
  }

  @Test
  void should_returnEmptyImmediately_when_readConnectionNotReady() {
    long start = System.nanoTime();

    var current = adapter.current(UUID.randomUUID(), UUID.randomUUID());
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

    assertThat(current).isEmpty();
    assertThat(elapsed).isLessThan(Duration.ofMillis(20));
  }

  @Test
  void should_probeFalseImmediately_when_readConnectionNotReady() {
    long start = System.nanoTime();

    boolean answered = adapter.probe();
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

    assertThat(answered).isFalse();
    assertThat(elapsed).isLessThan(Duration.ofMillis(20));
  }

  @Test
  void should_throwImmediately_when_bumpConnectionNotReady() {
    long start = System.nanoTime();

    Throwable thrown = catchThrowable(
        () -> adapter.bump(UUID.randomUUID(), List.of(UUID.randomUUID())));
    Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

    assertThat(thrown).isInstanceOf(DataAccessException.class);
    assertThat(elapsed).isLessThan(Duration.ofMillis(20));
  }

  @Test
  void should_reportNotReady_when_redisRefusesConnections() {
    assertThat(templates.readReady()).isFalse();
    assertThat(templates.bumpReady()).isFalse();
  }
}
