package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    assertThat(current).isEmpty();
    assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(20));
  }

  @Test
  void should_throwImmediately_when_bumpConnectionNotReady() {
    long start = System.nanoTime();

    assertThatThrownBy(() -> adapter.bump(UUID.randomUUID(), List.of(UUID.randomUUID())))
        .isInstanceOf(DataAccessException.class);

    assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(20));
  }

  @Test
  void should_reportNotReady_when_redisRefusesConnections() {
    assertThat(templates.readReady()).isFalse();
    assertThat(templates.bumpReady()).isFalse();
  }
}
