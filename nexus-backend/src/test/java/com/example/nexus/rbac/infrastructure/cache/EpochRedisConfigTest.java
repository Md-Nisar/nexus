package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.example.nexus.common.security.TokenClockSkew;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SslOptions;
import io.lettuce.core.resource.ClientResources;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/**
 * Unit tests for {@link EpochRedisConfig}: the key-TTL startup assertion (RC-29.2) and the two
 * dedicated connection factories, which must take every connection setting from the same
 * connection details as the main factory and differ only in timeout (RC-45.2).
 */
@Tag("UnitTest")
class EpochRedisConfigTest {

  private static final long TOKEN_TTL = 900;
  private static final long CACHE_TTL = 900;

  private final ClientResources clientResources = mock(ClientResources.class);

  // --- key-TTL startup assertion ---

  @Test
  void should_failStartup_when_keyTtlEqualsCacheTtl() {
    assertThatThrownBy(() -> new EpochRedisConfig(900, 600, CACHE_TTL))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("key-ttl-seconds");
  }

  @Test
  void should_failStartup_when_keyTtlBelowTokenTtl() {
    assertThatThrownBy(() -> new EpochRedisConfig(960, 1000, CACHE_TTL))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void should_failStartup_when_keyTtlEqualsTokenTtl() {
    assertThatThrownBy(() -> new EpochRedisConfig(900, TOKEN_TTL, 600))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void should_failStartup_when_marginBelow60s() {
    assertThatThrownBy(() -> new EpochRedisConfig(959, TOKEN_TTL, CACHE_TTL))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void should_start_when_keyTtlIs960WithDefaultTtls() {
    assertThatCode(() -> new EpochRedisConfig(960, TOKEN_TTL, CACHE_TTL))
        .doesNotThrowAnyException();
  }

  @Test
  void should_start_when_keyTtlEqualsTokenTtlPlusSkewPlusMargin() {
    long tokenTtl = 1_000;
    long minimum = tokenTtl + TokenClockSkew.SECONDS + EpochRedisConfig.MIN_KEY_TTL_MARGIN_SECONDS;

    assertThatCode(() -> new EpochRedisConfig(minimum, tokenTtl, CACHE_TTL))
        .doesNotThrowAnyException();
  }

  @Test
  void should_failStartup_when_keyTtlOneBelowTokenTtlPlusSkewPlusMargin() {
    long tokenTtl = 1_000;
    long belowMinimum =
        tokenTtl + TokenClockSkew.SECONDS + EpochRedisConfig.MIN_KEY_TTL_MARGIN_SECONDS - 1;

    assertThatThrownBy(() -> new EpochRedisConfig(belowMinimum, tokenTtl, CACHE_TTL))
        .isInstanceOf(IllegalStateException.class);
  }

  // --- dedicated factories ---

  @Test
  void should_buildBothFactoriesFromSameConnectionDetails_withOnlyTimeoutDiffering() {
    DataRedisConnectionDetails details = standalone("redis.internal", 6380, 2, "app", "s3cret");

    LettuceConnectionFactory read =
        EpochRedisConfig.dedicatedFactory(details, plainMain(), clientResources, Duration.ofMillis(50));
    LettuceConnectionFactory bump =
        EpochRedisConfig.dedicatedFactory(details, plainMain(), clientResources, Duration.ofMillis(500));

    for (LettuceConnectionFactory factory : List.of(read, bump)) {
      assertThat(factory.getStandaloneConfiguration().getHostName()).isEqualTo("redis.internal");
      assertThat(factory.getStandaloneConfiguration().getPort()).isEqualTo(6380);
      assertThat(factory.getStandaloneConfiguration().getDatabase()).isEqualTo(2);
      assertThat(factory.getStandaloneConfiguration().getUsername()).isEqualTo("app");
      assertThat(factory.getStandaloneConfiguration().getPassword().get())
          .isEqualTo("s3cret".toCharArray());
      assertThat(factory.getClientConfiguration().isUseSsl()).isFalse();
      assertThat(factory.getClientConfiguration().getClientResources()).containsSame(clientResources);
    }
    assertThat(read.getClientConfiguration().getCommandTimeout()).isEqualTo(Duration.ofMillis(50));
    assertThat(bump.getClientConfiguration().getCommandTimeout()).isEqualTo(Duration.ofMillis(500));
  }

  @Test
  void should_boundConnectTimeoutAndRejectWhileDisconnected_when_factoryBuilt() {
    LettuceConnectionFactory read = EpochRedisConfig.dedicatedFactory(
        standalone("localhost", 6379, 0, null, null), plainMain(), clientResources, Duration.ofMillis(50));

    ClientOptions options = read.getClientConfiguration().getClientOptions().orElseThrow();
    assertThat(options.getSocketOptions().getConnectTimeout()).isEqualTo(Duration.ofMillis(50));
    assertThat(options.getDisconnectedBehavior())
        .isEqualTo(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS);
    assertThat(options.getTimeoutOptions().isTimeoutCommands()).isTrue();
  }

  @Test
  void should_useSentinel_when_connectionDetailsDeclareSentinel() {
    DataRedisConnectionDetails details = new DataRedisConnectionDetails() {
      @Override
      public String getPassword() {
        return "s3cret";
      }

      @Override
      public Sentinel getSentinel() {
        return new Sentinel() {
          @Override
          public int getDatabase() {
            return 1;
          }

          @Override
          public String getMaster() {
            return "primary";
          }

          @Override
          public List<Node> getNodes() {
            return List.of(new Node("sentinel-a", 26379));
          }

          @Override
          public String getUsername() {
            return null;
          }

          @Override
          public String getPassword() {
            return null;
          }
        };
      }
    };

    LettuceConnectionFactory factory =
        EpochRedisConfig.dedicatedFactory(details, plainMain(), clientResources, Duration.ofMillis(50));

    assertThat(factory.getSentinelConfiguration()).isNotNull();
    assertThat(factory.getSentinelConfiguration().getMaster().getName()).isEqualTo("primary");
    assertThat(factory.getSentinelConfiguration().getDatabase()).isEqualTo(1);
    assertThat(factory.getSentinelConfiguration().getPassword().get())
        .isEqualTo("s3cret".toCharArray());
  }

  @Test
  void should_failStartup_when_connectionDetailsDeclareCluster() {
    DataRedisConnectionDetails details = new DataRedisConnectionDetails() {
      @Override
      public Cluster getCluster() {
        return () -> List.of(new Node("node-a", 6379));
      }
    };

    assertThatThrownBy(
            () -> EpochRedisConfig.dedicatedFactory(
                details, plainMain(), clientResources, Duration.ofMillis(50)))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void should_failStartup_when_connectionDetailsDeclareMasterReplica() {
    DataRedisConnectionDetails details = new DataRedisConnectionDetails() {
      @Override
      public MasterReplica getMasterReplica() {
        return () -> List.of(new Node("node-a", 6379));
      }
    };

    assertThatThrownBy(
            () -> EpochRedisConfig.dedicatedFactory(
                details, plainMain(), clientResources, Duration.ofMillis(50)))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void should_useSslWithBundleOptionsAndClientName_when_mainFactoryUsesSslBundle() throws Exception {
    SslOptions bundleOptions = SslOptions.builder()
        .keyManager(KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()))
        .trustManager(TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()))
        .cipherSuites("TLS_AES_256_GCM_SHA384")
        .protocols("TLSv1.3")
        .build();
    LettuceConnectionFactory main = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration("redis.internal", 6380),
        LettuceClientConfiguration.builder()
            .useSsl()
            .and()
            .clientName("nexus-main")
            .clientOptions(ClientOptions.builder().sslOptions(bundleOptions).build())
            .build());

    LettuceConnectionFactory read = EpochRedisConfig.dedicatedFactory(
        standalone("redis.internal", 6380, 0, null, null), main, clientResources,
        Duration.ofMillis(50));

    LettuceClientConfiguration client = read.getClientConfiguration();
    assertThat(client.isUseSsl()).isTrue();
    assertThat(client.getClientName()).contains("nexus-main");
    SslOptions options = client.getClientOptions().orElseThrow().getSslOptions();
    assertThat(options.getCipherSuites()).containsExactly("TLS_AES_256_GCM_SHA384");
    assertThat(options.getProtocols()).containsExactly("TLSv1.3");
    assertThat(client.getCommandTimeout()).isEqualTo(Duration.ofMillis(50));
  }

  @Test
  void should_useSsl_when_mainFactoryAutoConfiguredFromRedissUrl() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class))
        .withPropertyValues("spring.data.redis.url=rediss://redis.internal:6380")
        .run(context -> {
          LettuceConnectionFactory main = context.getBean(LettuceConnectionFactory.class);
          DataRedisConnectionDetails details = context.getBean(DataRedisConnectionDetails.class);

          LettuceConnectionFactory read = EpochRedisConfig.dedicatedFactory(
              details, main, clientResources, Duration.ofMillis(50));
          LettuceConnectionFactory bump = EpochRedisConfig.dedicatedFactory(
              details, main, clientResources, Duration.ofMillis(500));

          assertThat(main.getClientConfiguration().isUseSsl()).isTrue();
          assertThat(read.getClientConfiguration().isUseSsl()).isTrue();
          assertThat(bump.getClientConfiguration().isUseSsl()).isTrue();
          assertThat(read.getStandaloneConfiguration().getHostName()).isEqualTo("redis.internal");
        });
  }

  private static LettuceConnectionFactory plainMain() {
    return new LettuceConnectionFactory(new RedisStandaloneConfiguration("main", 6379));
  }

  private static DataRedisConnectionDetails standalone(
      String host, int port, int database, String username, String password) {
    return new DataRedisConnectionDetails() {
      @Override
      public String getUsername() {
        return username;
      }

      @Override
      public String getPassword() {
        return password;
      }

      @Override
      public Standalone getStandalone() {
        return Standalone.of(host, port, database);
      }
    };
  }
}
