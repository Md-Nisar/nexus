package com.example.nexus.rbac.infrastructure.cache;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.SslOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.resource.ClientResources;
import java.time.Duration;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisNode;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisSentinelConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Dedicated Redis connections for the permission epoch (US-018 A9, design §9.5, RC-45.2) and the
 * epoch-key TTL startup assertion (RC-29.2).
 *
 * <p><b>Two factories, private on purpose.</b> The epoch read runs on every authenticated request
 * and gets a 50 ms bound ({@code nexus.rbac.epoch.command-timeout}); the bump script gets {@code
 * nexus.rbac.epoch.bump-timeout}. Neither may use the platform's 2 s default. They are not exposed
 * as {@code RedisConnectionFactory} or {@code StringRedisTemplate} beans, because Boot's Redis
 * auto-configuration backs off when such a bean exists and the main cache and rate-limit template
 * would disappear. Only {@link EpochTemplates} is a bean.
 *
 * <p><b>Same connection settings as the main factory.</b> Both are built from the {@link
 * DataRedisConnectionDetails} the main factory uses (backed by {@code spring.data.redis.*}, or by
 * a service connection in tests): host, port, database, ACL username, password, SSL bundle and
 * Sentinel. Only the timeouts differ. Cluster and static master/replica are rejected, as ADR-0016
 * D1 does.
 *
 * <p>The socket connect timeout equals the command timeout and commands are rejected while
 * disconnected, so neither connection setup nor a reconnect can hold a request longer than the
 * bound.
 */
@Configuration(proxyBeanMethods = false)
public final class EpochRedisConfig {

  /** Minimum gap between the epoch-key TTL and the longer of the token and cache TTLs. */
  static final long MIN_KEY_TTL_MARGIN_SECONDS = 60;

  /**
   * Fails startup unless the epoch key outlives every token and cache entry that could carry an
   * older epoch by at least {@value #MIN_KEY_TTL_MARGIN_SECONDS} s (T-E37).
   *
   * @param keyTtlSeconds {@code nexus.rbac.epoch.key-ttl-seconds}
   * @param accessTokenTtlSeconds {@code nexus.jwt.access-token-ttl-seconds}
   * @param permissionCacheTtlSeconds {@code nexus.rbac.permission-cache-ttl-seconds}
   * @throws IllegalStateException if the key TTL is too short
   */
  public EpochRedisConfig(
      @Value("${nexus.rbac.epoch.key-ttl-seconds}") long keyTtlSeconds,
      @Value("${nexus.jwt.access-token-ttl-seconds}") long accessTokenTtlSeconds,
      @Value("${nexus.rbac.permission-cache-ttl-seconds}") long permissionCacheTtlSeconds) {
    long minimum =
        Math.max(accessTokenTtlSeconds, permissionCacheTtlSeconds) + MIN_KEY_TTL_MARGIN_SECONDS;
    if (keyTtlSeconds < minimum) {
      throw new IllegalStateException(
          "nexus.rbac.epoch.key-ttl-seconds=" + keyTtlSeconds + " must be at least " + minimum
              + " (max of nexus.jwt.access-token-ttl-seconds=" + accessTokenTtlSeconds
              + " and nexus.rbac.permission-cache-ttl-seconds=" + permissionCacheTtlSeconds
              + ", plus " + MIN_KEY_TTL_MARGIN_SECONDS + " s)");
    }
  }

  /**
   * The epoch read and bump templates.
   *
   * @param connectionDetails the main factory's connection details
   * @param clientResources the shared Lettuce client resources (event loops, timers)
   * @param commandTimeout bound on one epoch read
   * @param bumpTimeout bound on one bump script call
   * @return the templates, whose factories are destroyed with the context
   */
  @Bean
  EpochTemplates epochTemplates(
      DataRedisConnectionDetails connectionDetails,
      ClientResources clientResources,
      @Value("${nexus.rbac.epoch.command-timeout}") Duration commandTimeout,
      @Value("${nexus.rbac.epoch.bump-timeout}") Duration bumpTimeout) {
    return new EpochTemplates(
        dedicatedFactory(connectionDetails, clientResources, commandTimeout),
        dedicatedFactory(connectionDetails, clientResources, bumpTimeout));
  }

  /**
   * Builds a factory with the main factory's connection settings and the given timeout. It is
   * not started; {@link EpochTemplates} starts it. It connects lazily, on first use.
   */
  static LettuceConnectionFactory dedicatedFactory(
      DataRedisConnectionDetails details, ClientResources clientResources, Duration timeout) {
    if (details.getCluster() != null || details.getMasterReplica() != null) {
      throw new IllegalStateException(
          "Permission epoch requires Redis standalone or Sentinel (ADR-0016 D1)");
    }
    SslBundle sslBundle = details.getSslBundle();
    ClientOptions.Builder options = ClientOptions.builder()
        .socketOptions(SocketOptions.builder().connectTimeout(timeout).build())
        .timeoutOptions(TimeoutOptions.enabled(timeout))
        .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS);
    LettuceClientConfiguration.LettuceClientConfigurationBuilder client =
        LettuceClientConfiguration.builder()
            .clientResources(clientResources)
            .commandTimeout(timeout);
    if (sslBundle != null) {
      options.sslOptions(SslOptions.builder()
          .keyManager(sslBundle.getManagers().getKeyManagerFactory())
          .trustManager(sslBundle.getManagers().getTrustManagerFactory())
          .build());
      client.useSsl();
    }
    client.clientOptions(options.build());

    DataRedisConnectionDetails.Sentinel sentinel = details.getSentinel();
    if (sentinel != null) {
      RedisSentinelConfiguration config = new RedisSentinelConfiguration();
      config.master(sentinel.getMaster());
      sentinel.getNodes().forEach(node -> config.addSentinel(new RedisNode(node.host(), node.port())));
      config.setDatabase(sentinel.getDatabase());
      config.setUsername(details.getUsername());
      config.setPassword(RedisPassword.of(details.getPassword()));
      config.setSentinelUsername(sentinel.getUsername());
      config.setSentinelPassword(RedisPassword.of(sentinel.getPassword()));
      return new LettuceConnectionFactory(config, client.build());
    }
    DataRedisConnectionDetails.Standalone standalone = details.getStandalone();
    RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
        standalone.getHost(), standalone.getPort());
    config.setDatabase(standalone.getDatabase());
    config.setUsername(details.getUsername());
    config.setPassword(RedisPassword.of(details.getPassword()));
    return new LettuceConnectionFactory(config, client.build());
  }

  /** The two dedicated templates; owns and destroys their factories. */
  static final class EpochTemplates implements DisposableBean {

    private final LettuceConnectionFactory readFactory;
    private final LettuceConnectionFactory bumpFactory;
    private final StringRedisTemplate read;
    private final StringRedisTemplate bump;

    EpochTemplates(LettuceConnectionFactory readFactory, LettuceConnectionFactory bumpFactory) {
      this.readFactory = start(readFactory);
      this.bumpFactory = start(bumpFactory);
      this.read = new StringRedisTemplate(readFactory);
      this.bump = new StringRedisTemplate(bumpFactory);
    }

    private static LettuceConnectionFactory start(LettuceConnectionFactory factory) {
      factory.afterPropertiesSet();
      factory.start();
      return factory;
    }

    /** Template for the request-time and mint-time epoch read. */
    StringRedisTemplate read() {
      return read;
    }

    /** Template for the bump script. */
    StringRedisTemplate bump() {
      return bump;
    }

    @Override
    public void destroy() {
      readFactory.destroy();
      bumpFactory.destroy();
    }
  }
}
