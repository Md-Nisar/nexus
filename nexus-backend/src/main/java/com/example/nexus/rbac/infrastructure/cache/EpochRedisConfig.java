package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.common.security.TokenClockSkew;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.resource.ClientResources;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
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
 * <p><b>Same connection settings as the main factory.</b> The topology and credentials come from
 * the {@link DataRedisConnectionDetails} the main factory uses (backed by {@code
 * spring.data.redis.*}, or by a service connection in tests): host, port, database, ACL username,
 * password and Sentinel. Cluster and static master/replica are rejected, as ADR-0016 D1 does. The
 * transport settings are copied from the auto-configured main {@link LettuceConnectionFactory}'s
 * client configuration, so TLS matches however it was enabled ({@code rediss://} URL or SSL
 * bundle): the TLS flag, peer verification, STARTTLS, the {@link io.lettuce.core.SslOptions}
 * (bundle key and trust managers, ciphers, protocols) and the client name. Only the timeouts and
 * the disconnected behaviour differ.
 *
 * <p>The socket connect timeout equals the command timeout and commands are rejected while
 * disconnected, so a reconnect cannot hold a request longer than the bound. The very first
 * connection is the exception, because Spring Data Redis opens it lazily under a lock. It is
 * therefore never opened on a request thread: {@link EpochTemplates} warms each factory on its own
 * thread, with retry, and the adapter treats the store as unavailable until that succeeded.
 */
@Configuration(proxyBeanMethods = false)
public final class EpochRedisConfig {

  /** Minimum gap between the epoch-key TTL and the longer of the token and cache TTLs. */
  static final long MIN_KEY_TTL_MARGIN_SECONDS = 60;

  /**
   * Fails startup unless the epoch key outlives every token and cache entry that could carry an
   * older epoch by at least {@value #MIN_KEY_TTL_MARGIN_SECONDS} s (T-E37). A token is accepted up
   * to {@link TokenClockSkew#SECONDS} after its {@code exp}, so that skew counts towards the token
   * lifetime.
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
        Math.max(accessTokenTtlSeconds + TokenClockSkew.SECONDS, permissionCacheTtlSeconds)
            + MIN_KEY_TTL_MARGIN_SECONDS;
    if (keyTtlSeconds < minimum) {
      throw new IllegalStateException(
          "nexus.rbac.epoch.key-ttl-seconds=" + keyTtlSeconds + " must be at least " + minimum
              + " (max of nexus.jwt.access-token-ttl-seconds=" + accessTokenTtlSeconds
              + " plus " + TokenClockSkew.SECONDS + " s clock skew, and "
              + "nexus.rbac.permission-cache-ttl-seconds=" + permissionCacheTtlSeconds
              + ", plus " + MIN_KEY_TTL_MARGIN_SECONDS + " s)");
    }
  }

  /**
   * The epoch read and bump templates.
   *
   * @param connectionDetails the main factory's connection details
   * @param mainFactory the auto-configured main factory, the source of the TLS settings
   * @param clientResources the shared Lettuce client resources (event loops, timers)
   * @param commandTimeout bound on one epoch read
   * @param bumpTimeout bound on one bump script call
   * @param requireAuth {@code nexus.rbac.redis.require-auth}; when true, startup fails unless all
   *     three factories carry a password (T-014), checked before any connection is attempted
   * @return the templates, whose factories are destroyed with the context
   */
  @Bean
  EpochTemplates epochTemplates(
      DataRedisConnectionDetails connectionDetails,
      LettuceConnectionFactory mainFactory,
      ClientResources clientResources,
      @Value("${nexus.rbac.epoch.command-timeout}") Duration commandTimeout,
      @Value("${nexus.rbac.epoch.bump-timeout}") Duration bumpTimeout,
      @Value("${nexus.rbac.redis.require-auth}") boolean requireAuth) {
    LettuceConnectionFactory read =
        dedicatedFactory(connectionDetails, mainFactory, clientResources, commandTimeout);
    LettuceConnectionFactory bump =
        dedicatedFactory(connectionDetails, mainFactory, clientResources, bumpTimeout);
    RedisAuthStartupAssertion.verify(requireAuth, mainFactory, read, bump);
    return new EpochTemplates(read, bump);
  }

  /**
   * Builds a factory with the main factory's connection settings and the given timeout. It is
   * not started; {@link EpochTemplates} starts and warms it.
   *
   * @param main the main factory; only its client configuration is read, never connected
   */
  static LettuceConnectionFactory dedicatedFactory(
      DataRedisConnectionDetails details,
      LettuceConnectionFactory main,
      ClientResources clientResources,
      Duration timeout) {
    if (details.getCluster() != null || details.getMasterReplica() != null) {
      throw new IllegalStateException(
          "Permission epoch requires Redis standalone or Sentinel (ADR-0016 D1)");
    }
    LettuceClientConfiguration mainClient = main.getClientConfiguration();
    // Starting from the main factory's options keeps its SslOptions (bundle managers, ciphers,
    // protocols); the three settings below are the only intended differences.
    Optional<ClientOptions> mainOptions = mainClient.getClientOptions();
    ClientOptions.Builder options =
        mainOptions.map(ClientOptions::mutate).orElseGet(ClientOptions::builder)
            .socketOptions(SocketOptions.builder().connectTimeout(timeout).build())
            .timeoutOptions(TimeoutOptions.enabled(timeout))
            .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS);
    LettuceClientConfiguration.LettuceClientConfigurationBuilder client =
        LettuceClientConfiguration.builder()
            .clientResources(clientResources)
            .commandTimeout(timeout);
    if (mainClient.isUseSsl()) {
      LettuceClientConfiguration.LettuceSslClientConfigurationBuilder ssl =
          client.useSsl().verifyPeer(mainClient.getVerifyMode());
      if (mainClient.isStartTls()) {
        ssl.startTls();
      }
    }
    mainClient.getClientName().ifPresent(client::clientName);
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

  /**
   * The two dedicated templates; owns and destroys their factories. Each factory is connected on
   * its own daemon thread, retried with backoff until it succeeds, so that no request thread ever
   * opens the first connection (design §9.5).
   */
  static final class EpochTemplates implements DisposableBean {

    private final WarmedFactory readFactory;
    private final WarmedFactory bumpFactory;
    private final StringRedisTemplate read;
    private final StringRedisTemplate bump;

    EpochTemplates(LettuceConnectionFactory readFactory, LettuceConnectionFactory bumpFactory) {
      this.readFactory = new WarmedFactory(readFactory, "epoch-redis-warmup-read");
      this.bumpFactory = new WarmedFactory(bumpFactory, "epoch-redis-warmup-bump");
      this.read = new StringRedisTemplate(readFactory);
      this.bump = new StringRedisTemplate(bumpFactory);
    }

    /** Template for the request-time and mint-time epoch read. */
    StringRedisTemplate read() {
      return read;
    }

    /** Template for the bump script. */
    StringRedisTemplate bump() {
      return bump;
    }

    /** True once the read connection exists; until then a read must not touch the template. */
    boolean readReady() {
      return readFactory.ready;
    }

    /** True once the bump connection exists; until then a bump must not touch the template. */
    boolean bumpReady() {
      return bumpFactory.ready;
    }

    @Override
    public void destroy() {
      readFactory.destroy();
      bumpFactory.destroy();
    }
  }

  /** A started factory whose first connection is opened off-thread, retried until it works. */
  private static final class WarmedFactory {

    private static final Logger log = LoggerFactory.getLogger(WarmedFactory.class);
    private static final long RETRY_MIN_MILLIS = 100;
    private static final long RETRY_MAX_MILLIS = 2_000;

    private final LettuceConnectionFactory factory;
    private final Thread warmup;
    private volatile boolean ready;

    WarmedFactory(LettuceConnectionFactory factory, String threadName) {
      this.factory = factory;
      factory.afterPropertiesSet();
      factory.start();
      this.warmup = Thread.ofPlatform().daemon().name(threadName).start(this::connectWithRetry);
    }

    private void connectWithRetry() {
      long delayMillis = RETRY_MIN_MILLIS;
      boolean firstFailure = true;
      while (!Thread.currentThread().isInterrupted()) {
        try {
          // Opens and caches the shared native connection; closing the handle keeps it.
          factory.getConnection().close();
          ready = true;
          log.info("permission epoch redis connection ready thread={}",
              Thread.currentThread().getName());
          return;
        } catch (RuntimeException e) {
          if (firstFailure) {
            log.warn("permission epoch redis not reachable, retrying thread={} exception={}",
                Thread.currentThread().getName(), e.getClass().getSimpleName());
            firstFailure = false;
          }
        }
        try {
          Thread.sleep(delayMillis);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
        delayMillis = Math.min(delayMillis * 2, RETRY_MAX_MILLIS);
      }
    }

    void destroy() {
      warmup.interrupt();
      factory.destroy();
    }
  }
}
