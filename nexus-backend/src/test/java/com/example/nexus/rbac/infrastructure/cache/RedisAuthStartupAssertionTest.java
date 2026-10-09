package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.lettuce.core.resource.ClientResources;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.context.logging.LoggingApplicationListener;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisSentinelConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/**
 * Unit tests for {@link RedisAuthStartupAssertion} (US-018 T-014, RC-34.1, RC-45.1, RC-45.2): with
 * {@code nexus.rbac.redis.require-auth=true}, startup fails unless the main factory and both
 * dedicated epoch factories carry a password in their effective configuration. Factories are built
 * but never started, so no test here opens a connection.
 */
@Tag("UnitTest")
class RedisAuthStartupAssertionTest {

  private static final String REQUIRE_AUTH = "nexus.rbac.redis.require-auth";

  private static final String[] EPOCH_PROPERTIES = {
      "nexus.rbac.epoch.command-timeout=50ms",
      "nexus.rbac.epoch.bump-timeout=500ms",
      "nexus.rbac.epoch.key-ttl-seconds=960",
      "nexus.jwt.access-token-ttl-seconds=900",
      "nexus.rbac.permission-cache-ttl-seconds=900"
  };

  /** Boot applications convert "50ms" to Duration; a bare runner does not. */
  private static final ApplicationContextInitializer<ConfigurableApplicationContext>
      BOOT_CONVERSION = context -> context.getBeanFactory()
          .setConversionService(ApplicationConversionService.getSharedInstance());

  private final String password = UUID.randomUUID().toString();

  // --- each factory checked separately ---

  @Test
  void should_failStartup_when_requireAuthAndMainFactoryPasswordBlank() {
    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, standalone(null, null), standalone(null, password), standalone(null, password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"main\"");
  }

  @Test
  void should_failStartup_when_requireAuthAndEpochReadFactoryPasswordBlank() {
    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, standalone(null, password), standalone(null, null), standalone(null, password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"epoch-read\"");
  }

  @Test
  void should_failStartup_when_requireAuthAndEpochBumpFactoryPasswordBlank() {
    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, standalone(null, password), standalone(null, password), standalone(null, null)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"epoch-bump\"");
  }

  @Test
  void should_failStartup_when_requireAuthAndPasswordEmpty() {
    LettuceConnectionFactory empty = standalone(null, "");

    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, standalone(null, password), standalone(null, password), empty))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"epoch-bump\"");
  }

  @Test
  void should_failStartup_when_requireAuthAndPasswordWhitespaceOnly() {
    RedisStandaloneConfiguration config = new RedisStandaloneConfiguration("redis.internal", 6379);
    config.setPassword(" \t ".toCharArray());
    LettuceConnectionFactory whitespace = new LettuceConnectionFactory(config);

    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, whitespace, standalone(null, password), standalone(null, password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"main\"");
  }

  @Test
  void should_failStartup_when_requireAuthAndUsernameWithoutPassword() {
    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, standalone("nexus", password), standalone("nexus", null),
            standalone("nexus", password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"epoch-read\"");
  }

  @Test
  void should_start_when_requireAuthAndAllFactoriesHavePassword() {
    assertThatCode(() -> RedisAuthStartupAssertion.verify(
            true, standalone("nexus", password), standalone("nexus", password),
            standalone(null, password)))
        .doesNotThrowAnyException();
  }

  @Test
  void should_start_when_requireAuthFalseAndPasswordsBlank() {
    assertThatCode(() -> RedisAuthStartupAssertion.verify(
            false, standalone(null, null), standalone(null, ""), standalone("nexus", null)))
        .doesNotThrowAnyException();
  }

  // --- Sentinel ---

  @Test
  void should_failStartup_when_requireAuthAndSentinelPasswordBlank() {
    LettuceConnectionFactory noSentinelPassword = sentinel(null, password, null);

    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, sentinel(null, password, password), noSentinelPassword,
            sentinel(null, password, password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"epoch-read\"")
        .hasMessageContaining("spring.data.redis.sentinel.password");
  }

  @Test
  void should_failStartup_when_requireAuthAndSentinelDataNodePasswordBlank() {
    LettuceConnectionFactory noDataPassword = sentinel(null, null, password);

    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(
            true, noDataPassword, sentinel(null, password, password),
            sentinel(null, password, password)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("\"main\"")
        .hasMessageContaining("spring.data.redis.password");
  }

  @Test
  void should_start_when_requireAuthAndSentinelAndDataNodePasswordsSet() {
    assertThatCode(() -> RedisAuthStartupAssertion.verify(
            true, sentinel("nexus", password, password), sentinel("nexus", password, password),
            sentinel("nexus", password, password)))
        .doesNotThrowAnyException();
  }

  @Test
  void should_notIncludeCredentialValues_when_failureMessageBuilt() {
    String username = "user-" + UUID.randomUUID();
    String sentinelPassword = UUID.randomUUID().toString();
    LettuceConnectionFactory leaky = sentinel(username, null, sentinelPassword);

    assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(true, leaky, leaky, leaky))
        .isInstanceOf(IllegalStateException.class)
        .message()
        .doesNotContain(username)
        .doesNotContain(sentinelPassword)
        .doesNotContain("sentinel.internal")
        .doesNotContain("primary");
  }

  // --- effective credentials, as Boot resolves them (security review M7 Low 5) ---

  @Test
  void should_start_when_passwordSuppliedOnlyThroughRedissUrl() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class))
        .withPropertyValues(
            "spring.data.redis.url=rediss://nexus:" + password + "@redis.internal:6380")
        .run(context -> {
          LettuceConnectionFactory main = context.getBean(LettuceConnectionFactory.class);
          DataRedisConnectionDetails details = context.getBean(DataRedisConnectionDetails.class);
          ClientResources resources = context.getBean(ClientResources.class);

          assertThatCode(() -> RedisAuthStartupAssertion.verify(
                  true,
                  main,
                  EpochRedisConfig.dedicatedFactory(details, main, resources, Duration.ofMillis(50)),
                  EpochRedisConfig.dedicatedFactory(
                      details, main, resources, Duration.ofMillis(500))))
              .doesNotThrowAnyException();
        });
  }

  @Test
  void should_failStartup_when_urlHasNoUserinfoAndOnlyPasswordPropertySet() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class))
        .withPropertyValues(
            "spring.data.redis.url=redis://redis.internal:6379",
            "spring.data.redis.password=" + password)
        .run(context -> {
          LettuceConnectionFactory main = context.getBean(LettuceConnectionFactory.class);
          DataRedisConnectionDetails details = context.getBean(DataRedisConnectionDetails.class);
          ClientResources resources = context.getBean(ClientResources.class);
          LettuceConnectionFactory read =
              EpochRedisConfig.dedicatedFactory(details, main, resources, Duration.ofMillis(50));
          LettuceConnectionFactory bump =
              EpochRedisConfig.dedicatedFactory(details, main, resources, Duration.ofMillis(500));

          assertThatThrownBy(() -> RedisAuthStartupAssertion.verify(true, main, read, bump))
              .isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("\"main\"");
        });
  }

  @Test
  void should_failStartup_when_epochTemplatesBeanCreatedWithRequireAuthAndBlankPassword() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class))
        .withUserConfiguration(EpochRedisConfig.class)
        .withInitializer(BOOT_CONVERSION)
        .withPropertyValues(EPOCH_PROPERTIES)
        .withPropertyValues(
            "spring.data.redis.host=redis.internal", REQUIRE_AUTH + "=true")
        .run(context -> {
          assertThat(context).hasFailed();
          assertThat(rootCause(context.getStartupFailure()))
              .isInstanceOf(IllegalStateException.class)
              .hasMessageContaining(REQUIRE_AUTH);
        });
  }

  @Test
  void should_createEpochTemplates_when_requireAuthFalseAndBlankPassword() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class))
        .withUserConfiguration(EpochRedisConfig.class)
        .withInitializer(BOOT_CONVERSION)
        .withPropertyValues(EPOCH_PROPERTIES)
        .withPropertyValues(
            "spring.data.redis.host=redis.internal", REQUIRE_AUTH + "=false")
        .run(context -> assertThat(context)
            .hasNotFailed()
            .hasSingleBean(EpochRedisConfig.EpochTemplates.class));
  }

  // --- profile resolution (RC-45.1) ---

  @Test
  void should_resolveRequireAuthTrue_when_prodProfileActive() {
    assertThat(resolveRequireAuth("prod")).isTrue();
  }

  @Test
  void should_resolveRequireAuthFalse_when_noProfileActive() {
    assertThat(resolveRequireAuth()).isFalse();
  }

  @Test
  void should_resolveRequireAuthFalse_when_devProfileActive() {
    assertThat(resolveRequireAuth("dev")).isFalse();
  }

  @Test
  void should_resolveRequireAuthFalse_when_testProfileActive() {
    assertThat(resolveRequireAuth("test")).isFalse();
  }

  /**
   * Resolves the property from the real {@code application*.yml} files through Boot's config-data
   * loading only: an empty configuration, no auto-configuration, no web server, and no logging
   * re-initialisation (the prod file switches console logging to ECS).
   */
  private static Boolean resolveRequireAuth(String... profiles) {
    SpringApplication app = new SpringApplication(EmptyConfig.class);
    app.setWebApplicationType(WebApplicationType.NONE);
    app.setRegisterShutdownHook(false);
    app.setLogStartupInfo(false);
    app.setListeners(app.getListeners().stream()
        .filter(listener -> !(listener instanceof LoggingApplicationListener))
        .toList());
    app.setAdditionalProfiles(profiles);
    try (ConfigurableApplicationContext context = app.run("--spring.main.banner-mode=off")) {
      return context.getEnvironment().getProperty(REQUIRE_AUTH, Boolean.class);
    }
  }

  /** Deliberately empty: only the environment is under test. */
  @Configuration(proxyBeanMethods = false)
  static class EmptyConfig {
  }

  private static Throwable rootCause(Throwable failure) {
    Throwable cause = failure;
    while (cause.getCause() != null) {
      cause = cause.getCause();
    }
    return cause;
  }

  private static LettuceConnectionFactory standalone(String username, String password) {
    RedisStandaloneConfiguration config = new RedisStandaloneConfiguration("redis.internal", 6379);
    config.setUsername(username);
    config.setPassword(RedisPassword.of(password));
    return new LettuceConnectionFactory(config);
  }

  private static LettuceConnectionFactory sentinel(
      String username, String password, String sentinelPassword) {
    RedisSentinelConfiguration config = new RedisSentinelConfiguration()
        .master("primary")
        .sentinel("sentinel.internal", 26379);
    config.setUsername(username);
    config.setPassword(RedisPassword.of(password));
    config.setSentinelPassword(RedisPassword.of(sentinelPassword));
    return new LettuceConnectionFactory(config);
  }
}
