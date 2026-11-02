package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.context.logging.LoggingApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

/**
 * US-018 T-024 (B8, RC-45.1, RC-54(b)): with {@code nexus.rbac.throttle.require-shared-store=true}
 * startup fails unless the rate-limit store is {@code redis}, and the {@code prod} profile resolves
 * the property to {@code true}.
 */
@Tag("UnitTest")
class ThrottleSharedStoreStartupAssertionTest {

  private static final String REQUIRE_SHARED_STORE = "nexus.rbac.throttle.require-shared-store";

  @Test
  void should_failStartup_when_sharedStoreRequiredAndStoreTypeIsMemory() {
    assertThatThrownBy(() -> ThrottleSharedStoreStartupAssertion.verify(true, "memory"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.rbac.throttle.require-shared-store=true")
        .hasMessageContaining("nexus.security.rate-limit.store-type=memory");
  }

  @Test
  void should_failStartup_when_sharedStoreRequiredAndStoreTypeIsUnknown() {
    assertThatThrownBy(() -> ThrottleSharedStoreStartupAssertion.verify(true, ""))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void should_start_when_sharedStoreRequiredAndStoreTypeIsRedis() {
    assertThatCode(() -> ThrottleSharedStoreStartupAssertion.verify(true, "redis"))
        .doesNotThrowAnyException();
  }

  @Test
  void should_start_when_sharedStoreNotRequiredAndStoreTypeIsMemory() {
    assertThatCode(() -> ThrottleSharedStoreStartupAssertion.verify(false, "memory"))
        .doesNotThrowAnyException();
  }

  @Test
  void should_failAtStartup_when_beanIsBuiltWithMemoryAndRequirement() {
    assertThatThrownBy(() -> new ThrottleSharedStoreStartupAssertion(true, "memory").verifyAtStartup())
        .isInstanceOf(IllegalStateException.class);
  }

  // --- profile resolution (RC-54(b)) ---

  @Test
  void should_resolveRequireSharedStoreFalse_when_noProfileActive() {
    assertThat(resolveRequireSharedStore()).isFalse();
  }

  @Test
  void should_resolveRequireSharedStoreFalse_when_devProfileActive() {
    assertThat(resolveRequireSharedStore("dev")).isFalse();
  }

  /**
   * RC-54(b). DISABLED until a human adds the production line: {@code application-prod.yml} is
   * hook-protected against agent edits, exactly as for {@code nexus.rbac.redis.require-auth} in
   * T-014. Add under the existing {@code nexus.rbac} block of {@code application-prod.yml}:
   *
   * <pre>
   * nexus:
   *   rbac:
   *     throttle:
   *       require-shared-store: true
   * </pre>
   *
   * and remove this {@code @Disabled}. The runbook keeps it as a deployment check.
   */
  @Test
  void should_enforce_shared_throttle_store_in_prod() {
    assertThat(resolveRequireSharedStore("prod")).isTrue();
  }
  @Test
  void should_resolveRequireSharedStoreTrue_when_prodProfileActive() {
    assertThat(resolveRequireSharedStore("prod")).isTrue();
  }

  /**
   * Resolves the property from the real {@code application*.yml} files through Boot's config-data
   * loading only (see {@code RedisAuthStartupAssertionTest}).
   */
  private static Boolean resolveRequireSharedStore(String... profiles) {
    SpringApplication app = new SpringApplication(EmptyConfig.class);
    app.setWebApplicationType(WebApplicationType.NONE);
    app.setRegisterShutdownHook(false);
    app.setLogStartupInfo(false);
    app.setListeners(
        app.getListeners().stream()
            .filter(listener -> !(listener instanceof LoggingApplicationListener))
            .toList());
    app.setAdditionalProfiles(profiles);
    try (ConfigurableApplicationContext context = app.run("--spring.main.banner-mode=off")) {
      return context.getEnvironment().getProperty(REQUIRE_SHARED_STORE, Boolean.class);
    }
  }

  /** Deliberately empty: only the environment is under test. */
  @Configuration(proxyBeanMethods = false)
  static class EmptyConfig {}
}
