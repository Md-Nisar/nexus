package com.example.nexus.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

/**
 * US-019 T-027 (RC-63(h)): the e2e suite raises the login and refresh rate limits, and it does so
 * only through the CI-only {@code docker-compose.e2e.yml}. No profile file that can reach a shared
 * environment may set one of those limits above the {@code application.yml} default. The {@code
 * test} profile is exempt: it exists solely for the automated tests.
 */
@Tag("UnitTest")
class RateLimitProfileDefaultsTest {

  private static final String PREFIX = "nexus.security.rate-limit.";

  private static final List<String> LOGIN_AND_REFRESH_LIMITS =
      List.of(
          "ip-max-attempts",
          "user-max-attempts",
          "refresh-ip-max-attempts",
          "refresh-family-max-attempts",
          "refresh-fail-max-attempts");

  @ParameterizedTest
  @ValueSource(strings = {"dev", "prod", "break-glass"})
  void should_notRaiseLoginOrRefreshLimits_when_profileFileIsLoaded(String profile) {
    Properties base = load("application.yml");
    Properties overrides = load("application-" + profile + ".yml");

    for (String key : LOGIN_AND_REFRESH_LIMITS) {
      String overridden = overrides.getProperty(PREFIX + key);
      if (overridden == null) {
        continue;
      }
      assertThat(Integer.parseInt(overridden.trim()))
          .as("application-%s.yml must not raise %s%s", profile, PREFIX, key)
          .isLessThanOrEqualTo(Integer.parseInt(base.getProperty(PREFIX + key).trim()));
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"application.yml"})
  void should_defineEveryGuardedLimit_when_baseConfigurationIsLoaded(String file) {
    Properties base = load(file);

    for (String key : LOGIN_AND_REFRESH_LIMITS) {
      assertThat(base.getProperty(PREFIX + key)).as("%s%s", PREFIX, key).matches("\\d+");
    }
  }

  private static Properties load(String resource) {
    YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
    yaml.setResources(new ClassPathResource(resource));
    Properties properties = yaml.getObject();
    assertThat(properties).as(resource).isNotNull();
    return properties;
  }
}
