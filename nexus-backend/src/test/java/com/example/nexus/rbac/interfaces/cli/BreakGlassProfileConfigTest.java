package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.Environment;

/**
 * US-018 M5 (03-design.md §7.2 Packaging, RC-37.4): the {@code application-break-glass.yml} values
 * as Spring's real config-data loader resolves them, not as a raw YAML read ({@code
 * BreakGlassAdminRunnerTest#should_pinBreakGlassProfileConfig}). Proves the profile document
 * activates, that the flush wait defaults to 15 s and takes the documented environment override,
 * and that none of it leaks into a serving profile.
 */
@Tag("UnitTest")
class BreakGlassProfileConfigTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner().withInitializer(new ConfigDataApplicationContextInitializer());

  @Test
  void should_resolveNonWebNoFlywayAndDefaultFlushWait_when_breakGlassProfileActive() {
    runner
        .withPropertyValues("spring.profiles.active=break-glass")
        .run(
            context -> {
              Environment env = context.getEnvironment();

              assertThat(env.getProperty("spring.main.web-application-type")).isEqualTo("none");
              assertThat(env.getProperty("spring.flyway.enabled", Boolean.class)).isFalse();
              assertThat(env.getProperty("spring.datasource.hikari.maximum-pool-size", Integer.class))
                  .isEqualTo(4);
              assertThat(flushWait(env)).isEqualTo(Duration.ofSeconds(15));
            });
  }

  @Test
  void should_takeTheEnvironmentOverrideForTheFlushWait_when_breakGlassProfileActive() {
    runner
        .withPropertyValues(
            "spring.profiles.active=break-glass", "NEXUS_RBAC_BREAK_GLASS_LOG_FLUSH_WAIT=40s")
        .run(
            context -> assertThat(flushWait(context.getEnvironment())).isEqualTo(Duration.ofSeconds(40)));
  }

  @Test
  void should_notApplyAnyBreakGlassSetting_when_breakGlassProfileInactive() {
    runner
        .withPropertyValues("spring.profiles.active=test")
        .run(
            context -> {
              Environment env = context.getEnvironment();

              assertThat(env.getProperty("spring.main.web-application-type")).isNotEqualTo("none");
              assertThat(env.getProperty("nexus.rbac.break-glass.log-flush-wait")).isNull();
              assertThat(env.getProperty("spring.datasource.hikari.maximum-pool-size"))
                  .isNotEqualTo("4");
            });
  }

  /** The runner's {@code @Value} Duration conversion (Boot's duration style), resolved by hand. */
  private static Duration flushWait(Environment env) {
    return DurationStyle.detectAndParse(env.getRequiredProperty("nexus.rbac.break-glass.log-flush-wait"));
  }
}
