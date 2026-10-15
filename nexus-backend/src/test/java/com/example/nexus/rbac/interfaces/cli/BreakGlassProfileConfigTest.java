package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

/**
 * US-018 A7 (T-008): pins the values of {@code application-break-glass.yml}. {@code
 * BreakGlassAdminIT} overrides Flyway and the flush interval to build its schema and run fast, so
 * without this test a dropped {@code flyway.enabled: false} or a shortened flush wait would pass.
 */
class BreakGlassProfileConfigTest {

  @Test
  void should_disableFlywayAndWebAndWaitFifteenSeconds_when_breakGlassProfileFileIsLoaded()
      throws IOException {
    List<PropertySource<?>> sources =
        new YamlPropertySourceLoader()
            .load("break-glass", new ClassPathResource("application-break-glass.yml"));

    assertThat(sources).singleElement();
    PropertySource<?> profile = sources.get(0);
    assertThat(profile.getProperty("spring.main.web-application-type"))
        .as("no embedded server (RC-37.6)")
        .hasToString("none");
    assertThat(profile.getProperty("spring.flyway.enabled"))
        .as("the tool never migrates a schema")
        .hasToString("false");
    assertThat(profile.getProperty("nexus.rbac.break-glass.log-flush-interval"))
        .as("RC-37.4 page flush wait, kept at 15 s by the story owner (2026-10-15)")
        .hasToString("15s");
  }
}
