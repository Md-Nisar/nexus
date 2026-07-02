package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

/**
 * US-008 T-08-15 — binds {@link AuditRetryProperties} via {@link ApplicationContextRunner} and
 * cross-checks every default against the concrete table in {@code
 * docs/features/US-008/03-design.md} §4.1 and ADR 0011 §2, so an accidental edit to a default is
 * caught immediately.
 */
class AuditRetryPropertiesTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withConfiguration(
              org.springframework.boot.autoconfigure.AutoConfigurations.of(
                  PropertyPlaceholderAutoConfiguration.class))
          .withUserConfiguration(TestConfig.class);

  @Test
  void should_bindTopLevelDefaults_when_noPropertiesSupplied() {
    contextRunner.run(
        context -> {
          AuditRetryProperties props = context.getBean(AuditRetryProperties.class);

          assertThat(props.enabled()).isTrue();
          assertThat(props.priorityCapacity()).isEqualTo(200);
          assertThat(props.standardCapacity()).isEqualTo(800);
          assertThat(props.drainIntervalMs()).isEqualTo(10_000L);
          assertThat(props.maxAttempts()).isEqualTo(5);
        });
  }

  @Test
  void should_bindBackoffScheduleDefaults_when_noPropertiesSupplied() {
    contextRunner.run(
        context -> {
          AuditRetryProperties props = context.getBean(AuditRetryProperties.class);

          assertThat(props.backoffSchedule())
              .containsExactly(
                  Duration.ofSeconds(1),
                  Duration.ofSeconds(5),
                  Duration.ofSeconds(30),
                  Duration.ofMinutes(2),
                  Duration.ofMinutes(10));
          assertThat(props.backoffSchedule()).hasSize(props.maxAttempts());
        });
  }

  @Test
  void should_bindPriorityLaneDefaults_when_noPropertiesSupplied() {
    contextRunner.run(
        context -> {
          AuditRetryProperties props = context.getBean(AuditRetryProperties.class);

          assertThat(props.priority().depthWarn()).isEqualTo(1);
          assertThat(props.priority().depthCritical()).isEqualTo(180);
          assertThat(props.priority().ageCritical()).isEqualTo(Duration.ofMinutes(15));
        });
  }

  @Test
  void should_bindStandardLaneDefaults_when_noPropertiesSupplied() {
    contextRunner.run(
        context -> {
          AuditRetryProperties props = context.getBean(AuditRetryProperties.class);

          assertThat(props.standard().depthWarn()).isEqualTo(250);
          assertThat(props.standard().depthCritical()).isEqualTo(720);
          assertThat(props.standard().ageCritical()).isEqualTo(Duration.ofMinutes(15));
        });
  }

  @Test
  void should_bindOverriddenValues_when_propertiesSupplied() {
    contextRunner
        .withPropertyValues(
            "nexus.identity.audit.retry-buffer.enabled=false",
            "nexus.identity.audit.retry-buffer.priority-capacity=10",
            "nexus.identity.audit.retry-buffer.standard-capacity=20")
        .run(
            context -> {
              AuditRetryProperties props = context.getBean(AuditRetryProperties.class);

              assertThat(props.enabled()).isFalse();
              assertThat(props.priorityCapacity()).isEqualTo(10);
              assertThat(props.standardCapacity()).isEqualTo(20);
            });
  }

  @Test
  void should_substitutePriorityDefaults_when_constructedDirectlyWithNullPriority() {
    AuditRetryProperties props =
        new AuditRetryProperties(true, 200, 800, 10_000L, 5, List.of(Duration.ofSeconds(1)),
            null, AuditRetryProperties.LaneThresholds.standardDefaults());

    assertThat(props.priority()).isEqualTo(AuditRetryProperties.LaneThresholds.priorityDefaults());
  }

  @Test
  void should_substituteStandardDefaults_when_constructedDirectlyWithNullStandard() {
    AuditRetryProperties props =
        new AuditRetryProperties(true, 200, 800, 10_000L, 5, List.of(Duration.ofSeconds(1)),
            AuditRetryProperties.LaneThresholds.priorityDefaults(), null);

    assertThat(props.standard()).isEqualTo(AuditRetryProperties.LaneThresholds.standardDefaults());
  }

  @Configuration
  @EnableConfigurationProperties(AuditRetryProperties.class)
  static class TestConfig {}
}
