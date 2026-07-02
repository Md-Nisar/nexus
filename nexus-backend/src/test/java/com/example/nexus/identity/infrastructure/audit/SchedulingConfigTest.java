package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor;

/**
 * US-008 T-08-15 — confirms the {@code nexus.identity.audit.retry-buffer.enabled} escape-hatch
 * flag (design §10.3) genuinely gates whether Spring's scheduling infrastructure is enabled,
 * without loading the full application context.
 */
class SchedulingConfigTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner().withUserConfiguration(SchedulingConfig.class);

  @Test
  void should_registerScheduledAnnotationProcessor_when_flagDefaulted() {
    contextRunner.run(
        context ->
            assertThat(context).hasSingleBean(ScheduledAnnotationBeanPostProcessor.class));
  }

  @Test
  void should_registerScheduledAnnotationProcessor_when_flagExplicitlyTrue() {
    contextRunner
        .withPropertyValues("nexus.identity.audit.retry-buffer.enabled=true")
        .run(
            context ->
                assertThat(context).hasSingleBean(ScheduledAnnotationBeanPostProcessor.class));
  }

  @Test
  void should_notRegisterScheduledAnnotationProcessor_when_flagFalse() {
    contextRunner
        .withPropertyValues("nexus.identity.audit.retry-buffer.enabled=false")
        .run(
            context ->
                assertThat(context).doesNotHaveBean(ScheduledAnnotationBeanPostProcessor.class));
  }
}
