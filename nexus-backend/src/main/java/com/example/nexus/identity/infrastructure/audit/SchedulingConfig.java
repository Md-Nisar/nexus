package com.example.nexus.identity.infrastructure.audit;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * US-008 T-08-15 (design §4.2, ADR 0011 §3) — the single {@code @EnableScheduling} point in the
 * codebase (verified absent elsewhere prior to this task). Enables Spring's {@code
 * ScheduledAnnotationBeanPostProcessor}, which is what makes {@link
 * AuthEventRetryBuffer#drain()}'s {@code @Scheduled} annotation actually run.
 *
 * <p>Guarded by the same escape-hatch flag as the buffer itself (design §10.3): {@code
 * nexus.identity.audit.retry-buffer.enabled=false} skips this configuration entirely, so no
 * {@code ScheduledAnnotationBeanPostProcessor} bean is registered and {@code drain()} is never
 * invoked — no drain thread starts. {@link AuthEventRetryBuffer} itself is not conditional: it
 * always exists as a bean (so {@code enqueue()} and its metrics remain available), but with the
 * flag off nothing ever calls {@code enqueue()} in the first place (T-08-16's adapter reverts to
 * synchronous-swallow-and-WARN-only when disabled) and nothing ever drains it.
 */
@Configuration
@EnableScheduling
@ConditionalOnProperty(
    name = "nexus.identity.audit.retry-buffer.enabled",
    havingValue = "true",
    matchIfMissing = true)
class SchedulingConfig {}
