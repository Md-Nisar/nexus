package com.example.nexus.identity.infrastructure.audit;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * US-008 T-08-15 — registers {@link AuditRetryProperties} as a bean.
 *
 * <p>Deliberately unconditional (unlike {@link SchedulingConfig}): {@link AuthEventRetryBuffer}
 * itself always exists regardless of the {@code nexus.identity.audit.retry-buffer.enabled}
 * escape hatch (design §10.3) — only the scheduler that drains it is flag-gated — so its
 * {@link AuditRetryProperties} dependency must always be available too.
 */
@Configuration
@EnableConfigurationProperties(AuditRetryProperties.class)
class AuditRetryPropertiesConfig {}
