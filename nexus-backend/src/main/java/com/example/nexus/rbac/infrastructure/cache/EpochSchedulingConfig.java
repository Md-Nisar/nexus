package com.example.nexus.rbac.infrastructure.cache;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables Spring scheduling for the permission-epoch probe (US-018 A9, design §9.5, RC-52).
 *
 * <p>Deliberately unconditional. The identity context's {@code SchedulingConfig} is conditional on
 * {@code nexus.identity.audit.retry-buffer.enabled}; if the probe relied on it, switching that
 * escape hatch off would stop the probe and a degraded instance would never recover.
 * {@code @EnableScheduling} is idempotent, so both declarations may be active together.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class EpochSchedulingConfig {}
