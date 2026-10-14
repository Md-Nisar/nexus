package com.example.nexus.rbac.application.port.out;

/**
 * Outbound port that pages on every break-glass invocation (US-018 A7, ADR-0025 6). Implemented in
 * {@code identity.infrastructure.audit} as an ERROR log carrying the {@code RBAC_BREAK_GLASS_USED}
 * marker: the page comes from a log-based alert, not a metric, because the CLI process lives for
 * seconds and is never scraped.
 */
public interface BreakGlassAlertPort {

  /** Raises the page. MUST NEVER throw: the invocation's outcome must not depend on the alert. */
  void raise(BreakGlassAlert alert);
}
