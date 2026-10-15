package com.example.nexus.rbac.application.port.out;

/**
 * Outbound paging port for the break-glass CLI (US-018 A7, 03-design.md §7.2). Implemented in
 * {@code identity.infrastructure.audit.BreakGlassAlertAdapter}. Called on every invocation,
 * grant or refusal. The page comes from a log-based alert on the emitted marker, never a metric:
 * the CLI process lives for seconds and is never scraped.
 *
 * <p>Implementations MUST NOT throw and MUST NOT block.
 */
public interface BreakGlassAlertPort {

  void alert(BreakGlassAlert alert);
}
