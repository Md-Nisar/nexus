package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.AuditAlert;

/**
 * Port for raising ops alerts from the audit retry buffer (US-008 WS-3, T-08-14).
 *
 * <p>Raised when {@code AuthEventRetryBuffer} (T-08-15) crosses a depth/age threshold or exhausts
 * retries for a buffered event. This story ships only a {@code LoggingAuditAlertAdapter}
 * implementation — no concrete vendor channel (e.g. Slack, PagerDuty) is wired; that choice is
 * left to ops behind this port (see {@code docs/features/US-008/03b-threat-model.md} T-I2/Gap-2).
 */
public interface AuditAlertPort {

  /**
   * Raises an alert. Implementations must be non-throwing and side-effect-cheap — no synchronous
   * network call on the hot path. A slower/real channel should fan out asynchronously if one is
   * later wired behind this port.
   *
   * @param alert the alert to raise
   */
  void raise(AuditAlert alert);
}
