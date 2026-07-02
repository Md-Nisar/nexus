package com.example.nexus.identity.domain;

import java.time.Instant;

/**
 * An ops alert raised by the audit retry buffer (US-008 WS-3, T-08-14) when a lane crosses a
 * depth/age threshold, or a buffered event exhausts its retry budget.
 *
 * <p>Carried through {@code AuditAlertPort#raise(AuditAlert)}. Implementations (e.g. {@code
 * LoggingAuditAlertAdapter}) must treat this as a plain, non-throwing data carrier — no
 * synchronous network call is made from the hot drain path.
 *
 * @param type the kind/severity of the alert
 * @param message a human-readable description of what triggered the alert
 * @param occurredAt when the triggering condition was observed
 * @param bufferDepth the buffer/lane depth at the time of the alert (0 when not depth-related,
 *     e.g. {@link AuditAlertType#RETRY_EXHAUSTED})
 */
public record AuditAlert(AuditAlertType type, String message, Instant occurredAt, int bufferDepth) {
}
