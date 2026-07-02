package com.example.nexus.identity.domain;

/**
 * Severity/kind of an ops alert raised by the audit retry buffer (US-008 WS-3, T-08-14).
 *
 * <p>Raised via {@code AuditAlertPort} when {@code AuthEventRetryBuffer} (T-08-15) crosses a
 * depth/age threshold or exhausts retries for a buffered {@link AuthEvent}. See {@code
 * docs/features/US-008/03-design.md} §4.1 for the concrete threshold values that trigger each
 * constant.
 */
public enum AuditAlertType {
  /** A lane's buffered-event depth crossed the warn threshold (§4.1: ticket-worthy). */
  BUFFER_DEPTH_WARN,

  /** A lane's buffered-event depth crossed the critical threshold (§4.1: page-worthy). */
  BUFFER_DEPTH_CRITICAL,

  /** The oldest un-drained event in a lane exceeded the age-critical threshold (§4.1). */
  BUFFER_AGE_CRITICAL,

  /** A buffered event was dropped after exhausting all retry attempts (§4.1: data loss). */
  RETRY_EXHAUSTED
}
