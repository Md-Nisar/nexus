package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.AuthEvent;

/**
 * Port for appending {@link AuthEvent} audit records.
 *
 * <p>Auth events are append-only — there is deliberately no read or update method on this port
 * (the DB trigger enforces immutability at the storage layer).
 */
public interface AuthEventPort {

  /**
   * Persists an auth event. Must never throw or block on persistence failure — on failure,
   * implementations enqueue the event for bounded, backed-off retry (US-008 T-08-16; see {@code
   * com.example.nexus.identity.infrastructure.audit.AuthEventRetryBuffer}) so a transient
   * audit-store outage does not lose the event outright. If retry buffering is disabled (the
   * {@code nexus.identity.audit.retry-buffer.enabled} escape hatch), implementations fall back to
   * logging the failure and continuing. In every case — success, buffered failure, or
   * unbuffered failure — the call never throws and never blocks the primary flow.
   *
   * @param event the event to record
   */
  @SuppressWarnings("java:S6213")
  void record(AuthEvent event);
}
