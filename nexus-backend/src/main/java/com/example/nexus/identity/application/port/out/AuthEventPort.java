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
   * Persists an auth event. Must never throw on persistence failure — implementations should log
   * the error and continue, so that a failed audit write never blocks the primary flow.
   *
   * @param event the event to record
   */
  void record(AuthEvent event);
}
