package com.example.nexus.rbac.application.port.out;

/**
 * Thrown by {@link PermissionEpochPort#current} when the store answered, but the stored value is
 * not a non-negative epoch (US-018 M7 review L-1). It is a statement about one user's key, not
 * about the store's health, so callers must not count it as a read failure. Never reaches a
 * client: the freshness policy turns it into a stale verdict.
 */
public final class EpochUnparseableException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  /** Creates the exception; the stored value is deliberately not part of the message. */
  public EpochUnparseableException() {
    super("stored permission epoch is not a number");
  }
}
