package com.example.nexus.rbac.application;

/**
 * Per-instance state of the permission-epoch outage policy (US-018 A9, design §9.5). The tag is
 * the {@code state} value of the {@code nexus.rbac.epoch.degraded} gauge.
 */
public enum DegradedState {
  /** Epoch checks run on every non-public authenticated request. */
  HEALTHY("healthy"),
  /** Epoch checks are skipped; requests fail open until the time box ends. */
  DEGRADED_OPEN("open"),
  /** The time box has ended; non-public authenticated requests get 503 {@code AUTH_005}. */
  DEGRADED_CLOSED("closed"),
  /** A probe succeeded; epoch checks resume, and {@code t0} is kept until sustained health. */
  RECOVERING("recovering");

  private final String tag;

  DegradedState(String tag) {
    this.tag = tag;
  }

  /** Returns the metric tag value for this state. */
  public String tag() {
    return tag;
  }
}
