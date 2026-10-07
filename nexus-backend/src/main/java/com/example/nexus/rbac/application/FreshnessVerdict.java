package com.example.nexus.rbac.application;

/**
 * Outcome of one request-time permission-epoch check (US-018 A9, design §9.1, §9.9). The tag is
 * the {@code outcome} value of {@code nexus.rbac.epoch.check}.
 */
public enum FreshnessVerdict {
  /** The token epoch is not lower than the stored epoch (an absent key reads as 0). */
  FRESH("fresh"),
  /** The token epoch is lower than the stored epoch: the token predates a revocation. */
  STALE("stale"),
  /** The store did not answer in time; this one request proceeds unchecked and is counted. */
  SKIPPED_ERROR("skipped_error");

  private final String tag;

  FreshnessVerdict(String tag) {
    this.tag = tag;
  }

  /** Returns the metric tag value for this verdict. */
  public String tag() {
    return tag;
  }
}
