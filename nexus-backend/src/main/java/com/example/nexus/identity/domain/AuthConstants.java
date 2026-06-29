package com.example.nexus.identity.domain;

import java.time.Duration;

/** Token lifetime constants shared across the identity bounded context. */
public final class AuthConstants {

  public static final int AUTH_REFRESH_TOKEN_TTL_DAYS = 14;
  public static final int AUTH_ACCESS_TOKEN_TTL_SECONDS = 900;
  public static final Duration AUTH_VERIFICATION_TOKEN_TTL = Duration.ofHours(24);
  public static final Duration AUTH_RESET_TOKEN_TTL = Duration.ofMinutes(60);
  /** NTP-synchronised infra requires no skew; set to 0 to honour the 900 s design contract. */
  public static final int AUTH_CLOCK_SKEW_SECONDS = 0;

  /** Maximum consecutive failed login attempts before the account is locked. */
  public static final int LOCKOUT_THRESHOLD = 5;

  /** Consecutive-failure window in seconds. NOTE: the current implementation counts all
   *  failures since the last successful login — it does not enforce a rolling time window.
   *  This constant is retained for documentation and future rolling-window implementation. */
  public static final int LOCKOUT_WINDOW_SECONDS = 900; // 15 min

  /**
   * How long (in seconds) an account remains locked after reaching {@link #LOCKOUT_THRESHOLD}.
   * Kept separate from {@link #LOCKOUT_WINDOW_SECONDS} so each can be tuned independently.
   */
  public static final int LOCKOUT_DURATION_SECONDS = 900; // 15 min

  private AuthConstants() {
    throw new AssertionError("no instances");
  }
}
