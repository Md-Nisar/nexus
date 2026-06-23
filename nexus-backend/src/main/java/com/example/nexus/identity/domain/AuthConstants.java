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

  private AuthConstants() {
    throw new AssertionError("no instances");
  }
}
