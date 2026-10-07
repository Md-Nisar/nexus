package com.example.nexus.common.security;

/**
 * Clock skew the access-token verifier tolerates after {@code exp}. It lives in {@code common} so
 * that {@code rbac} (the permission-epoch key TTL) can read it without depending on {@code
 * identity}; {@code AuthConstants.AUTH_CLOCK_SKEW_SECONDS} is this value.
 */
public final class TokenClockSkew {

  /** NTP-synchronised infra requires no skew; set to 0 to honour the 900 s design contract. */
  public static final int SECONDS = 0;

  private TokenClockSkew() {
    throw new AssertionError("no instances");
  }
}
