package com.example.nexus.common.web;

/**
 * @deprecated Moved to {@link com.example.nexus.common.domain.LogMaskingUtil}.
 *     This wrapper exists so existing web-layer callers and tests continue to compile
 *     without change.  Prefer importing from {@code common.domain} in new code.
 */
@Deprecated(since = "US-002", forRemoval = true)
public final class LogMaskingUtil {

  private LogMaskingUtil() {}

  public static String maskEmail(String email) {
    return com.example.nexus.common.domain.LogMaskingUtil.maskEmail(email);
  }

  public static String sanitizeCrlf(String input) {
    return com.example.nexus.common.domain.LogMaskingUtil.sanitizeCrlf(input);
  }
}
