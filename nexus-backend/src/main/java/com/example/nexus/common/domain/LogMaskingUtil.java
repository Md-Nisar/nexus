package com.example.nexus.common.domain;

/**
 * Static helpers for masking PII and sanitising user-supplied strings before they reach log
 * output. Prevents accidental exposure of email addresses and log injection via CRLF characters.
 *
 * <p>No Spring or external dependencies — pure JDK so this class is safe to use from any layer
 * (domain, application, infrastructure, interfaces).
 */
public final class LogMaskingUtil {

  private LogMaskingUtil() {}

  /**
   * Masks an email address so only its first character and domain are visible.
   * {@code alice@example.com} becomes {@code a***@example.com}.
   *
   * <p>Edge cases: {@code null} → {@code null}; no {@code @} sign → returned unchanged;
   * zero-length local part (e.g. {@code @host}) → {@code ***@host}.
   */
  public static String maskEmail(String email) {
    if (email == null) {
      return null;
    }
    int at = email.indexOf('@');
    if (at < 0) {
      return email;
    }
    if (at == 0) {
      return "***" + email.substring(at);
    }
    return email.charAt(0) + "***" + email.substring(at);
  }

  /**
   * Replaces every {@code \r} and {@code \n} character with {@code _} to prevent log injection.
   * Returns {@code null} when given {@code null}.
   */
  public static String sanitizeCrlf(String input) {
    return input == null ? null : input.replaceAll("[\r\n]", "_");
  }
}
