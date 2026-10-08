package com.example.nexus.rbac.infrastructure.cache;

import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisSentinelConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/**
 * Refuses to start against an unauthenticated Redis when {@code nexus.rbac.redis.require-auth} is
 * true (US-018 T-014, RC-34.1, RC-45.1, RC-45.2). Redis write access equals permission injection
 * and revocation suppression (RES-32), so production must authenticate every connection.
 *
 * <p>Each factory is checked separately, on its <b>effective</b> configuration rather than on the
 * {@code spring.data.redis.password} property: with {@code spring.data.redis.url} set, Boot takes
 * the credentials from the URL userinfo only and ignores the property (security review M7 Low 5).
 * Under Sentinel the Sentinel password is required too. A password that is absent, empty or only
 * whitespace counts as missing; a username alone does not authenticate.
 *
 * <p>Failure messages name the factory and the properties to set, never a credential, username,
 * URL or host.
 */
final class RedisAuthStartupAssertion {

  private static final String PASSWORD_SOURCES =
      "spring.data.redis.password, or the password in the spring.data.redis.url userinfo";
  private static final String SENTINEL_PASSWORD_SOURCE = "spring.data.redis.sentinel.password";

  private RedisAuthStartupAssertion() {
  }

  /**
   * Checks the three factories; does nothing when {@code requireAuth} is false.
   *
   * @param requireAuth {@code nexus.rbac.redis.require-auth}
   * @param main the auto-configured main factory
   * @param read the dedicated epoch-read factory
   * @param bump the dedicated epoch-bump factory
   * @throws IllegalStateException if any factory lacks a password
   */
  static void verify(
      boolean requireAuth,
      LettuceConnectionFactory main,
      LettuceConnectionFactory read,
      LettuceConnectionFactory bump) {
    if (!requireAuth) {
      return;
    }
    verify("main", main);
    verify("epoch-read", read);
    verify("epoch-bump", bump);
  }

  private static void verify(String name, LettuceConnectionFactory factory) {
    RedisSentinelConfiguration sentinel = factory.getSentinelConfiguration();
    if (sentinel != null) {
      requirePassword(name, "password", sentinel.getPassword(), PASSWORD_SOURCES);
      requirePassword(
          name, "Sentinel password", sentinel.getSentinelPassword(), SENTINEL_PASSWORD_SOURCE);
      return;
    }
    requirePassword(
        name, "password", factory.getStandaloneConfiguration().getPassword(), PASSWORD_SOURCES);
  }

  private static void requirePassword(
      String name, String what, RedisPassword password, String sources) {
    if (isBlank(password)) {
      throw new IllegalStateException(
          "nexus.rbac.redis.require-auth=true but the \"" + name + "\" Redis connection has no "
              + what + "; set " + sources + " (RC-34.1, RC-45.2)");
    }
  }

  private static boolean isBlank(RedisPassword password) {
    if (!password.isPresent()) {
      return true;
    }
    for (char c : password.get()) {
      if (!Character.isWhitespace(c)) {
        return false;
      }
    }
    return true;
  }
}
