package com.example.nexus.common.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AccountLockedException}: immutability and correctness of exception
 * construction, including retry-after duration handling (edge cases: zero and negative values).
 */
class AccountLockedExceptionTest {

  /**
   * Verifies that code is correctly stored during construction.
   *
   * <p>Given: AccountLockedException constructed with error code
   * When: code() accessed
   * Then: returns the stored code
   */
  @Test
  void should_storeCode_when_constructed() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 900L);

    assertThat(ex.code()).isEqualTo("AUTH_LCK_001");
  }

  /**
   * Verifies that exception message is correctly stored during construction.
   *
   * <p>Given: AccountLockedException constructed with custom message
   * When: getMessage() called
   * Then: returns the stored message
   */
  @Test
  void should_storeMessage_when_constructed() {
    AccountLockedException ex =
        new AccountLockedException("AUTH_LCK_001", "Account locked due to too many failed attempts", 900L);

    assertThat(ex.getMessage()).isEqualTo("Account locked due to too many failed attempts");
  }

  /**
   * Verifies that retry-after duration (in seconds) is correctly stored.
   *
   * <p>Given: AccountLockedException constructed with TTL
   * When: retryAfterSeconds() called
   * Then: returns the stored duration
   */
  @Test
  void should_storeRetryAfterSeconds_when_constructed() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 900L);

    assertThat(ex.retryAfterSeconds()).isEqualTo(900L);
  }

  /**
   * Verifies that AccountLockedException is a domain exception for inheritance-based
   * exception handling.
   *
   * <p>Given: AccountLockedException instance
   * When: checked with instanceof
   * Then: is an instance of DomainException
   */
  @Test
  void should_extendDomainException() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 900L);

    assertThat(ex).isInstanceOf(DomainException.class);
  }

  /**
   * Verifies edge case: zero retry-after duration is accepted (immediate retry allowed).
   *
   * <p>Given: AccountLockedException with 0L retry-after
   * When: retryAfterSeconds() called
   * Then: returns zero (no delay)
   */
  @Test
  void should_storeZeroRetryAfterSeconds_when_constructedWithZero() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 0L);

    assertThat(ex.retryAfterSeconds()).isZero();
  }

  /**
   * Verifies edge case: negative retry-after values are accepted (clamped at handler layer).
   * Production code never produces negative values, but the exception type must not reject them
   * to avoid unexpected failures; clamping is the HTTP handler's responsibility.
   *
   * <p>Given: AccountLockedException with negative retry-after
   * When: retryAfterSeconds() called
   * Then: returns the negative value as-is (handler will clamp)
   */
  @Test
  void should_storeNegativeRetryAfterSeconds_when_constructedWithNegative() {
    // Negative values are not produced by production code but the type must not reject them;
    // the handler clamps via Math.max(0, ...) at the call site.
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", -1L);

    assertThat(ex.retryAfterSeconds()).isEqualTo(-1L);
  }
}
