package com.example.nexus.common.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AccountLockedExceptionTest {

  @Test
  void should_storeCode_when_constructed() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 900L);

    assertThat(ex.code()).isEqualTo("AUTH_LCK_001");
  }

  @Test
  void should_storeMessage_when_constructed() {
    AccountLockedException ex =
        new AccountLockedException("AUTH_LCK_001", "Account locked due to too many failed attempts", 900L);

    assertThat(ex.getMessage()).isEqualTo("Account locked due to too many failed attempts");
  }

  @Test
  void should_storeRetryAfterSeconds_when_constructed() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 900L);

    assertThat(ex.retryAfterSeconds()).isEqualTo(900L);
  }

  @Test
  void should_extendDomainException() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 900L);

    assertThat(ex).isInstanceOf(DomainException.class);
  }

  @Test
  void should_storeZeroRetryAfterSeconds_when_constructedWithZero() {
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", 0L);

    assertThat(ex.retryAfterSeconds()).isZero();
  }

  @Test
  void should_storeNegativeRetryAfterSeconds_when_constructedWithNegative() {
    // Negative values are not produced by production code but the type must not reject them;
    // the handler clamps via Math.max(0, ...) at the call site.
    AccountLockedException ex = new AccountLockedException("AUTH_LCK_001", "Account locked", -1L);

    assertThat(ex.retryAfterSeconds()).isEqualTo(-1L);
  }
}
