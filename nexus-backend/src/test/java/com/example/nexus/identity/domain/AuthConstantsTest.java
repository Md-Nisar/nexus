package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class AuthConstantsTest {

  @Test
  void should_have14DaysRefreshTtl() {
    assertThat(AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS).isEqualTo(14);
  }

  @Test
  void should_have900SecondsAccessTokenTtl() {
    assertThat(AuthConstants.AUTH_ACCESS_TOKEN_TTL_SECONDS).isEqualTo(900);
  }

  @Test
  void should_have24HoursVerificationTtl() {
    assertThat(AuthConstants.AUTH_VERIFICATION_TOKEN_TTL).isEqualTo(Duration.ofHours(24));
  }

  @Test
  void should_have60MinutesResetTtl() {
    assertThat(AuthConstants.AUTH_RESET_TOKEN_TTL).isEqualTo(Duration.ofMinutes(60));
  }

  @Test
  void should_have5AsLockoutThreshold() {
    assertThat(AuthConstants.LOCKOUT_THRESHOLD).isEqualTo(5);
  }

  @Test
  void should_have900SecondsLockoutWindow() {
    assertThat(AuthConstants.LOCKOUT_WINDOW_SECONDS).isEqualTo(900);
  }

  @Test
  void should_have900SecondsLockoutDuration() {
    assertThat(AuthConstants.LOCKOUT_DURATION_SECONDS).isEqualTo(900);
  }

  @Test
  void should_throwAssertionError_when_constructorInvoked() throws Exception {
    var ctor = AuthConstants.class.getDeclaredConstructor();
    ctor.setAccessible(true);
    assertThatThrownBy(ctor::newInstance).hasCauseInstanceOf(AssertionError.class);
  }
}
