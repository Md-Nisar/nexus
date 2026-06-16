package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class AuthConstantsTest {

  @Test
  void should_have7DaysRefreshTtl() {
    assertThat(AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS).isEqualTo(7);
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
  void should_throwAssertionError_when_constructorInvoked() throws Exception {
    var ctor = AuthConstants.class.getDeclaredConstructor();
    ctor.setAccessible(true);
    assertThatThrownBy(ctor::newInstance).hasCauseInstanceOf(AssertionError.class);
  }
}
