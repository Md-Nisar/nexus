package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import org.junit.jupiter.api.Test;

class RateLimitResultTest {

  @Test
  void should_returnAllowed_when_permitCalled() {
    RateLimitResult result = RateLimitResult.permit();

    assertThat(result.allowed()).isTrue();
    assertThat(result.retryAfterSeconds()).isZero();
  }

  @Test
  void should_returnRejected_when_rejectCalled() {
    RateLimitResult result = RateLimitResult.reject(300L);

    assertThat(result.allowed()).isFalse();
    assertThat(result.retryAfterSeconds()).isEqualTo(300L);
  }
}
