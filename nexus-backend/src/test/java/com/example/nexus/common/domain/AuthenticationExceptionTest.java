package com.example.nexus.common.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class AuthenticationExceptionTest {

  @Test
  void should_storeCode_when_constructed() {
    AuthenticationException ex = new AuthenticationException("AUTH_001", "Invalid email or password");

    assertThat(ex.code()).isEqualTo("AUTH_001");
  }

  @Test
  void should_storeMessage_when_constructed() {
    AuthenticationException ex = new AuthenticationException("AUTH_003", "Token invalid or expired");

    assertThat(ex.getMessage()).isEqualTo("Token invalid or expired");
  }

  @Test
  void should_extendDomainException() {
    AuthenticationException ex = new AuthenticationException("AUTH_001", "msg");

    assertThat(ex).isInstanceOf(DomainException.class);
  }
}
