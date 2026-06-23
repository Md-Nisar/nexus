package com.example.nexus.common.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AccountNotVerifiedExceptionTest {

  @Test
  void should_storeCode_when_constructed() {
    AccountNotVerifiedException ex =
        new AccountNotVerifiedException("AUTH_002", "Email not verified");

    assertThat(ex.code()).isEqualTo("AUTH_002");
  }

  @Test
  void should_storeMessage_when_constructed() {
    AccountNotVerifiedException ex =
        new AccountNotVerifiedException("AUTH_002", "Email not verified");

    assertThat(ex.getMessage()).isEqualTo("Email not verified");
  }

  @Test
  void should_extendDomainException() {
    AccountNotVerifiedException ex = new AccountNotVerifiedException("AUTH_002", "msg");

    assertThat(ex).isInstanceOf(DomainException.class);
  }
}
