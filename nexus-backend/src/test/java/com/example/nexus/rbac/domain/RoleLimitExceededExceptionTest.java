package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleLimitExceededExceptionTest {

  @Test
  void should_returnFixedCode_when_constructed() {
    RoleLimitExceededException ex = new RoleLimitExceededException();

    assertThat(ex.code()).isEqualTo("RBAC_008");
  }

  @Test
  void should_returnFixedMessage_when_constructed() {
    RoleLimitExceededException ex = new RoleLimitExceededException();

    assertThat(ex.getMessage()).isEqualTo("This tenant has reached its role limit");
  }

  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    RoleLimitExceededException first = new RoleLimitExceededException();
    RoleLimitExceededException second = new RoleLimitExceededException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    RoleLimitExceededException ex = new RoleLimitExceededException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
