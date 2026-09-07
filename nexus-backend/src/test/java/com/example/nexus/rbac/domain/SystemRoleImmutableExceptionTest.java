package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class SystemRoleImmutableExceptionTest {

  @Test
  void should_returnFixedCode_when_constructed() {
    SystemRoleImmutableException ex = new SystemRoleImmutableException();

    assertThat(ex.code()).isEqualTo("RBAC_003");
  }

  @Test
  void should_returnFixedMessage_when_constructed() {
    SystemRoleImmutableException ex = new SystemRoleImmutableException();

    assertThat(ex.getMessage()).isEqualTo("System roles cannot be modified through this API");
  }

  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    SystemRoleImmutableException first = new SystemRoleImmutableException();
    SystemRoleImmutableException second = new SystemRoleImmutableException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    SystemRoleImmutableException ex = new SystemRoleImmutableException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
