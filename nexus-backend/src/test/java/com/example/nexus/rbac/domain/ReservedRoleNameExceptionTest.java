package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class ReservedRoleNameExceptionTest {

  @Test
  void should_returnFixedCode_when_constructed() {
    ReservedRoleNameException ex = new ReservedRoleNameException();

    assertThat(ex.code()).isEqualTo("RBAC_007");
  }

  @Test
  void should_returnFixedMessage_when_constructed() {
    ReservedRoleNameException ex = new ReservedRoleNameException();

    assertThat(ex.getMessage()).isEqualTo("This name is reserved for a system role");
  }

  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    ReservedRoleNameException first = new ReservedRoleNameException();
    ReservedRoleNameException second = new ReservedRoleNameException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    ReservedRoleNameException ex = new ReservedRoleNameException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
