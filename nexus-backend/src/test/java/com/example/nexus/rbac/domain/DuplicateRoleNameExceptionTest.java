package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class DuplicateRoleNameExceptionTest {

  @Test
  void should_returnFixedCode_when_constructed() {
    DuplicateRoleNameException ex = new DuplicateRoleNameException();

    assertThat(ex.code()).isEqualTo("RBAC_006");
  }

  @Test
  void should_returnFixedMessage_when_constructed() {
    DuplicateRoleNameException ex = new DuplicateRoleNameException();

    assertThat(ex.getMessage()).isEqualTo("A role with this name already exists in this tenant");
  }

  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    DuplicateRoleNameException first = new DuplicateRoleNameException();
    DuplicateRoleNameException second = new DuplicateRoleNameException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    DuplicateRoleNameException ex = new DuplicateRoleNameException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
