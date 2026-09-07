package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class DuplicateRolePermissionExceptionTest {

  @Test
  void should_returnFixedCode_when_constructed() {
    DuplicateRolePermissionException ex = new DuplicateRolePermissionException();

    assertThat(ex.code()).isEqualTo("RBAC_005");
  }

  @Test
  void should_returnFixedMessage_when_constructed() {
    DuplicateRolePermissionException ex = new DuplicateRolePermissionException();

    assertThat(ex.getMessage()).isEqualTo("This permission is already attached to this role");
  }

  @Test
  void should_returnSameCodeAndMessage_when_constructedRepeatedly() {
    DuplicateRolePermissionException first = new DuplicateRolePermissionException();
    DuplicateRolePermissionException second = new DuplicateRolePermissionException();

    assertThat(first.code()).isEqualTo(second.code());
    assertThat(first.getMessage()).isEqualTo(second.getMessage());
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    DuplicateRolePermissionException ex = new DuplicateRolePermissionException();

    assertThat(ex).isInstanceOf(ConflictException.class).isInstanceOf(DomainException.class);
  }
}
