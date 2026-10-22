package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleHasHoldersExceptionTest {

  @Test
  void should_returnFixedCode_when_constructed() {
    assertThat(new RoleHasHoldersException().code()).isEqualTo("RBAC_009");
  }

  @Test
  void should_returnFixedMessageNamingNoHolder_when_constructed() {
    assertThat(new RoleHasHoldersException().getMessage())
        .isEqualTo("This role still has active holders; revoke them first");
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    assertThat(new RoleHasHoldersException()).isInstanceOf(ConflictException.class);
  }
}
