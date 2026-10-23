package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleClassificationChangedExceptionTest {

  @Test
  void should_returnRbac012_when_constructed() {
    assertThat(new RoleClassificationChangedException().code()).isEqualTo("RBAC_012");
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    assertThat(new RoleClassificationChangedException()).isInstanceOf(ConflictException.class);
  }

  @Test
  void should_askForARetryWithTheDesignedDetail_when_messageRead() {
    assertThat(new RoleClassificationChangedException().getMessage())
        .isEqualTo("The role changed while your request was waiting. Try again.");
  }

  @Test
  void should_nameNoIdentifier_when_messageRead() {
    assertThat(new RoleClassificationChangedException().getMessage())
        .doesNotContainPattern("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}")
        .doesNotContainPattern("\\d");
  }
}
