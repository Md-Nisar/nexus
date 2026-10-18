package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.common.domain.ConflictException;
import com.example.nexus.common.domain.DomainException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class AttachProvenanceConflictExceptionTest {

  @Test
  void should_returnRbac010_when_constructed() {
    assertThat(new AttachProvenanceConflictException().code()).isEqualTo("RBAC_010");
  }

  @Test
  void should_extendConflictException_when_checkedForType() {
    assertThat(new AttachProvenanceConflictException())
        .isInstanceOf(ConflictException.class)
        .isInstanceOf(DomainException.class);
  }

  @Test
  void should_returnSameFixedMessage_when_constructedRepeatedly() {
    assertThat(new AttachProvenanceConflictException().getMessage())
        .isEqualTo(new AttachProvenanceConflictException().getMessage());
  }

  @Test
  void should_nameNoHolderOrIdentifier_when_messageRead() {
    assertThat(new AttachProvenanceConflictException().getMessage())
        .doesNotContainPattern("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}")
        .doesNotContainPattern("\\d");
  }
}
