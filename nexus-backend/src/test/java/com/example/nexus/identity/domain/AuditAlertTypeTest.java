package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuditAlertTypeTest {

  @Test
  void should_containAllExpectedValues_when_valuesListed() {
    assertThat(AuditAlertType.values())
        .containsExactly(
            AuditAlertType.BUFFER_DEPTH_WARN,
            AuditAlertType.BUFFER_DEPTH_CRITICAL,
            AuditAlertType.BUFFER_AGE_CRITICAL,
            AuditAlertType.RETRY_EXHAUSTED);
  }
}
