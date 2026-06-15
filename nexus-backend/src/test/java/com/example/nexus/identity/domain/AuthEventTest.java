package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthEventTest {

  @Test
  void should_setRequiredFields_when_constructorCalled() {
    UUID id = UUID.randomUUID();

    AuthEvent event = new AuthEvent(id, "LOGIN_ATTEMPT", "SUCCESS");

    assertThat(event.getId()).isEqualTo(id);
    assertThat(event.getEventType()).isEqualTo("LOGIN_ATTEMPT");
    assertThat(event.getOutcome()).isEqualTo("SUCCESS");
  }

  @Test
  void should_defaultOptionalFieldsToNull_when_constructed() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "SYSTEM_EVENT", "INFO");

    assertThat(event.getUserId()).isNull();
    assertThat(event.getTenantId()).isNull();
    assertThat(event.getIpAddress()).isNull();
    assertThat(event.getMetadata()).isNull();
    assertThat(event.getCreatedAt()).isNull();
  }
}
