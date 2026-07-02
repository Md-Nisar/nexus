package com.example.nexus.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuditAlertTest {

  @Test
  void should_exposeAllComponents_when_constructed() {
    Instant occurredAt = Instant.parse("2026-07-01T00:00:00Z");

    AuditAlert alert =
        new AuditAlert(AuditAlertType.BUFFER_DEPTH_CRITICAL, "standard lane at 90%", occurredAt,
            720);

    assertThat(alert.type()).isEqualTo(AuditAlertType.BUFFER_DEPTH_CRITICAL);
    assertThat(alert.message()).isEqualTo("standard lane at 90%");
    assertThat(alert.occurredAt()).isEqualTo(occurredAt);
    assertThat(alert.bufferDepth()).isEqualTo(720);
  }

  @Test
  void should_produceEqualRecords_when_sameComponentsGiven() {
    Instant occurredAt = Instant.parse("2026-07-01T00:00:00Z");
    AuditAlert first = new AuditAlert(AuditAlertType.RETRY_EXHAUSTED, "dropped", occurredAt, 5);
    AuditAlert second = new AuditAlert(AuditAlertType.RETRY_EXHAUSTED, "dropped", occurredAt, 5);

    assertThat(first).isEqualTo(second);
    assertThat(first.hashCode()).isEqualTo(second.hashCode());
  }

  @Test
  void should_produceUnequalRecords_when_bufferDepthDiffers() {
    Instant occurredAt = Instant.parse("2026-07-01T00:00:00Z");
    AuditAlert first = new AuditAlert(AuditAlertType.RETRY_EXHAUSTED, "dropped", occurredAt, 5);
    AuditAlert second = new AuditAlert(AuditAlertType.RETRY_EXHAUSTED, "dropped", occurredAt, 6);

    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void should_includeTypeAndBufferDepth_when_toStringCalled() {
    Instant occurredAt = Instant.parse("2026-07-01T00:00:00Z");

    AuditAlert alert =
        new AuditAlert(AuditAlertType.BUFFER_AGE_CRITICAL, "oldest event too old", occurredAt,
            42);

    String text = alert.toString();

    assertThat(text).contains("BUFFER_AGE_CRITICAL").contains("42");
  }
}
