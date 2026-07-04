package com.example.nexus.common.observation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

class ExecutionObserverTest {

  private ExecutionObserver observer;
  private MeterRegistry meterRegistry;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    observer = new ExecutionObserver(meterRegistry);
    MDC.clear();
  }

  @Test
  void shouldObserveSuccessAndRecordMetrics() {
    String result = observer.observe(
        "integration_call",
        "http",
        "testOperation",
        true,
        false,
        () -> "success-value"
    );

    assertEquals("success-value", result);
    assertNotNull(meterRegistry.find("nexus.execution.duration").timer());
    assertEquals("SUCCESS", meterRegistry.find("nexus.execution.duration").timer().getId().getTag("outcome"));
  }

  @Test
  void shouldObserveFailureAndRethrow() {
    assertThrows(RuntimeException.class, () -> {
      observer.observe(
          "integration_call",
          "http",
          "testOperation",
          true,
          false,
          () -> {
            throw new RuntimeException("Test integration error");
          }
      );
    });

    assertNotNull(meterRegistry.find("nexus.execution.duration").timer());
    assertEquals("FAILURE", meterRegistry.find("nexus.execution.duration").timer().getId().getTag("outcome"));
  }

  @Test
  void shouldObserveTerminalBoundaryFailure() {
    assertThrows(RuntimeException.class, () -> {
      observer.observe(
          "scheduled_job",
          "schedule",
          "testJob",
          true,
          true, // Terminal boundary
          () -> {
            throw new RuntimeException("Critical background error");
          }
      );
    });
  }

  @Test
  void shouldGenerateAndCleanupCorrelationIdIfMissing() {
    assertNull(MDC.get("correlationId"));

    observer.observe(
        "integration_call",
        "http",
        "testOperation",
        true,
        false,
        () -> {
          assertNotNull(MDC.get("correlationId"));
          assertEquals(MDC.get("correlationId"), MDC.get("traceId"));
          return "ok";
        }
    );

    assertNull(MDC.get("correlationId"));
    assertNull(MDC.get("traceId"));
  }
}
