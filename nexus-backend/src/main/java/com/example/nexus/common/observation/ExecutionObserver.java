package com.example.nexus.common.observation;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Reusable component to observe, time, log, and record metrics for logical executions
 * (such as external integrations, events, and scheduled jobs) in a standardized way.
 */
@Component
public class ExecutionObserver {

  private static final Logger log = LoggerFactory.getLogger(ExecutionObserver.class);

  private final MeterRegistry meterRegistry;

  /**
   * Constructs the observer with an optional MeterRegistry.
   */
  public ExecutionObserver(@Autowired(required = false) MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;
  }

  /**
   * Wraps the execution of a task, timing it, recording metrics, and logging the outcome.
   *
   * @param event                the event category (e.g. "integration_call", "event_processing")
   * @param executionType        the execution runtime environment (e.g. "http", "async", "schedule")
   * @param operation            the specific logical action (e.g. "sendVerificationEmail")
   * @param logSuccessAtInfo     if true, log success at INFO level; if false, log at DEBUG
   * @param terminalBoundary     if true, this is the final execution boundary and unexpected
   *                             exceptions will be logged with full stack traces. If false,
   *                             exceptions are logged as single-line failures and rethrown.
   * @param supplier             the task to execute
   * @param <T>                  the return type of the task
   * @return the result of the task
   */
  public <T> T observe(
      String event,
      String executionType,
      String operation,
      boolean logSuccessAtInfo,
      boolean terminalBoundary,
      Supplier<T> supplier) {
    long startTime = System.nanoTime();
    boolean correlationIdAdded = false;
    String currentCorrelationId = MDC.get("correlationId");

    // Initialize correlationId if missing (e.g. in background jobs)
    if (currentCorrelationId == null) {
      currentCorrelationId = UUID.randomUUID().toString();
      MDC.put("correlationId", currentCorrelationId);
      MDC.put("traceId", currentCorrelationId); // Deprecated alias
      correlationIdAdded = true;
    }

    try {
      T result = supplier.get();
      long durationMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
          System.nanoTime() - startTime);

      if (logSuccessAtInfo) {
        log.atInfo()
            .addKeyValue("event", event)
            .addKeyValue("executionType", executionType)
            .addKeyValue("operation", operation)
            .addKeyValue("correlationId", currentCorrelationId)
            .addKeyValue("durationMs", durationMs)
            .addKeyValue("outcome", "SUCCESS")
            .log("Execution completed: event={} operation={} durationMs={} outcome=SUCCESS",
                event, operation, durationMs);
      } else {
        log.atDebug()
            .addKeyValue("event", event)
            .addKeyValue("executionType", executionType)
            .addKeyValue("operation", operation)
            .addKeyValue("correlationId", currentCorrelationId)
            .addKeyValue("durationMs", durationMs)
            .addKeyValue("outcome", "SUCCESS")
            .log("Execution completed: event={} operation={} durationMs={} outcome=SUCCESS",
                event, operation, durationMs);
      }

      recordMetric(event, operation, "SUCCESS", durationMs);
      return result;
    } catch (Exception e) {
      long durationMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
          System.nanoTime() - startTime);

      String errorType = e.getClass().getSimpleName();

      if (terminalBoundary) {
        // At the terminal boundary, we must log the full stack trace to ensure diagnostic
        // details are not lost.
        log.atError()
            .addKeyValue("event", event)
            .addKeyValue("executionType", executionType)
            .addKeyValue("operation", operation)
            .addKeyValue("correlationId", currentCorrelationId)
            .addKeyValue("durationMs", durationMs)
            .addKeyValue("outcome", "FAILURE")
            .addKeyValue("errorCode", "INTERNAL_ERROR")
            .log("Execution failed at terminal boundary: event=" + event + " operation="
                + operation + " durationMs=" + durationMs + " outcome=FAILURE errorType="
                + errorType, e);
      } else {
        // Not a terminal boundary: log a single-line failure without stack trace and rethrow.
        log.atWarn()
            .addKeyValue("event", event)
            .addKeyValue("executionType", executionType)
            .addKeyValue("operation", operation)
            .addKeyValue("correlationId", currentCorrelationId)
            .addKeyValue("durationMs", durationMs)
            .addKeyValue("outcome", "FAILURE")
            .addKeyValue("errorCode", "INTERNAL_ERROR")
            .log("Execution failed: event={} operation={} durationMs={} outcome=FAILURE errorType={}",
                event, operation, durationMs, errorType);
      }

      recordMetric(event, operation, "FAILURE", durationMs);
      throw e;
    } finally {
      if (correlationIdAdded) {
        MDC.remove("correlationId");
        MDC.remove("traceId");
      }
    }
  }

  /**
   * Wraps the execution of a runnable task.
   */
  public void observe(
      String event,
      String executionType,
      String operation,
      boolean logSuccessAtInfo,
      boolean terminalBoundary,
      Runnable runnable) {
    observe(event, executionType, operation, logSuccessAtInfo, terminalBoundary, () -> {
      runnable.run();
      return null;
    });
  }

  private void recordMetric(String event, String operation, String outcome, long durationMs) {
    if (meterRegistry != null) {
      Timer.builder("nexus.execution.duration")
          .tag("event", event)
          .tag("operation", operation)
          .tag("outcome", outcome)
          .register(meterRegistry)
          .record(durationMs, java.util.concurrent.TimeUnit.MILLISECONDS);
    }
  }
}
