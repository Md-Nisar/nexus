package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.identity.application.port.out.AuditAlertPort;
import com.example.nexus.identity.domain.AuditAlert;
import com.example.nexus.identity.domain.AuditAlertType;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * US-008 T-08-14 (design §4.4) — the only concrete {@link AuditAlertPort} adapter shipped by this
 * story. Logs at {@code WARN} or {@code ERROR} depending on {@link AuditAlertType} severity and
 * increments the {@code nexus.audit.alert.raised} Micrometer counter, tagged by alert type.
 *
 * <p>No concrete vendor channel (Slack, PagerDuty, etc.) is wired here — channel choice is left to
 * ops behind {@link AuditAlertPort} (threat model T-I2/Gap-2). This adapter never throws and makes
 * no synchronous network call, so it is always safe to call from the retry buffer's drain path.
 */
@Component
public class LoggingAuditAlertAdapter implements AuditAlertPort {

  private static final Logger log = LoggerFactory.getLogger(LoggingAuditAlertAdapter.class);

  private static final String METRIC_NAME = "nexus.audit.alert.raised";

  private final MeterRegistry meterRegistry;

  public LoggingAuditAlertAdapter(MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;
  }

  @Override
  public void raise(AuditAlert alert) {
    try {
      logBySeverity(alert);
    } finally {
      meterRegistry.counter(METRIC_NAME, "type", alert.type().name()).increment();
    }
  }

  /**
   * {@link AuditAlertType#BUFFER_DEPTH_WARN} logs at WARN (ticket-worthy per design §4.1); the
   * remaining three types are all page-worthy (critical depth/age thresholds, or outright data
   * loss on retry exhaustion) and log at ERROR.
   */
  private void logBySeverity(AuditAlert alert) {
    switch (alert.type()) {
      case BUFFER_DEPTH_WARN ->
          log.warn(
              "Audit alert raised [type={}, bufferDepth={}]: {}",
              alert.type(),
              alert.bufferDepth(),
              alert.message());
      case BUFFER_DEPTH_CRITICAL, BUFFER_AGE_CRITICAL, RETRY_EXHAUSTED ->
          log.error(
              "Audit alert raised [type={}, bufferDepth={}]: {}",
              alert.type(),
              alert.bufferDepth(),
              alert.message());
    }
  }
}
