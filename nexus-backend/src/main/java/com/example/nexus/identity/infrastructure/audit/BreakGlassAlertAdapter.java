package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;
import org.springframework.stereotype.Component;

/**
 * US-018 A7 (03-design.md §7.2): emits ERROR {@code RBAC_BREAK_GLASS_USED {tenantId,
 * targetUserId, outcome, reason, changeRef}} for every break-glass invocation; a log-based alert
 * on the marker pages Platform Security on-call. {@code null} fields are omitted.
 *
 * <p>Logs directly rather than through {@code AuditAlertPort} / {@code LoggingAuditAlertAdapter}:
 * that port's alert types describe the audit retry buffer, and its adapter increments a metric
 * this never-scraped process would never deliver. No metric is emitted here.
 */
@Component
public class BreakGlassAlertAdapter implements BreakGlassAlertPort {

  private static final Logger log = LoggerFactory.getLogger(BreakGlassAlertAdapter.class);

  @Override
  public void alert(BreakGlassAlert alert) {
    LoggingEventBuilder builder = log.atError().addKeyValue("event", "RBAC_BREAK_GLASS_USED");
    builder = addIfPresent(builder, "tenantId", alert.tenantId());
    builder = addIfPresent(builder, "targetUserId", alert.targetUserId());
    builder = addIfPresent(builder, "outcome", alert.outcome());
    builder = addIfPresent(builder, "reason", alert.reason());
    builder = addIfPresent(builder, "changeRef", alert.changeRef());
    builder.log(
        "Break-glass admin tool used: outcome={} reason={}", alert.outcome(), alert.reason());
  }

  private static LoggingEventBuilder addIfPresent(
      LoggingEventBuilder builder, String key, Object value) {
    return value == null ? builder : builder.addKeyValue(key, value);
  }
}
