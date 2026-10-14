package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * US-018 A7 (ADR-0025 6, 03-design.md §7.2): pages on every break-glass invocation with an ERROR
 * log carrying the {@code RBAC_BREAK_GLASS_USED} marker, which a log-based alert turns into a page.
 *
 * <p>Deliberately a log line and nothing else: no metric (the CLI process lives for seconds and is
 * never scraped, so a counter would never reach Prometheus) and no network call. A field whose
 * value is {@code null} is omitted from the line, so an argument-validation refusal carries
 * neither {@code targetUserId} nor {@code changeRef} (L-6, RC-54(a)). The same fields are also
 * attached as key-values for structured appenders.
 */
@Component
public class BreakGlassAlertAdapter implements BreakGlassAlertPort {

  static final String MARKER = "RBAC_BREAK_GLASS_USED";

  private static final Logger log = LoggerFactory.getLogger(BreakGlassAlertAdapter.class);

  @Override
  public void raise(BreakGlassAlert alert) {
    var builder = log.atError().addKeyValue("event", MARKER);
    StringBuilder message = new StringBuilder(MARKER);
    message.append(" outcome=").append(alert.outcome());
    builder = builder.addKeyValue("outcome", alert.outcome());
    if (alert.reason() != null) {
      message.append(" reason=").append(alert.reason());
      builder = builder.addKeyValue("reason", alert.reason());
    }
    if (alert.tenantId() != null) {
      message.append(" tenantId=").append(alert.tenantId());
      builder = builder.addKeyValue("tenantId", alert.tenantId());
    }
    if (alert.targetUserId() != null) {
      message.append(" targetUserId=").append(alert.targetUserId());
      builder = builder.addKeyValue("targetUserId", alert.targetUserId());
    }
    if (alert.changeRef() != null) {
      message.append(" changeRef=").append(alert.changeRef());
      builder = builder.addKeyValue("changeRef", alert.changeRef());
    }
    builder.log(message.toString());
  }
}
