package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.infrastructure.audit.AuditRetryProperties;
import com.example.nexus.identity.infrastructure.audit.AuthEventRetryBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/**
 * JPA-backed {@link AuthEventPort}.
 *
 * <p>The primary path is a synchronous {@code save()}. On {@link DataAccessException}, the
 * failure is logged at WARN (the enum wire name + exception message only — see design §4.3/T-I1 —
 * never {@code user_agent} or any other request-derived value) and, when {@link
 * AuditRetryProperties#enabled()} is {@code true}, the event is handed to {@link
 * AuthEventRetryBuffer#enqueue(AuthEvent)} for bounded, backed-off retry (US-008 T-08-16, design
 * §4.3, ADR 0011).
 *
 * <p>When the {@code nexus.identity.audit.retry-buffer.enabled} escape hatch is {@code false},
 * this adapter does NOT enqueue at all — it reverts to the original synchronous-swallow-and-WARN
 * behavior (design §10.3). This mirrors {@link
 * com.example.nexus.identity.infrastructure.audit.SchedulingConfig}, which stops the drainer under
 * the same flag: with the flag off, nothing calls {@code enqueue()} and nothing drains it, so no
 * events silently accumulate in a buffer that will never be serviced.
 *
 * <p>Either way, {@link #record(AuthEvent)} never throws and never blocks the primary user flow —
 * a failed audit write must not roll back or delay the caller.
 */
@Component
public class JpaAuthEventAdapter implements AuthEventPort {

  private static final Logger log = LoggerFactory.getLogger(JpaAuthEventAdapter.class);

  private final JpaAuthEventRepository authEventRepository;
  private final AuthEventRetryBuffer retryBuffer;
  private final AuditRetryProperties retryProperties;

  public JpaAuthEventAdapter(
      JpaAuthEventRepository authEventRepository,
      AuthEventRetryBuffer retryBuffer,
      AuditRetryProperties retryProperties) {
    this.authEventRepository = authEventRepository;
    this.retryBuffer = retryBuffer;
    this.retryProperties = retryProperties;
  }

  @Override
  @SuppressWarnings("java:S6213")
  public void record(AuthEvent event) {
    try {
      authEventRepository.save(event);
    } catch (DataAccessException e) {
      log.warn("Failed to persist auth event [type={}]: {}",
          event.getEventType(), e.getMessage());
      if (retryProperties.enabled()) {
        retryBuffer.enqueue(event);
      }
    }
  }
}
