package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.identity.application.port.out.DirectoryReadAuditPort;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.domain.UuidGenerator;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Writes the {@code USER_DIRECTORY_READ} row of a directory read (US-019 design §4.5) through the
 * best-effort path, {@link SecureEventService#recordEvent(AuthEvent)} ({@code REQUIRES_NEW}),
 * because the read transaction is read-only.
 *
 * <p>A failure, including a serialisation failure, never reaches the read: it is logged as {@code
 * IDENTITY_DIRECTORY_AUDIT_WRITE_FAILED} (ids only, never the exception text, which may echo
 * values) and counted in {@code nexus.identity.directory.audit_write_failed}.
 */
@Component
public class DirectoryReadAuthEventAdapter implements DirectoryReadAuditPort {

  private static final Logger log = LoggerFactory.getLogger(DirectoryReadAuthEventAdapter.class);
  private static final String COUNTER_AUDIT_WRITE_FAILED =
      "nexus.identity.directory.audit_write_failed";

  private final SecureEventService secureEventService;
  private final UuidGenerator uuidGenerator;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public DirectoryReadAuthEventAdapter(
      SecureEventService secureEventService,
      UuidGenerator uuidGenerator,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry) {
    this.secureEventService = secureEventService;
    this.uuidGenerator = uuidGenerator;
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
  }

  @Override
  public void recordDirectoryRead(UUID tenantId, UUID actorUserId, Map<String, Object> metadata) {
    try {
      AuthEvent event =
          new AuthEvent(uuidGenerator.newId(), AuthEventType.USER_DIRECTORY_READ, "SUCCESS")
              .withUserId(actorUserId)
              .withTenantId(tenantId)
              .withMetadata(objectMapper.writeValueAsString(metadata));
      secureEventService.recordEvent(event);
    } catch (RuntimeException e) {
      log.atWarn()
          .addKeyValue("event", "IDENTITY_DIRECTORY_AUDIT_WRITE_FAILED")
          .addKeyValue("tenantId", tenantId)
          .addKeyValue("actorUserId", actorUserId)
          .addKeyValue("errorType", e.getClass().getSimpleName())
          .log("Could not write the directory read audit row");
      meterRegistry.counter(COUNTER_AUDIT_WRITE_FAILED).increment();
    }
  }
}
