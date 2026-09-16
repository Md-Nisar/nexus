package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.common.security.DenialReason;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.RbacAuditEvent;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleAuditEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Outbound audit adapter for RBAC role-assignment/revocation events (03-design.md §4.8, §6.3,
 * §6.4). Delegates to {@link SecureEventService#recordEvent(AuthEvent)} ({@code REQUIRES_NEW}) so
 * {@code rbac} gets the existing retry-buffer / append-only audit infrastructure for free without
 * importing {@code identity}.
 *
 * <p>Sits beside {@link AuthEventRetryBuffer} / {@link LoggingAuditAlertAdapter} /
 * {@link AuthEventDbPrivilegeHealthIndicator}.
 *
 * <p><b>ObjectMapper type note (T-E13):</b> the injected {@link ObjectMapper} is {@code
 * tools.jackson.databind.ObjectMapper} — Jackson <b>3</b>, the Spring Boot 4.1 auto-configured
 * bean — never {@code com.fasterxml.jackson.databind.ObjectMapper} (Jackson 2, used only by
 * {@code LoginRateLimitFilter}'s self-instantiated, unrelated {@code new ObjectMapper()}, which is
 * NOT the pattern to copy here) and never hand-instantiated. Injecting the wrong Jackson major
 * either fails context startup or puts the T-T5 security-critical escaping on an unmanaged,
 * unconfigured object.
 *
 * <p><b>T-R3 audit-write-loss handling (mandatory, not optional):</b> {@code AuthEvent} has an
 * assigned {@code @Id}, so the actual {@code INSERT} (and any DB-level rejection) happens at
 * {@code REQUIRES_NEW} <i>commit</i> time, inside {@code SecureEventService}'s proxy — after
 * {@code recordEvent} has already returned. {@code JpaAuthEventAdapter}'s own retry-buffer catch
 * never fires for this failure mode. This adapter's catch-all therefore logs at {@code ERROR}
 * (not WARN) with a distinct {@code event=RBAC_AUDIT_WRITE_LOST} marker and increments {@code
 * nexus.rbac.audit_write_failed{operation}} — without this, a committed role change can lose its
 * audit record with zero operational signal. For {@link #recordRoleAssignmentDenied}, the
 * surrounding caller transaction is already doomed to roll back, so {@code REQUIRES_NEW} here is
 * not merely a durability nicety but the sole reason the denial row survives (US-014 AC4).
 */
@Component
public class RbacAuthEventAdapter implements RbacAuditPort {

  private static final Logger log = LoggerFactory.getLogger(RbacAuthEventAdapter.class);

  private final SecureEventService secureEventService;
  private final UuidGenerator uuidGenerator;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public RbacAuthEventAdapter(
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
  public void recordRoleAssigned(RbacAuditEvent event) {
    record(event, AuthEventType.ROLE_ASSIGNED, "SUCCESS", "assignedBy", "assign", null, null);
  }

  @Override
  public void recordRoleRevoked(RbacAuditEvent event) {
    record(event, AuthEventType.ROLE_REVOKED, "SUCCESS", "revokedBy", "revoke", null, null);
  }

  /**
   * Persists {@code operation} ({@code "assign"} or {@code "revoke"}) into the denial's audit
   * metadata via {@link #buildMetadataJson(RbacAuditEvent, String, String, String)} (03-design.md
   * §4.9, D17/RC-13). <b>Deliberately excluded from the {@code
   * nexus.rbac.audit_write_failed{operation="deny"}} metric tag</b>, which keeps receiving the
   * fixed {@code "deny"} literal passed to {@link #record(RbacAuditEvent, AuthEventType, String,
   * String, String, String, String)}'s own {@code operation} parameter regardless of which verb
   * was denied: the metric tag and this metadata field are deliberately different axes — the tag
   * identifies which of this adapter's port methods failed to write (fixed at {@code "deny"} here,
   * so no existing dashboard breaks), while the metadata field identifies which caller verb
   * produced the denial being recorded — and MUST NOT be unified or confused.
   */
  @Override
  public void recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason, String operation) {
    record(
        event,
        AuthEventType.ROLE_ASSIGNMENT_DENIED,
        "DENIED",
        "attemptedBy",
        "deny",
        reason != null ? reason.name() : null,
        operation);
  }

  /**
   * Records a successful role creation (AC12, 03-design.md §6.3). {@code auth_events.user_id}
   * stays {@code NULL} — {@link RoleAuditEvent} has no {@code targetUserId}; these events have no
   * subject user by design.
   */
  @Override
  public void recordRoleCreated(RoleAuditEvent event) {
    record(event, AuthEventType.ROLE_CREATED, "createdBy", "createRole");
  }

  /** @see #recordRoleCreated(RoleAuditEvent) */
  @Override
  public void recordRolePermissionGranted(RoleAuditEvent event) {
    record(event, AuthEventType.ROLE_PERMISSION_GRANTED, "grantedBy", "grantPermission");
  }

  /** @see #recordRoleCreated(RoleAuditEvent) */
  @Override
  public void recordRolePermissionRevoked(RoleAuditEvent event) {
    record(event, AuthEventType.ROLE_PERMISSION_REVOKED, "revokedBy", "revokePermission");
  }

  /**
   * The {@link RoleAuditEvent} counterpart of {@link #record(RbacAuditEvent, AuthEventType,
   * String, String, String, String)}. All three callers are post-commit successes (03-design.md
   * §6.2), so {@code outcome} is hardcoded to {@code "SUCCESS"} rather than threaded through as an
   * always-constant parameter. {@code withUserId} is deliberately never called — {@code
   * auth_events.user_id} stays {@code NULL} for these three event types (03-design.md §6.1/§6.3).
   */
  private void record(
      RoleAuditEvent event, AuthEventType eventType, String actorFieldName, String operation) {
    try {
      // Metadata JSON is built and serialised BEFORE any transaction/port call (T-R3 mitigation
      // #3): a JsonProcessingException is caught here, before SecureEventService's REQUIRES_NEW
      // transaction ever opens.
      String metadata = buildMetadataJson(event, actorFieldName);

      AuthEvent authEvent =
          new AuthEvent(uuidGenerator.newId(), eventType, "SUCCESS")
              .withTenantId(event.tenantId())
              .withIpAddress(event.requestContext() != null ? event.requestContext().ipAddress() : null)
              .withUserAgent(event.requestContext() != null ? event.requestContext().userAgent() : null)
              .withMetadata(metadata);

      secureEventService.recordEvent(authEvent);
    } catch (Exception e) {
      String traceId = event.requestContext() != null ? event.requestContext().traceId() : null;
      log.atError()
          .addKeyValue("event", "RBAC_AUDIT_WRITE_LOST")
          .addKeyValue("tenantId", event.tenantId())
          .addKeyValue("roleId", event.roleId())
          .addKeyValue("actorUserId", event.actorUserId())
          .addKeyValue("traceId", traceId)
          .log("RBAC audit write lost: operation={} tenantId={} roleId={}",
              operation, event.tenantId(), event.roleId(), e);
      Counter.builder("nexus.rbac.audit_write_failed")
          .tag("operation", operation)
          .register(meterRegistry)
          .increment();
    }
  }

  /**
   * Builds the ordered metadata map for a {@link RoleAuditEvent} and serialises it to JSON. Keys
   * are omitted entirely when their value is {@code null} — never emitted as a JSON {@code null}
   * (03-design.md §6.3). Key order: {@code traceId}, {@code roleId}, {@code roleName}, {@code
   * permissionId}, {@code permissionName}, {@code holderCount} (D13, dangerous-attach only),
   * {@code <actorFieldName>}.
   */
  private String buildMetadataJson(RoleAuditEvent event, String actorFieldName) {
    Map<String, Object> metadata = new LinkedHashMap<>();
    String traceId = event.requestContext() != null ? event.requestContext().traceId() : null;
    if (traceId != null) {
      metadata.put("traceId", traceId);
    }
    if (event.roleId() != null) {
      metadata.put("roleId", event.roleId().toString());
    }
    if (event.roleName() != null) {
      metadata.put("roleName", event.roleName());
    }
    if (event.permissionId() != null) {
      metadata.put("permissionId", event.permissionId().toString());
    }
    if (event.permissionName() != null) {
      metadata.put("permissionName", event.permissionName());
    }
    if (event.holderCount() != null) {
      metadata.put("holderCount", event.holderCount());
    }
    if (event.actorUserId() != null) {
      metadata.put(actorFieldName, event.actorUserId().toString());
    }
    return objectMapper.writeValueAsString(metadata);
  }

  @SuppressWarnings("java:S6213")
  private void record(
      RbacAuditEvent event,
      AuthEventType eventType,
      String outcome,
      String actorFieldName,
      String operation,
      String reasonName,
      String deniedOperation) {
    try {
      // Metadata JSON is built and serialised BEFORE any transaction/port call (T-R3 mitigation
      // #3): a JsonProcessingException is caught here, before SecureEventService's REQUIRES_NEW
      // transaction ever opens.
      String metadata = buildMetadataJson(event, actorFieldName, reasonName, deniedOperation);

      AuthEvent authEvent =
          new AuthEvent(uuidGenerator.newId(), eventType, outcome)
              .withUserId(event.targetUserId()) // the subject, matching the LOCKOUT convention
              .withTenantId(event.tenantId())
              .withIpAddress(event.requestContext() != null ? event.requestContext().ipAddress() : null)
              .withUserAgent(event.requestContext() != null ? event.requestContext().userAgent() : null)
              .withMetadata(metadata);

      secureEventService.recordEvent(authEvent);
    } catch (Exception e) {
      String traceId = event.requestContext() != null ? event.requestContext().traceId() : null;
      log.atError()
          .addKeyValue("event", "RBAC_AUDIT_WRITE_LOST")
          .addKeyValue("tenantId", event.tenantId())
          .addKeyValue("targetUserId", event.targetUserId())
          .addKeyValue("roleId", event.roleId())
          .addKeyValue("actorUserId", event.actorUserId())
          .addKeyValue("traceId", traceId)
          .log("RBAC audit write lost: operation={} tenantId={} targetUserId={} roleId={}",
              operation, event.tenantId(), event.targetUserId(), event.roleId(), e);
      Counter.builder("nexus.rbac.audit_write_failed")
          .tag("operation", operation)
          .register(meterRegistry)
          .increment();
    }
  }

  /**
   * Builds the ordered metadata map and serialises it to JSON. Keys are omitted entirely when
   * their value is {@code null} — never emitted as a JSON {@code null} (03-design.md §6.3). Key
   * order: {@code traceId}, {@code roleId}, {@code roleName}, {@code reason}, {@code operation}
   * (D17), {@code <actorFieldName>}.
   */
  private String buildMetadataJson(
      RbacAuditEvent event, String actorFieldName, String reasonName, String operation) {
    Map<String, Object> metadata = new LinkedHashMap<>();
    String traceId = event.requestContext() != null ? event.requestContext().traceId() : null;
    if (traceId != null) {
      metadata.put("traceId", traceId);
    }
    if (event.roleId() != null) {
      metadata.put("roleId", event.roleId().toString());
    }
    if (event.roleName() != null) {
      metadata.put("roleName", event.roleName());
    }
    if (reasonName != null) {
      metadata.put("reason", reasonName);
    }
    if (operation != null) {
      metadata.put("operation", operation);
    }
    if (event.actorUserId() != null) {
      metadata.put(actorFieldName, event.actorUserId().toString());
    }
    return objectMapper.writeValueAsString(metadata);
  }
}
