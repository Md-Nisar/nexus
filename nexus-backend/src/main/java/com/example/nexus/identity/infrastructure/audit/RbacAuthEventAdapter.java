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
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Outbound audit adapter for RBAC role-assignment/revocation events (03-design.md §4.8, §6.3,
 * §6.4). Implements {@link RbacAuditPort}'s two groups (Decision 9, US-018 A6):
 *
 * <ul>
 *   <li><b>Group A (atomic)</b> — {@link #recordRoleAssigned}, {@link #recordRoleRevoked}, {@link
 *       #recordRoleCreated}, {@link #recordRolePermissionGranted}, {@link
 *       #recordRolePermissionRevoked} — delegates to {@link
 *       SecureEventService#recordEventInCurrentTransaction(AuthEvent)} ({@code MANDATORY}: joins
 *       the caller's own mutation transaction) and propagates any failure, including a metadata
 *       JSON-serialization failure.
 *   <li><b>Group B (best-effort)</b> — {@link #recordRoleAssignmentDenied} — delegates to {@link
 *       SecureEventService#recordEvent(AuthEvent)} ({@code REQUIRES_NEW}) and never throws.
 * </ul>
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
 * <p><b>US-018 A6 failure handling (design §6.2):</b> on the atomic (Group A) path, {@code
 * AuthEvent} has an assigned {@code @Id}, so {@code recordEventInCurrentTransaction} {@code
 * saveAndFlush}es, surfacing a DB-level rejection here rather than at a later, unrelated flush
 * point or at commit as an unmapped {@code TransactionSystemException}. This adapter logs the
 * failure at {@code ERROR} with a distinct {@code event=RBAC_AUDIT_WRITE_FAILED} marker, increments
 * {@code nexus.rbac.audit_write_failed{operation, mode="atomic"}}, and RETHROWS — the mutation
 * transaction must roll back, never silently lose its audit record. For {@link
 * #recordRoleAssignmentDenied} (Group B), the surrounding caller transaction is already doomed to
 * roll back, so {@code REQUIRES_NEW} is the sole reason the denial row survives (US-014 AC4); a
 * failure there logs {@code event=RBAC_AUDIT_WRITE_LOST}, increments {@code
 * nexus.rbac.audit_write_failed{operation="deny", mode="best_effort"}}, and is swallowed.
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
    recordAtomic(event, AuthEventType.ROLE_ASSIGNED, "assignedBy", "assign");
  }

  @Override
  public void recordRoleRevoked(RbacAuditEvent event) {
    recordAtomic(event, AuthEventType.ROLE_REVOKED, "revokedBy", "revoke");
  }

  /**
   * Persists {@code operation} ({@code "assign"} or {@code "revoke"}) into the denial's audit
   * metadata via {@link #buildMetadataJson(RbacAuditEvent, String, String, String, Integer)}
   * (03-design.md §4.9, D17/RC-13). <b>Deliberately excluded from the {@code
   * nexus.rbac.audit_write_failed{operation="deny"}} metric tag</b>, which keeps receiving the
   * fixed {@code "deny"} literal passed to {@link #recordDenied}'s own {@code operation} parameter
   * regardless of which verb was denied: the metric tag and this metadata field are deliberately
   * different axes — the tag identifies which of this adapter's port methods failed to write
   * (fixed at {@code "deny"} here, so no existing dashboard breaks), while the metadata field
   * identifies which caller verb produced the denial being recorded — and MUST NOT be unified or
   * confused.
   */
  @Override
  public void recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason, String operation) {
    recordRoleAssignmentDenied(event, reason, operation, null);
  }

  /**
   * US-018 A2 (03-design.md §4.4): as above, plus {@code missingCount}, the NUMBER of the target
   * role's permissions the caller lacked, written after {@code operation}. Only the count is ever
   * persisted, never the ids or names ({@code auth_events} is readable by {@code audit:read}
   * holders). A {@code null} count omits the key.
   */
  @Override
  public void recordRoleAssignmentDenied(
      RbacAuditEvent event, DenialReason reason, String operation, Integer missingCount) {
    recordDenied(
        event,
        AuthEventType.ROLE_ASSIGNMENT_DENIED,
        "attemptedBy",
        reason != null ? reason.name() : null,
        operation,
        missingCount);
  }

  /**
   * Records a successful role creation (AC12, Group A — atomic, US-018 A6, 03-design.md §6.3).
   * {@code auth_events.user_id} stays {@code NULL} — {@link RoleAuditEvent} has no {@code
   * targetUserId}; these events have no subject user by design.
   */
  @Override
  public void recordRoleCreated(RoleAuditEvent event) {
    recordAtomic(event, AuthEventType.ROLE_CREATED, "createdBy", "createRole");
  }

  /** @see #recordRoleCreated(RoleAuditEvent) */
  @Override
  public void recordRolePermissionGranted(RoleAuditEvent event) {
    recordAtomic(event, AuthEventType.ROLE_PERMISSION_GRANTED, "grantedBy", "grantPermission");
  }

  /** @see #recordRoleCreated(RoleAuditEvent) */
  @Override
  public void recordRolePermissionRevoked(RoleAuditEvent event) {
    recordAtomic(event, AuthEventType.ROLE_PERMISSION_REVOKED, "revokedBy", "revokePermission");
  }

  /**
   * The {@link RoleAuditEvent} counterpart of {@link #recordAtomic(RbacAuditEvent, AuthEventType,
   * String, String)}. All three callers are successes (03-design.md §6.2), so {@code outcome} is
   * hardcoded to {@code "SUCCESS"} rather than threaded through as an always-constant parameter.
   * {@code withUserId} is deliberately never called — {@code auth_events.user_id} stays {@code
   * NULL} for these three event types (03-design.md §6.1/§6.3).
   *
   * <p>US-018 A6 (Group A — atomic): joins the caller's mutation transaction via {@link
   * SecureEventService#recordEventInCurrentTransaction(AuthEvent)} and RETHROWS on failure
   * (including a metadata JSON-serialization failure) — no catch-all swallow — so the mutation
   * transaction rolls back rather than silently losing its audit record.
   */
  private void recordAtomic(
      RoleAuditEvent event, AuthEventType eventType, String actorFieldName, String operation) {
    try {
      String metadata = buildMetadataJson(event, actorFieldName);

      AuthEvent authEvent =
          new AuthEvent(uuidGenerator.newId(), eventType, "SUCCESS")
              .withTenantId(event.tenantId())
              .withIpAddress(event.requestContext() != null ? event.requestContext().ipAddress() : null)
              .withUserAgent(event.requestContext() != null ? event.requestContext().userAgent() : null)
              .withMetadata(metadata);

      secureEventService.recordEventInCurrentTransaction(authEvent);
    } catch (RuntimeException e) {
      logAtomicAuditWriteFailed(event.tenantId(), event.actorUserId(), event.roleId(), operation, e);
      throw e;
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

  /**
   * {@link RbacAuditEvent} counterpart of {@link #recordAtomic(RoleAuditEvent, AuthEventType,
   * String, String)} — backs {@link #recordRoleAssigned}/{@link #recordRoleRevoked} (Group A —
   * atomic, US-018 A6). Joins the caller's mutation transaction via {@link
   * SecureEventService#recordEventInCurrentTransaction(AuthEvent)} and RETHROWS on failure
   * (including a metadata JSON-serialization failure) — no catch-all swallow.
   */
  private void recordAtomic(
      RbacAuditEvent event, AuthEventType eventType, String actorFieldName, String operation) {
    try {
      String metadata = buildMetadataJson(event, actorFieldName, null, null, null);

      AuthEvent authEvent =
          new AuthEvent(uuidGenerator.newId(), eventType, "SUCCESS")
              .withUserId(event.targetUserId()) // the subject, matching the LOCKOUT convention
              .withTenantId(event.tenantId())
              .withIpAddress(event.requestContext() != null ? event.requestContext().ipAddress() : null)
              .withUserAgent(event.requestContext() != null ? event.requestContext().userAgent() : null)
              .withMetadata(metadata);

      secureEventService.recordEventInCurrentTransaction(authEvent);
    } catch (RuntimeException e) {
      logAtomicAuditWriteFailed(event.tenantId(), event.actorUserId(), event.roleId(), operation, e);
      throw e;
    }
  }

  /**
   * Backs {@link #recordRoleAssignmentDenied} (Group B — best-effort, US-014 AC4). Delegates to
   * {@link SecureEventService#recordEvent(AuthEvent)} ({@code REQUIRES_NEW}) and MUST NEVER throw
   * — on failure it logs {@code event=RBAC_AUDIT_WRITE_LOST}, increments {@code
   * nexus.rbac.audit_write_failed{operation="deny", mode="best_effort"}}, and swallows.
   */
  @SuppressWarnings("java:S6213")
  private void recordDenied(
      RbacAuditEvent event,
      AuthEventType eventType,
      String actorFieldName,
      String reasonName,
      String deniedOperation,
      Integer missingCount) {
    try {
      // Metadata JSON is built and serialised BEFORE any transaction/port call (T-R3 mitigation
      // #3): a JsonProcessingException is caught here, before SecureEventService's REQUIRES_NEW
      // transaction ever opens.
      String metadata = buildMetadataJson(event, actorFieldName, reasonName, deniedOperation, missingCount);

      AuthEvent authEvent =
          new AuthEvent(uuidGenerator.newId(), eventType, "DENIED")
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
          .log("RBAC audit write lost: operation=deny tenantId={} targetUserId={} roleId={}",
              event.tenantId(), event.targetUserId(), event.roleId(), e);
      Counter.builder("nexus.rbac.audit_write_failed")
          .tag("operation", "deny")
          .tag("mode", "best_effort")
          .register(meterRegistry)
          .increment();
    }
  }

  /**
   * US-018 A6 (design §6.2): the Group A (atomic) failure marker, shared by both {@code
   * recordAtomic} overloads. Distinct from Group B's {@code RBAC_AUDIT_WRITE_LOST} — the mutation
   * this accompanies is about to roll back, not silently lose its audit record.
   */
  private void logAtomicAuditWriteFailed(
      UUID tenantId, UUID actorUserId, UUID roleId, String operation, Exception e) {
    log.atError()
        .addKeyValue("event", "RBAC_AUDIT_WRITE_FAILED")
        .addKeyValue("tenantId", tenantId)
        .addKeyValue("roleId", roleId)
        .addKeyValue("actorUserId", actorUserId)
        .addKeyValue("operation", operation)
        .log("RBAC audit write failed: operation={} tenantId={} roleId={}",
            operation, tenantId, roleId, e);
    Counter.builder("nexus.rbac.audit_write_failed")
        .tag("operation", operation)
        .tag("mode", "atomic")
        .register(meterRegistry)
        .increment();
  }

  /**
   * Builds the ordered metadata map and serialises it to JSON. Keys are omitted entirely when
   * their value is {@code null} — never emitted as a JSON {@code null} (03-design.md §6.3). Key
   * order: {@code traceId}, {@code roleId}, {@code roleName}, {@code reason}, {@code operation}
   * (D17), {@code missingCount} (US-018 A2, grant-subset denials only), {@code <actorFieldName>}.
   */
  private String buildMetadataJson(
      RbacAuditEvent event,
      String actorFieldName,
      String reasonName,
      String operation,
      Integer missingCount) {
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
    if (missingCount != null) {
      metadata.put("missingCount", missingCount);
    }
    if (event.actorUserId() != null) {
      metadata.put(actorFieldName, event.actorUserId().toString());
    }
    return objectMapper.writeValueAsString(metadata);
  }
}
