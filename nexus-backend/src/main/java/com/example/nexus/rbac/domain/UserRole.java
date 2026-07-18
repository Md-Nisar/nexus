package com.example.nexus.rbac.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Generated;
import org.hibernate.generator.EventType;

/**
 * A (soft-deletable) grant of a {@link Role} to a user. Hard delete is blocked by a DB trigger;
 * {@code revoked_at} (via {@code UPDATE}) is the only permitted mutation path. No {@code @Version}
 * — same rationale as {@link Role} (03-design.md §4.6).
 */
@Entity
@Table(name = "user_roles")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserRole {

  @Id
  @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID id;

  @Column(name = "user_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID userId;

  @Column(name = "role_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID roleId;

  @Column(name = "tenant_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID tenantId;

  @Column(name = "assigned_by", columnDefinition = "BINARY(16)", nullable = false)
  private UUID assignedBy;

  // DB DEFAULT CURRENT_TIMESTAMP(6); never written by this entity.
  @Column(name = "assigned_at", insertable = false, updatable = false)
  private Instant assignedAt;

  // The one permitted mutation path (soft-delete); set via a targeted UPDATE, never
  // load-mutate-save.
  @Column(name = "revoked_at")
  private Instant revokedAt;

  /**
   * DB-computed generated column: {@code CONCAT(user_id, role_id)} while {@code revoked_at} is
   * null, else {@code null}. Backs {@code uq_user_role_active} (ADR-0013 D2). Mapped as
   * {@code byte[]} (NOT {@code UUID}): it is 32 bytes, and {@code UuidV7Converter} is UUID-typed
   * only, so it correctly leaves a {@code byte[]} field untouched. {@code insertable=false,
   * updatable=false} is mandatory (a client must never be able to supply this value directly —
   * T-T3); {@code @Generated} makes Hibernate re-SELECT the DB-computed value after INSERT/UPDATE
   * so the in-memory field reflects it without a separate re-fetch.
   */
  @Generated(event = {EventType.INSERT, EventType.UPDATE})
  @Column(
      name = "active_key",
      columnDefinition = "BINARY(32)",
      insertable = false,
      updatable = false)
  private byte[] activeKey;

  /**
   * Creates an active assignment; {@code assigned_at} and {@code active_key} are set by the
   * database.
   */
  public UserRole(UUID id, UUID userId, UUID roleId, UUID tenantId, UUID assignedBy) {
    this.id = id;
    this.userId = userId;
    this.roleId = roleId;
    this.tenantId = tenantId;
    this.assignedBy = assignedBy;
  }
}
