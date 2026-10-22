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
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.generator.EventType;

/**
 * A tenant-scoped, named collection of permissions. No {@code @Version}: the schema defines no
 * {@code version} column, so an optimistic-lock field would fail {@code ddl-auto=validate} at
 * boot; it is also unnecessary — no in-scope path performs read-modify-write on a {@code roles}
 * row (see 03-design.md §4.6).
 *
 * <p><b>Soft delete (US-018 C1, V9).</b> {@code @SQLRestriction} makes every JPQL and entity load
 * skip a deleted role. It is defense in depth: native queries are not covered, so each read also
 * names {@code deleted_at IS NULL} itself, and the primary control is the invariant that a deleted
 * role has no active holders. {@code deleted_at} is mapped read-only: it is set only by a targeted
 * single-column {@code UPDATE}, never by a dirty flush of this entity (the {@code nexus_app} grant
 * is column-scoped to {@code name}, {@code description} and {@code deleted_at}). The generated
 * {@code active_name} column is deliberately not mapped.
 */
@Entity
@Table(name = "roles")
@SQLRestriction("deleted_at IS NULL")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Role {

  @Id
  @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID id;

  @Column(name = "tenant_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID tenantId;

  @Column(name = "name", length = 64, nullable = false)
  private String name;

  @Column(name = "description", length = 255)
  private String description;

  @Column(name = "is_system_role", nullable = false)
  private boolean systemRole;

  /**
   * DB DEFAULT CURRENT_TIMESTAMP(6); never written by this entity. {@code @Generated} makes
   * Hibernate re-SELECT the DB-computed value immediately after INSERT so this entity's own
   * in-memory field reflects it without a separate re-fetch. Mirrors {@link
   * UserRole#getActiveKey()}'s identical rationale.
   */
  @Generated(event = EventType.INSERT)
  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  // DB-managed via ON UPDATE CURRENT_TIMESTAMP(6); never written by this entity (§3.2).
  @Column(name = "updated_at", insertable = false, updatable = false)
  private Instant updatedAt;

  @Column(name = "deleted_at", insertable = false, updatable = false)
  private Instant deletedAt;

  /** Creates a role; {@code created_at}/{@code updated_at} are set by the database. */
  public Role(UUID id, UUID tenantId, String name, String description, boolean systemRole) {
    this.id = id;
    this.tenantId = tenantId;
    this.name = name;
    this.description = description;
    this.systemRole = systemRole;
  }
}
