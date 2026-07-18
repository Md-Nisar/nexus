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

/**
 * A tenant-scoped, named collection of permissions. No {@code @Version}: the schema defines no
 * {@code version} column, so an optimistic-lock field would fail {@code ddl-auto=validate} at
 * boot; it is also unnecessary — no in-scope path performs read-modify-write on a {@code roles}
 * row (see 03-design.md §4.6).
 */
@Entity
@Table(name = "roles")
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

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  // DB-managed via ON UPDATE CURRENT_TIMESTAMP(6); never written by this entity (§3.2).
  @Column(name = "updated_at", insertable = false, updatable = false)
  private Instant updatedAt;

  /** Creates a role; {@code created_at}/{@code updated_at} are set by the database. */
  public Role(UUID id, UUID tenantId, String name, String description, boolean systemRole) {
    this.id = id;
    this.tenantId = tenantId;
    this.name = name;
    this.description = description;
    this.systemRole = systemRole;
  }
}
