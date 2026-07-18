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
 * A single grantable capability (e.g. {@code user:read}). Code-/migration-defined only; read-only
 * at runtime (ADR-0013 D1) — no application path creates or mutates rows in this table.
 */
@Entity
@Table(name = "permissions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Permission {

  @Id
  @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID id;

  @Column(name = "name", length = 64, nullable = false)
  private String name;

  @Column(name = "description", length = 255, nullable = false)
  private String description;

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  /** Creates a permission; {@code created_at} is set by the database. */
  public Permission(UUID id, String name, String description) {
    this.id = id;
    this.name = name;
    this.description = description;
  }
}
