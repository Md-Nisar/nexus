package com.example.nexus.rbac.domain;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Persistable;

/**
 * Join row granting a {@link Permission} to a {@link Role}. First-class entity (not
 * {@code @ManyToMany}) because the join table carries {@code created_at}, which a plain
 * many-to-many mapping cannot express.
 *
 * <p>Composite key is {@link RolePermissionId} via {@code @EmbeddedId} — see that class's Javadoc
 * for why {@code @EmbeddedId} is used instead of the {@code @IdClass} originally specified in
 * 03-design.md §4.3 (a Hibernate restriction on converters for {@code @IdClass} components,
 * discovered during implementation). {@code getRoleId()}/{@code getPermissionId()} below preserve
 * the flat, bare-{@code UUID} accessor API the rest of this bounded context's "no nested ID value
 * objects at the call site" policy expects (03-design.md §4.1), delegating to the embedded id.
 *
 * <p>Implements {@link Persistable} because the key is assigned, not generated: without it Spring
 * Data's {@code save} treats every instance as detached and {@code merge}s it, costing one
 * existence {@code SELECT} per row (US-019 P-22). An instance built in code is new; one loaded or
 * persisted is not.
 */
@Entity
@Table(name = "role_permissions")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RolePermission implements Persistable<RolePermissionId> {

  @EmbeddedId private RolePermissionId id;

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  @Transient private boolean isNew = true;

  public RolePermission(UUID roleId, UUID permissionId) {
    this.id = new RolePermissionId(roleId, permissionId);
  }

  @Override
  public RolePermissionId getId() {
    return id;
  }

  @Override
  public boolean isNew() {
    return isNew;
  }

  @PostLoad
  @PostPersist
  void markNotNew() {
    this.isNew = false;
  }

  public UUID getRoleId() {
    return id.getRoleId();
  }

  public UUID getPermissionId() {
    return id.getPermissionId();
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
