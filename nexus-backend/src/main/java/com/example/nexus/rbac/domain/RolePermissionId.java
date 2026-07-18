package com.example.nexus.rbac.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Composite key for {@link RolePermission}, used as its {@code @EmbeddedId}.
 *
 * <p>{@code @EmbeddedId} rather than {@code @IdClass}: Hibernate disallows an
 * {@code AttributeConverter} on a non-aggregated composite identifier's ({@code @IdClass})
 * component attributes ({@code org.hibernate.AnnotationException: 'AttributeConverter' not
 * allowed for attribute ... annotated '@Id'}) — verified against the actual Hibernate version
 * resolved on this project's classpath. An aggregated composite identifier ({@code @EmbeddedId})
 * does not have this restriction. This is a deviation from 03-design.md §4.3's original
 * {@code @IdClass} choice, forced by this Hibernate constraint discovered during implementation.
 *
 * <p>No explicit {@code @Convert} here, deliberately: {@code UuidV7Converter} is
 * {@code @Converter(autoApply = true)} and picks up these {@code UUID} fields implicitly at
 * runtime, exactly as it does for {@link Permission}/{@link Role}/{@link UserRole}'s {@code @Id}
 * fields. An explicit {@code @Convert(converter = UuidV7Converter.class)} was tried first and
 * reverted — it compiles and passes {@code ddl-auto=validate}, but it creates a source-level
 * reference from {@code rbac.domain} to {@code identity.infrastructure.persistence}, which
 * {@code HexagonalArchitectureTest} correctly flags as a layering violation. Relying on
 * {@code autoApply} keeps this class free of any cross-context/cross-layer import.
 */
@Embeddable
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class RolePermissionId implements Serializable {

  @Column(name = "role_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID roleId;

  @Column(name = "permission_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID permissionId;
}
