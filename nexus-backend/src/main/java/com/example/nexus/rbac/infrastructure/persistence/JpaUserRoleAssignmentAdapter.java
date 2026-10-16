package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionRef;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * Adapter for {@link UserRoleAssignmentPort}, backed by {@link JpaUserRoleRepository} (M2–M6,
 * M11, M13, M16) and {@link JpaRoleRepository} (M10', M14). Purely mechanical: this layer decides
 * nothing about who is an administrator and hardcodes no role or permission name; that is {@code
 * rbac.domain.RbacAdministrators}, over ids. This adapter holds no write capability over {@code
 * role_permissions} and must not acquire one: its permission reads (M10', M14) are hosted on {@link
 * JpaRoleRepository} precisely so that it cannot (03-design.md D16, T-T13).
 *
 * <p><b>Zero new constructor dependencies:</b> {@code JpaRolePermissionRepository} is still not
 * injected — ADR-0017 D2's second half is unweakened by this story.
 *
 * <p><b>US-018 M15:</b> the catalogue read goes through {@link JpaPermissionCatalogueRepository},
 * a read-only {@code Repository} that declares {@code findCatalogueIds()} and nothing else, so this
 * adapter has no write capability over {@code permissions} either (07-security-review.md L-5).
 */
@Component
public class JpaUserRoleAssignmentAdapter implements UserRoleAssignmentPort {

  private final JpaUserRoleRepository userRoleRepository;
  private final JpaRoleRepository roleRepository;
  private final JpaPermissionCatalogueRepository permissionCatalogueRepository;
  private final IdGenerator idGenerator;

  public JpaUserRoleAssignmentAdapter(
      JpaUserRoleRepository userRoleRepository,
      JpaRoleRepository roleRepository,
      JpaPermissionCatalogueRepository permissionCatalogueRepository,
      IdGenerator idGenerator) {
    this.userRoleRepository = userRoleRepository;
    this.roleRepository = roleRepository;
    this.permissionCatalogueRepository = permissionCatalogueRepository;
    this.idGenerator = idGenerator;
  }

  @Override
  public Optional<Role> findRole(UUID roleId) {
    return roleRepository.findById(roleId);
  }

  @Override
  public boolean hasActiveAssignment(UUID userId, UUID roleId) {
    return userRoleRepository.countActiveByUserAndRole(userId, roleId) > 0;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  @Override
  public List<RolePermissionRef> findRolePermissionIdsForTenantRoles(UUID tenantId) {
    return roleRepository.findRolePermissionIdsByTenantRoles(tenantId);
  }

  @Override
  public List<ActiveAssignmentHolder> lockActiveAssignmentHolders(
      UUID tenantId, List<UUID> roleIds) {
    // M11 is native (03-design.md §7.2 step 1 / MC-C): the adapter converts the
    // IN-list to byte[] explicitly and maps the returned entities down to id/userId-only records
    // before they escape this adapter, preserving the repository method's "ids only, never
    // entities" contract.
    List<byte[]> roleIdBytes = roleIds.stream().map(JpaUserRoleAssignmentAdapter::toBytes).toList();
    return userRoleRepository
        .lockActiveAssignmentHoldersByRoles(roleIdBytes, toBytes(tenantId))
        .stream()
        .map(ur -> new ActiveAssignmentHolder(ur.getId(), ur.getUserId(), ur.getRoleId()))
        .toList();
  }

  @Override
  public List<RolePermissionRef> findHeldRolePermissionIdsForAuthorization(
      UUID userId, UUID tenantId) {
    return userRoleRepository.findHeldRolePermissionIdsForAuthorization(userId, tenantId);
  }

  @Override
  public Optional<Set<UUID>> findPermissionIdsForRole(UUID roleId, UUID tenantId) {
    // L-2 (07-security-review.md): no row at all means the role is not in this tenant -> empty,
    // which the caller denies. A role in the tenant always yields at least one row; its null
    // element (the LEFT JOIN's "no permissions" row) is dropped, never mapped to an id.
    List<UUID> rows = roleRepository.findPermissionIdsByRoleAndTenantId(roleId, tenantId);
    if (rows.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(
        rows.stream().filter(Objects::nonNull).collect(Collectors.toUnmodifiableSet()));
  }

  @Override
  public Set<UUID> findCatalogueIds() {
    return permissionCatalogueRepository.findCatalogueIds();
  }

  @Override
  public Optional<ActiveAssignmentRef> findActiveAssignmentRef(
      UUID userId, UUID roleId, UUID tenantId) {
    return userRoleRepository.findActiveAssignmentRef(userId, roleId, tenantId);
  }

  @Override
  public Optional<ActiveRoleAssignment> findActiveAssignmentView(
      UUID userId, UUID roleId, UUID tenantId) {
    return userRoleRepository.findActiveAssignmentView(userId, roleId, tenantId);
  }

  @Override
  public PageResult<ActiveRoleAssignment> findActiveAssignmentViews(
      UUID userId, UUID tenantId, int page, int size) {
    Page<ActiveRoleAssignment> result =
        userRoleRepository.findActiveAssignmentViews(userId, tenantId, PageRequest.of(page, size));
    return new PageResult<>(result.getContent(), result.getTotalElements(), page, size);
  }

  @Override
  public UUID assign(UUID userId, UUID roleId, UUID tenantId, UUID assignedBy) {
    UUID id = idGenerator.newId();
    int inserted;
    try {
      // A conditional native INSERT ... SELECT (US-018 C1, RC-36.1), executed synchronously here so
      // a uq_user_role_active violation surfaces inside this try/catch and is translated to 409
      // RBAC_004 (the TOCTOU backstop a deferred JPA flush would have let escape as a 500). Zero
      // rows means the role is deleted (or not in the tenant): the same 404 as a missing role.
      inserted =
          userRoleRepository.assignIfRoleLive(
              toBytes(id), toBytes(userId), toBytes(roleId), toBytes(tenantId), toBytes(assignedBy));
    } catch (DataIntegrityViolationException e) {
      throw new DuplicateRoleAssignmentException();
    }
    if (inserted == 0) {
      throw new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role");
    }
    return id;
  }

  @Override
  public Optional<UUID> findRoleIdByName(UUID tenantId, String name) {
    return roleRepository.findIdByTenantIdAndName(tenantId, name);
  }

  @Override
  public int revoke(UUID userRoleId, Instant revokedAt) {
    return userRoleRepository.revokeById(userRoleId, revokedAt);
  }

  @Override
  public List<UUID> findActiveUserIdsForRole(UUID roleId) {
    return userRoleRepository.findActiveUserIdsByRole(roleId);
  }

  @Override
  public List<UUID> findHeldAdminDefiningRoleIds(UUID userId, UUID tenantId) {
    return userRoleRepository.findHeldAdminDefiningRoleIds(userId, tenantId);
  }

  @Override
  public List<HolderProvenance> findActiveHoldersForRole(UUID roleId, UUID tenantId) {
    return userRoleRepository.findActiveHoldersByRole(roleId, tenantId);
  }

  @Override
  public Set<UUID> findActiveHolderUserIdsForRoles(UUID tenantId, Collection<UUID> roleIds) {
    if (roleIds.isEmpty()) {
      return Set.of();
    }
    return Set.copyOf(userRoleRepository.findActiveHolderUserIdsByRoles(roleIds, tenantId));
  }
}
