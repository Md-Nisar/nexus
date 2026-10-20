package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.Permission;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import com.example.nexus.rbac.domain.RoleView;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;

/**
 * Adapter for {@link RoleManagementPort}, backed by {@link JpaRoleRepository}, {@link
 * JpaRolePermissionRepository} and {@link JpaPermissionRepository} (03-design.md §4.5,
 * 04-tasks.md T-003). Id generation stays in the adapter, matching {@link
 * JpaUserRoleAssignmentAdapter}'s precedent.
 *
 * <p>Its one non-mechanical responsibility is constraint-violation translation on {@code
 * createRole} and {@code attachPermission}: a {@link DataIntegrityViolationException} is
 * translated into {@link DuplicateRoleNameException} (RBAC_006) / {@link
 * DuplicateRolePermissionException} (RBAC_005) respectively, using their fixed static literal
 * messages — never the caught exception's own message, which {@code GlobalExceptionHandler}
 * would otherwise echo verbatim into the client-visible response body.
 *
 * <p>Both inserts use {@code saveAndFlush}, deliberately not {@code save}, mirroring {@link
 * JpaUserRoleAssignmentAdapter#assign}'s documented rationale: a plain {@code save()} only queues
 * the INSERT in Hibernate's persistence context, so a constraint violation would not necessarily
 * surface until some later auto-flush-triggering call — for {@code createRole}, the caller's own
 * immediate re-read via {@code findRole}; for {@code attachPermission}, the enclosing
 * transaction's commit — in either case, outside this method's own {@code try/catch}, letting the
 * violation escape untranslated as a 500. Flushing here forces the INSERT (and any constraint
 * violation) to happen synchronously, inside this method's own try/catch.
 *
 * <p>Every method returns a {@link RoleView}/{@link PermissionView} projection or a raw id/count,
 * never a managed {@link Role} entity (R-6) — see {@link RoleManagementPort}'s Javadoc for why.
 */
@Component
public class JpaRoleManagementAdapter implements RoleManagementPort {

  private final JpaRoleRepository roleRepository;
  private final JpaUserRoleRepository userRoleRepository;
  private final JpaRolePermissionRepository rolePermissionRepository;
  private final JpaPermissionRepository permissionRepository;
  private final IdGenerator idGenerator;

  public JpaRoleManagementAdapter(
      JpaRoleRepository roleRepository,
      JpaUserRoleRepository userRoleRepository,
      JpaRolePermissionRepository rolePermissionRepository,
      JpaPermissionRepository permissionRepository,
      IdGenerator idGenerator) {
    this.roleRepository = roleRepository;
    this.userRoleRepository = userRoleRepository;
    this.rolePermissionRepository = rolePermissionRepository;
    this.permissionRepository = permissionRepository;
    this.idGenerator = idGenerator;
  }

  @Override
  public UUID createRole(UUID tenantId, String name, String description) {
    try {
      Role role = new Role(idGenerator.newId(), tenantId, name, description, false);
      return roleRepository.saveAndFlush(role).getId();
    } catch (DataIntegrityViolationException e) {
      throw new DuplicateRoleNameException();
    }
  }

  @Override
  public Optional<RoleView> findRole(UUID roleId) {
    return roleRepository.findRoleViewById(roleId);
  }

  @Override
  public PageResult<RoleView> findRolesInTenant(UUID tenantId, int page, int size) {
    return toResult(
        roleRepository.findRoleViewsByTenantId(tenantId, PageRequest.of(page, size)), page, size);
  }

  @Override
  public int softDeleteRole(UUID roleId, UUID tenantId, Instant deletedAt) {
    return roleRepository.softDelete(roleId, tenantId, deletedAt);
  }

  @Override
  public int updateRole(UUID roleId, UUID tenantId, String name, String description) {
    try {
      return roleRepository.updateNameAndDescription(roleId, tenantId, name, description);
    } catch (DataIntegrityViolationException e) {
      // The active-name (or, until V10, the plain name) unique key: a fixed literal, never the
      // driver's message, which the conflict handler would echo into the response body.
      throw new DuplicateRoleNameException();
    }
  }

  @Override
  public long countRolesInTenant(UUID tenantId) {
    return roleRepository.countByTenantIdAndDeletedAtIsNull(tenantId);
  }

  @Override
  public Map<UUID, Long> countActiveHoldersByRole(UUID tenantId, Collection<UUID> roleIds) {
    if (roleIds.isEmpty()) {
      return Map.of();
    }
    return toCountMap(userRoleRepository.countActiveHoldersByRole(tenantId, roleIds));
  }

  @Override
  public Map<UUID, Long> countPermissionsByRole(UUID tenantId, Collection<UUID> roleIds) {
    if (roleIds.isEmpty()) {
      return Map.of();
    }
    return toCountMap(roleRepository.countPermissionsByRole(tenantId, roleIds));
  }

  private static Map<UUID, Long> toCountMap(List<Object[]> rows) {
    Map<UUID, Long> counts = new HashMap<>();
    for (Object[] row : rows) {
      counts.put((UUID) row[0], ((Number) row[1]).longValue());
    }
    return counts;
  }

  @Override
  public Optional<PermissionView> findPermission(UUID permissionId) {
    return permissionRepository
        .findById(permissionId)
        .map(JpaRoleManagementAdapter::toPermissionView);
  }

  @Override
  public PageResult<PermissionView> findAllPermissions(int page, int size) {
    // name is unique, so Sort.by("name") alone is a total order.
    return toResult(
        permissionRepository
            .findAll(PageRequest.of(page, size, Sort.by("name")))
            .map(JpaRoleManagementAdapter::toPermissionView),
        page,
        size);
  }

  private static <T> PageResult<T> toResult(Page<T> springPage, int page, int size) {
    return new PageResult<>(springPage.getContent(), springPage.getTotalElements(), page, size);
  }

  @Override
  public List<PermissionView> findPermissionsForRole(UUID roleId) {
    return rolePermissionRepository.findPermissionViewsForRole(roleId);
  }

  @Override
  public boolean hasPermission(UUID roleId, UUID permissionId) {
    return rolePermissionRepository.existsById(new RolePermissionId(roleId, permissionId));
  }

  @Override
  public void attachPermission(UUID roleId, UUID permissionId) {
    try {
      rolePermissionRepository.saveAndFlush(new RolePermission(roleId, permissionId));
    } catch (DataIntegrityViolationException e) {
      throw new DuplicateRolePermissionException();
    }
  }

  @Override
  public int detachPermission(UUID roleId, UUID permissionId) {
    return rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permissionId);
  }

  @Override
  public boolean lockRoleRow(UUID roleId, UUID tenantId) {
    return !roleRepository.lockLiveRoleRow(toBytes(roleId), toBytes(tenantId)).isEmpty();
  }

  @Override
  public Set<UUID> lockPermissionIdsForRole(UUID roleId) {
    Set<UUID> permissionIds = new HashSet<>();
    for (byte[] id : rolePermissionRepository.lockPermissionIdsByRoleId(toBytes(roleId))) {
      permissionIds.add(fromBytes(id));
    }
    return permissionIds;
  }

  @Override
  public int detachPermissions(UUID roleId, Collection<UUID> permissionIds) {
    if (permissionIds.isEmpty()) {
      return 0;
    }
    return rolePermissionRepository.deleteByRoleIdAndPermissionIdIn(roleId, permissionIds);
  }

  /**
   * Inserts through {@code saveAllAndFlush} for the reason {@link #attachPermission} documents: a
   * key violation must surface here, translated to {@link DuplicateRolePermissionException}. Under
   * the replace's role-row lock and its current-read check none is expected.
   */
  @Override
  public void attachPermissions(UUID roleId, Collection<UUID> permissionIds) {
    try {
      rolePermissionRepository.saveAllAndFlush(
          permissionIds.stream().map(id -> new RolePermission(roleId, id)).toList());
    } catch (DataIntegrityViolationException e) {
      throw new DuplicateRolePermissionException();
    }
  }

  /** Native queries bypass {@code UuidV7Converter}: ids are bound and read as 16 bytes. */
  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }

  private static UUID fromBytes(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }

  private static PermissionView toPermissionView(Permission permission) {
    return new PermissionView(permission.getId(), permission.getName(), permission.getDescription());
  }
}
