package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.Permission;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import com.example.nexus.rbac.domain.RoleView;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
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
  private final JpaRolePermissionRepository rolePermissionRepository;
  private final JpaPermissionRepository permissionRepository;
  private final IdGenerator idGenerator;

  public JpaRoleManagementAdapter(
      JpaRoleRepository roleRepository,
      JpaRolePermissionRepository rolePermissionRepository,
      JpaPermissionRepository permissionRepository,
      IdGenerator idGenerator) {
    this.roleRepository = roleRepository;
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
  public List<RoleView> findRolesInTenant(UUID tenantId) {
    return roleRepository.findRoleViewsByTenantId(tenantId);
  }

  @Override
  public Optional<UUID> findRoleIdByName(UUID tenantId, String name) {
    return roleRepository.findIdByTenantIdAndName(tenantId, name);
  }

  @Override
  public long countRolesInTenant(UUID tenantId) {
    return roleRepository.countByTenantId(tenantId);
  }

  @Override
  public Optional<PermissionView> findPermission(UUID permissionId) {
    return permissionRepository
        .findById(permissionId)
        .map(JpaRoleManagementAdapter::toPermissionView);
  }

  @Override
  public List<PermissionView> findAllPermissions() {
    return permissionRepository.findAll(Sort.by("name")).stream()
        .map(JpaRoleManagementAdapter::toPermissionView)
        .toList();
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

  private static PermissionView toPermissionView(Permission permission) {
    return new PermissionView(permission.getId(), permission.getName(), permission.getDescription());
  }
}
