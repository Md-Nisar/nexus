package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionName;
import com.example.nexus.rbac.domain.UserRole;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

/**
 * Adapter for {@link UserRoleAssignmentPort}, backed by {@link JpaUserRoleRepository} (M2–M6,
 * M11, M5b, M12) and {@link JpaRoleRepository} (M7, M10). Purely mechanical: this layer does not
 * resolve {@code TENANT_ADMIN} by any hardcoded literal — that resolution (matching a role by name
 * case-insensitively within a tenant) happens in the service layer, per 03-design.md §5.2's R-9
 * discipline. The same discipline now also covers dangerous permission names — this layer never
 * hardcodes a check against {@code RbacDangerousPermissions.NAMES} either. This adapter holds no
 * write capability over {@code role_permissions} and must not acquire one: its permission reads
 * (M7, and now the tenant-scoped M10) are hosted on {@link JpaRoleRepository} precisely so that it
 * cannot (03-design.md D16, T-T13; extended to M10 by D4).
 *
 * <p><b>Zero new constructor dependencies (US-017 D4):</b> both repositories were already
 * injected; M10 delegates to {@code roleRepository}, and M11/M5b/M12 delegate to {@code
 * userRoleRepository}. {@code JpaRolePermissionRepository} is still not injected — ADR-0017 D2's
 * second half is unweakened by this story.
 */
@Component
public class JpaUserRoleAssignmentAdapter implements UserRoleAssignmentPort {

  private final JpaUserRoleRepository userRoleRepository;
  private final JpaRoleRepository roleRepository;
  private final IdGenerator idGenerator;

  public JpaUserRoleAssignmentAdapter(
      JpaUserRoleRepository userRoleRepository,
      JpaRoleRepository roleRepository,
      IdGenerator idGenerator) {
    this.userRoleRepository = userRoleRepository;
    this.roleRepository = roleRepository;
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

  @Override
  public boolean hasActiveAdminAssignment(UUID userId, UUID roleId, UUID tenantId) {
    // M5 is now a native query (03-design.md §7.2 step 1 / MC-5): it does not go through the
    // entity-mapped UuidV7Converter on bind, so the UUID -> BINARY(16) conversion is done here
    // explicitly, matching ADR-0005's big-endian layout.
    return !userRoleRepository
        .lockActiveAdminAssignment(toBytes(userId), toBytes(roleId), toBytes(tenantId))
        .isEmpty();
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  @Override
  public List<RolePermissionName> findPermissionNamesForTenantRoles(UUID tenantId) {
    return roleRepository.findPermissionNamesByTenantRoles(tenantId);
  }

  @Override
  public List<ActiveAssignmentHolder> lockActiveAssignmentHolders(
      UUID tenantId, List<UUID> roleIds) {
    // M11 is native, like M5/M5b (03-design.md §7.2 step 1 / MC-C): the adapter converts the
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
  public boolean hasActiveAssignmentOfAnyRole(UUID userId, List<UUID> roleIds, UUID tenantId) {
    // M5b is native, like M5 (03-design.md §7.2 step 1 / MC-5): the adapter converts the IN-list
    // to byte[] explicitly, reusing the existing toBytes helper — never re-implemented.
    List<byte[]> roleIdBytes = roleIds.stream().map(JpaUserRoleAssignmentAdapter::toBytes).toList();
    return !userRoleRepository
        .lockActiveAssignmentOfAnyRole(toBytes(userId), roleIdBytes, toBytes(tenantId))
        .isEmpty();
  }

  @Override
  public List<RolePermissionName> findPermissionNamesForActiveAssignmentsOfUser(
      UUID userId, UUID tenantId) {
    return userRoleRepository.findPermissionNamesForActiveAssignmentsOfUser(userId, tenantId);
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
  public List<ActiveRoleAssignment> findActiveAssignmentViews(UUID userId, UUID tenantId) {
    return userRoleRepository.findActiveAssignmentViews(userId, tenantId);
  }

  @Override
  public UUID assign(UUID userId, UUID roleId, UUID tenantId, UUID assignedBy) {
    try {
      UserRole userRole = new UserRole(idGenerator.newId(), userId, roleId, tenantId, assignedBy);
      // saveAndFlush, deliberately NOT save: a plain save() only queues the INSERT in
      // Hibernate's persistence context -- the physical statement (and any uq_user_role_active
      // violation) may not execute until whatever LATER operation happens to trigger an
      // auto-flush (e.g. RoleAssignmentService#assign's own M4a re-read query immediately
      // after this call). That would let the DataIntegrityViolationException escape this
      // try/catch entirely and surface as an unhandled 500 instead of a clean 409 RBAC_004 --
      // a genuine TOCTOU-race bug this project's Phase 8 test-validate concurrency test
      // caught. Flushing here forces the INSERT (and any constraint violation) to happen
      // synchronously, inside this method's own try/catch, guaranteeing the translation fires.
      return userRoleRepository.saveAndFlush(userRole).getId();
    } catch (DataIntegrityViolationException e) {
      throw new DuplicateRoleAssignmentException();
    }
  }

  @Override
  public List<String> findPermissionNamesForRole(UUID roleId) {
    return roleRepository.findPermissionNamesByRole(roleId);
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
}
