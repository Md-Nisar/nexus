package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.UserRole;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

/**
 * Adapter for {@link UserRoleAssignmentPort}, backed by {@link JpaUserRoleRepository} (M1–M6) and
 * {@link JpaRoleRepository}. Purely mechanical: this layer does not resolve {@code TENANT_ADMIN}
 * by any hardcoded literal — that resolution (matching a role by name case-insensitively within a
 * tenant) happens in the service layer, per 03-design.md §5.2's R-9 discipline.
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
    return !userRoleRepository.lockActiveAdminAssignment(userId, roleId, tenantId).isEmpty();
  }

  @Override
  public List<UUID> lockActiveAssignmentIds(UUID tenantId, UUID roleId) {
    return userRoleRepository.lockActiveAssignmentsByRole(tenantId, roleId).stream()
        .map(UserRole::getId)
        .toList();
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
  public int revoke(UUID userRoleId, Instant revokedAt) {
    return userRoleRepository.revokeById(userRoleId, revokedAt);
  }
}
