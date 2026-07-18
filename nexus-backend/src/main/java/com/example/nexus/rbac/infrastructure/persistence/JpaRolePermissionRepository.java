package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository for the {@link RolePermission} join entity. */
public interface JpaRolePermissionRepository
    extends JpaRepository<RolePermission, RolePermissionId> {}
