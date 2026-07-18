package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Permission;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository for the {@link Permission} aggregate. */
public interface JpaPermissionRepository extends JpaRepository<Permission, UUID> {}
