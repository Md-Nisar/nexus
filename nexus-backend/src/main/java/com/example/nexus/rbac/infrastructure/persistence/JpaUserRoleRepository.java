package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.UserRole;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository for the {@link UserRole} aggregate. */
public interface JpaUserRoleRepository extends JpaRepository<UserRole, UUID> {}
