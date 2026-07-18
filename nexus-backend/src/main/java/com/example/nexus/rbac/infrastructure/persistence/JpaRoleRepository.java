package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Role;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository for the {@link Role} aggregate. */
public interface JpaRoleRepository extends JpaRepository<Role, UUID> {}
