package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Permission;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for the {@link Permission} aggregate. M15 ({@code findCatalogueIds})
 * lives on the read-only {@link JpaPermissionCatalogueRepository} instead (US-018
 * 07-security-review.md L-5).
 */
public interface JpaPermissionRepository extends JpaRepository<Permission, UUID> {}
