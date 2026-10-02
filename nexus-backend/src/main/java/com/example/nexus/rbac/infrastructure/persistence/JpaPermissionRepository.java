package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Permission;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

/** Spring Data JPA repository for the {@link Permission} aggregate. */
public interface JpaPermissionRepository extends JpaRepository<Permission, UUID> {

  /**
   * M15 (US-018, 03-design.md §2.1, §4.3) — the ids of the whole permission catalogue, the input to
   * {@code RbacAdministrators#isAdminDefining}. The catalogue is global (migration-defined,
   * read-only, ADR-0013 D1; {@link Permission} has no tenant column), so there is no tenant
   * predicate to add. Hosted here rather than on {@link JpaRoleRepository} because it reads only
   * {@code permissions}.
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated {@code @Lock}: {@code
   * nexus_app} holds {@code SELECT} only on {@code permissions} (MC-A).
   */
  @Query("SELECT p.id FROM Permission p")
  Set<UUID> findCatalogueIds();
}
