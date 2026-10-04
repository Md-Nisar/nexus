package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Permission;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;

/**
 * Read-only view of the {@link Permission} catalogue for the assignment adapter (US-018
 * 07-security-review.md L-5). Extends the marker {@link Repository}, not {@code JpaRepository},
 * so it exposes no {@code save} or {@code delete}: the adapter's only need is M15, and least
 * privilege no longer rests on the {@code nexus_app} DB grant alone.
 */
public interface JpaPermissionCatalogueRepository extends Repository<Permission, UUID> {

  /**
   * M15 (US-018, 03-design.md §2.1, §4.3) — the ids of the whole permission catalogue, the input to
   * {@code RbacAdministrators#isAdminDefining}. The catalogue is global (migration-defined,
   * read-only, ADR-0013 D1; {@link Permission} has no tenant column), so there is no tenant
   * predicate to add.
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated {@code @Lock}: {@code
   * nexus_app} holds {@code SELECT} only on {@code permissions} (MC-A).
   */
  @Query("SELECT p.id FROM Permission p")
  Set<UUID> findCatalogueIds();
}
