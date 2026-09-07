package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Spring Data JPA repository for the {@link RolePermission} join entity. */
public interface JpaRolePermissionRepository
    extends JpaRepository<RolePermission, RolePermissionId> {

  /**
   * Q7 — US-015 AC3. A single projection join {@code RolePermission -> Permission}, bounded at
   * {@code |permissions| = 7}, {@code ORDER BY p.name} for a stable contract (03-design.md §5.2).
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.PermissionView(p.id, p.name, p.description)
      FROM RolePermission rp JOIN Permission p ON p.id = rp.id.permissionId
      WHERE rp.id.roleId = :roleId
      ORDER BY p.name
      """)
  List<PermissionView> findPermissionViewsForRole(@Param("roleId") UUID roleId);

  /**
   * Q9 — US-015 AC5. MUST be a {@code @Modifying} bulk {@code DELETE} returning an affected-row
   * count: {@code deleteById} returns void and cannot distinguish "was attached" from "never
   * attached", which is exactly the distinction the 404-not-204 resolution requires. {@link
   * RolePermission} has no {@code @Version}, so this int count IS the concurrency guard
   * (03-design.md §5.2).
   */
  @Modifying
  @Query(
      "DELETE FROM RolePermission rp WHERE rp.id.roleId = :roleId AND rp.id.permissionId ="
          + " :permissionId")
  int deleteByRoleIdAndPermissionId(
      @Param("roleId") UUID roleId, @Param("permissionId") UUID permissionId);
}
