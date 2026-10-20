package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserStatus;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Read side of the user directory (US-019 B1, design §4.1). Distinct from RBAC's {@code
 * UserDirectoryPort}. Every method that returns users is scoped to one tenant; the two unscoped
 * methods return only an existence flag or a count and exist solely to detect cross-tenant probes.
 */
public interface UserDirectoryQueryPort {

  /**
   * One page of the tenant's users ordered by id.
   *
   * @param status the status to filter by, or {@code null} for every status
   */
  DirectoryPage<DirectoryUserView> findPageByTenant(
      UUID tenantId, UserStatus status, int page, int size);

  /** The tenant's users among {@code ids}, ordered by id; ids of other tenants are omitted. */
  List<DirectoryUserView> findByTenantAndIds(UUID tenantId, Collection<UUID> ids);

  /**
   * The user of {@code tenantId} whose email blind index is {@code emailHmac}; another tenant's
   * user with the same email is simply absent.
   *
   * @param emailHmac computed by {@code EmailBlindIndexService.blindIndex} only (ADR-0006)
   */
  Optional<DirectoryUserView> findByTenantAndEmailHmac(UUID tenantId, String emailHmac);

  /** The user {@code userId} if it belongs to {@code tenantId}. */
  Optional<DirectoryUserView> findByTenantAndId(UUID tenantId, UUID userId);

  /**
   * Whether {@code userId} exists in any tenant. Unscoped: only to tell a cross-tenant miss from a
   * genuine one after {@link #findByTenantAndId} found nothing; never feeds a response.
   */
  boolean existsById(UUID userId);

  /**
   * How many of {@code ids} exist in any tenant. Unscoped and count only (RC-61.2): only to detect
   * a batch that names another tenant's users; never feeds a response.
   */
  long countByIdIn(Collection<UUID> ids);
}
