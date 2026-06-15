package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository for the {@link User} aggregate. */
public interface JpaUserRepository extends JpaRepository<User, UUID> {

  /**
   * Looks up a user by tenant and pre-computed email blind index.
   *
   * <p>Served by the {@code uq_users_tenant_id_email_hmac} UNIQUE index. Callers must compute the
   * {@code emailHmac} argument via {@code EmailBlindIndexService.blindIndex()} using the same
   * normalization contract.
   */
  Optional<User> findByTenantIdAndEmailHmac(UUID tenantId, String emailHmac);
}
