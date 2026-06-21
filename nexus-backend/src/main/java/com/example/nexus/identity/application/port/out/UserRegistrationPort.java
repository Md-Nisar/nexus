package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.User;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence port for {@link User} read/write operations within the registration flow.
 *
 * <p>Implementations live in {@code identity.infrastructure.persistence} — the domain and
 * application layers depend only on this interface (hexagonal architecture, ADR-0002).
 */
public interface UserRegistrationPort {

  /**
   * Finds a user by their tenant and email blind-index HMAC.
   *
   * @param tenantId the owning tenant
   * @param emailHmac SHA-256 HMAC of the normalised email address (ADR-0006)
   * @return the matching user, or empty if none exists
   */
  Optional<User> findByTenantAndEmailHmac(UUID tenantId, String emailHmac);

  /**
   * Finds a user by their primary key.
   *
   * @param userId the user's UUID
   * @return the matching user, or empty if none exists
   */
  Optional<User> findById(UUID userId);

  /**
   * Persists a new or updated {@link User}.
   *
   * @param user the user to save
   * @return the saved user (may differ from the input if the persistence layer sets defaults)
   */
  User save(User user);
}
