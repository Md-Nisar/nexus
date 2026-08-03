package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.User;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * {@code identity.infrastructure} implementation of {@link UserDirectoryPort}, delegating to the
 * existing {@link JpaUserRepository}. This is the one permitted {@code identity} &rarr; {@code
 * rbac} dependency direction: {@code identity.infrastructure} depends only on {@code
 * rbac.application.port.out.UserDirectoryPort}; {@code rbac} never imports {@code identity}
 * (03-design.md §5.1/§7.4, ArchUnit-enforced).
 */
@Component
public class JpaUserDirectoryAdapter implements UserDirectoryPort {

  private final JpaUserRepository userRepository;

  public JpaUserDirectoryAdapter(JpaUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public Optional<UUID> findTenantId(UUID userId) {
    return userRepository.findById(userId).map(User::getTenantId);
  }
}
