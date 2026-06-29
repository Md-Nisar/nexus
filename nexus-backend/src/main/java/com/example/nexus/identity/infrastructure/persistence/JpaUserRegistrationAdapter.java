package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class JpaUserRegistrationAdapter implements UserRegistrationPort {

  private final JpaUserRepository userRepository;

  public JpaUserRegistrationAdapter(JpaUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public Optional<User> findByTenantAndEmailHmac(UUID tenantId, String emailHmac) {
    return userRepository.findByTenantIdAndEmailHmac(tenantId, emailHmac);
  }

  @Override
  public Optional<User> findById(UUID userId) {
    return userRepository.findById(userId);
  }

  @Override
  public User save(User user) {
    return userRepository.save(user);
  }

  @Override
  public void resetFailedAttemptsDirect(UUID userId) {
    userRepository.resetFailedAttemptsDirect(userId);
  }
}
