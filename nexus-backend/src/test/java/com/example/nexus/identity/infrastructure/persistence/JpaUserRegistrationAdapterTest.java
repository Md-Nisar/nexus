package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.domain.User;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class JpaUserRegistrationAdapterTest {

  @Mock
  private JpaUserRepository userRepository;

  @InjectMocks
  private JpaUserRegistrationAdapter adapter;

  @Test
  void findByTenantAndEmailHmac_delegatesToRepository() {
    UUID tenantId = UUID.randomUUID();
    String hmac = "abc123hmac";
    when(userRepository.findByTenantIdAndEmailHmac(tenantId, hmac)).thenReturn(Optional.empty());

    Optional<User> result = adapter.findByTenantAndEmailHmac(tenantId, hmac);

    assertThat(result).isEmpty();
    verify(userRepository).findByTenantIdAndEmailHmac(tenantId, hmac);
  }

  @Test
  void findById_delegatesToRepository() {
    UUID userId = UUID.randomUUID();
    when(userRepository.findById(userId)).thenReturn(Optional.empty());

    Optional<User> result = adapter.findById(userId);

    assertThat(result).isEmpty();
    verify(userRepository).findById(userId);
  }

  @Test
  void save_delegatesToRepository_andReturnsResult() {
    User user = mock(User.class);
    when(userRepository.save(user)).thenReturn(user);

    User result = adapter.save(user);

    assertThat(result).isSameAs(user);
    verify(userRepository).save(user);
  }
}
