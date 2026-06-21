package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class JpaAuthTokenAdapterTest {

  @Mock
  private JpaAuthTokenRepository tokenRepository;

  @InjectMocks
  private JpaAuthTokenAdapter adapter;

  @Test
  void findByTokenHash_delegatesToRepository() {
    String hash = "abc123hash";
    when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.empty());

    assertThat(adapter.findByTokenHash(hash)).isEmpty();
    verify(tokenRepository).findByTokenHash(hash);
  }

  @Test
  void countByUserIdAndTypeAndCreatedAtAfter_delegatesToRepository() {
    UUID userId = UUID.randomUUID();
    Instant since = Instant.now().minusSeconds(60);
    when(tokenRepository.countByUserIdAndTypeAndCreatedAtAfter(
        userId, AuthTokenType.VERIFICATION, since)).thenReturn(2);

    int count = adapter.countByUserIdAndTypeAndCreatedAtAfter(userId, AuthTokenType.VERIFICATION, since);

    assertThat(count).isEqualTo(2);
    verify(tokenRepository).countByUserIdAndTypeAndCreatedAtAfter(userId, AuthTokenType.VERIFICATION, since);
  }

  @Test
  void markConsumed_setsConsumedAtOnToken_andSaves() {
    AuthToken token = new AuthToken(UUID.randomUUID(), UUID.randomUUID(),
        AuthTokenType.VERIFICATION, "sha256hash", Instant.now().plusSeconds(3600));
    Instant consumedAt = Instant.now();
    when(tokenRepository.save(token)).thenReturn(token);

    AuthToken result = adapter.markConsumed(token, consumedAt);

    assertThat(token.getConsumedAt()).isEqualTo(consumedAt);
    verify(tokenRepository).save(token);
    assertThat(result).isSameAs(token);
  }
}
