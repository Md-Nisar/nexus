package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaAuthTokenRepository extends JpaRepository<AuthToken, UUID> {

  Optional<AuthToken> findByTokenHash(String tokenHash);

  int countByUserIdAndTypeAndCreatedAtAfter(UUID userId, AuthTokenType type, Instant since);
}
