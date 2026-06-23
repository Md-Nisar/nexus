package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Testcontainers MySQL integration tests for {@link JpaRefreshTokenAdapter}.
 * Each test creates isolated data (unique token hashes, unique user emails) so tests are
 * independent and can run in any order.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class RefreshTokenIT {

  @Autowired private RefreshTokenPort refreshTokenPort;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private UuidGenerator uuidGenerator;

  private static final UUID TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final Instant FUTURE = Instant.now().plus(14, ChronoUnit.DAYS);

  private User createUser(String emailTag) {
    String email = "rt-it-" + emailTag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user = new User(uuidGenerator.newId(), TENANT_ID,
        new EmailCipher(email), hmac, "dummy-hash", null);
    return userRegistrationPort.save(user);
  }

  private RefreshToken saveToken(UUID userId, String tokenHash, UUID familyId) {
    RefreshToken token = new RefreshToken(
        uuidGenerator.newId(), userId, tokenHash, familyId, FUTURE);
    refreshTokenPort.save(token);
    return token;
  }

  /** Returns a unique 64-char hex string suitable for use as a token_hash in tests. */
  private static String uniqueHash() {
    String a = UUID.randomUUID().toString().replace("-", "");
    String b = UUID.randomUUID().toString().replace("-", "");
    return a + b;
  }

  @Test
  void save_then_findByTokenHash_returns_correct_token() {
    User user = createUser("save");
    UUID familyId = uuidGenerator.newId();
    String hash = uniqueHash();

    RefreshToken saved = saveToken(user.getId(), hash, familyId);

    Optional<RefreshToken> found = refreshTokenPort.findByTokenHash(hash);

    assertThat(found).isPresent();
    RefreshToken loaded = found.get();
    assertThat(loaded.getId()).isEqualTo(saved.getId());
    assertThat(loaded.getUserId()).isEqualTo(user.getId());
    assertThat(loaded.getTokenHash()).isEqualTo(hash);
    assertThat(loaded.getFamilyId()).isEqualTo(familyId);
    assertThat(loaded.getExpiresAt()).isNotNull();
    assertThat(loaded.getRevokedAt()).isNull();
  }

  @Test
  void findByTokenHash_returns_empty_when_not_found() {
    Optional<RefreshToken> result = refreshTokenPort.findByTokenHash("no-such-hash");
    assertThat(result).isEmpty();
  }

  @Test
  void revokeFamily_sets_revokedAt_on_all_family_members() {
    User user = createUser("revokeFamily");
    UUID familyId = uuidGenerator.newId();
    String hash1 = uniqueHash();
    String hash2 = uniqueHash();
    String hashOther = uniqueHash();
    UUID otherFamily = uuidGenerator.newId();

    saveToken(user.getId(), hash1, familyId);
    saveToken(user.getId(), hash2, familyId);
    saveToken(user.getId(), hashOther, otherFamily);

    Instant revokedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
    refreshTokenPort.revokeFamily(familyId, revokedAt);

    // Both tokens in the target family are revoked
    RefreshToken t1 = refreshTokenPort.findByTokenHash(hash1).orElseThrow();
    RefreshToken t2 = refreshTokenPort.findByTokenHash(hash2).orElseThrow();
    assertThat(t1.getRevokedAt()).isNotNull();
    assertThat(t2.getRevokedAt()).isNotNull();

    // Token in a different family is untouched
    RefreshToken other = refreshTokenPort.findByTokenHash(hashOther).orElseThrow();
    assertThat(other.getRevokedAt()).isNull();
  }

  @Test
  void revokeByUserId_sets_revokedAt_on_all_user_tokens() {
    User user = createUser("revokeUser");
    User otherUser = createUser("revokeUserOther");
    UUID familyId = uuidGenerator.newId();
    String hash1 = uniqueHash();
    String hash2 = uniqueHash();
    String hashOther = uniqueHash();

    saveToken(user.getId(), hash1, familyId);
    saveToken(user.getId(), hash2, uuidGenerator.newId());
    saveToken(otherUser.getId(), hashOther, uuidGenerator.newId());

    Instant revokedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
    refreshTokenPort.revokeByUserId(user.getId(), revokedAt);

    // Both tokens owned by the target user are revoked
    RefreshToken t1 = refreshTokenPort.findByTokenHash(hash1).orElseThrow();
    RefreshToken t2 = refreshTokenPort.findByTokenHash(hash2).orElseThrow();
    assertThat(t1.getRevokedAt()).isNotNull();
    assertThat(t2.getRevokedAt()).isNotNull();

    // Token owned by a different user is untouched
    RefreshToken other = refreshTokenPort.findByTokenHash(hashOther).orElseThrow();
    assertThat(other.getRevokedAt()).isNull();
  }

  @Test
  void revokeFamily_is_idempotent_when_already_revoked() {
    User user = createUser("revFamIdem");
    UUID familyId = uuidGenerator.newId();
    String hash = uniqueHash();

    saveToken(user.getId(), hash, familyId);

    Instant first = Instant.parse("2026-01-01T00:00:00Z");
    Instant second = Instant.parse("2026-01-02T00:00:00Z");

    refreshTokenPort.revokeFamily(familyId, first);
    refreshTokenPort.revokeFamily(familyId, second); // already revoked — WHERE revokedAt IS NULL skips it

    RefreshToken loaded = refreshTokenPort.findByTokenHash(hash).orElseThrow();
    assertThat(loaded.getRevokedAt()).isNotNull();
    // revokedAt must reflect the FIRST call, not the second
    assertThat(loaded.getRevokedAt()).isBefore(second);
  }

  @Test
  void revokeByUserId_is_idempotent_when_already_revoked() {
    User user = createUser("revUserIdem");
    String hash = uniqueHash();

    saveToken(user.getId(), hash, uuidGenerator.newId());

    Instant first = Instant.parse("2026-01-01T00:00:00Z");
    Instant second = Instant.parse("2026-01-02T00:00:00Z");

    refreshTokenPort.revokeByUserId(user.getId(), first);
    refreshTokenPort.revokeByUserId(user.getId(), second);

    RefreshToken loaded = refreshTokenPort.findByTokenHash(hash).orElseThrow();
    assertThat(loaded.getRevokedAt()).isNotNull();
    assertThat(loaded.getRevokedAt()).isBefore(second);
  }
}
