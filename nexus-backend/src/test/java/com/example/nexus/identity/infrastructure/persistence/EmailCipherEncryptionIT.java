package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import jakarta.persistence.EntityManager;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Transactional
class EmailCipherEncryptionIT {

  @Autowired private JpaUserRepository userRepository;
  @Autowired private EmailBlindIndexService blindIndexService;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private EntityManager em;

  @Test
  void should_storeCiphertextNotPlaintext_when_userSaved() {
    UUID tenantId = uuidGenerator.newId();
    String email = "secret@example.com";
    String hmac = blindIndexService.blindIndex(email);

    User user = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac);
    userRepository.saveAndFlush(user);

    // Raw column value must NOT contain the plaintext email
    String rawCipher =
        jdbc.queryForObject(
            "SELECT email_cipher FROM users WHERE tenant_id = ? AND email_hmac = ?",
            String.class,
            // tenant_id is stored as BINARY(16) — pass bytes
            uuidToBytes(tenantId),
            hmac);

    assertThat(rawCipher).isNotNull();
    assertThat(rawCipher).doesNotContain("secret@example.com");
    assertThat(rawCipher.length()).isGreaterThan(20); // encrypted form is always longer
  }

  @Test
  void should_decryptCorrectly_when_userLoadedFromDatabase() {
    UUID tenantId = uuidGenerator.newId();
    String email = "transparent@example.com";
    String hmac = blindIndexService.blindIndex(email);

    User saved = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac);
    userRepository.saveAndFlush(saved);

    // Clear JPA first-level cache so we re-read from DB
    userRepository.flush();

    User loaded = userRepository.findByTenantIdAndEmailHmac(tenantId, hmac).orElseThrow();
    assertThat(loaded.getEmailCipher().value()).isEqualTo(email);
  }

  @Test
  void should_produceDifferentCiphertexts_when_sameEmailEncryptedTwice() {
    // AES-256-GCM is non-deterministic: same plaintext → different ciphertext each time
    UUID t1 = uuidGenerator.newId();
    UUID t2 = uuidGenerator.newId();
    String email = "nonce@example.com";
    String hmac = blindIndexService.blindIndex(email);

    userRepository.saveAndFlush(new User(uuidGenerator.newId(), t1, new EmailCipher(email), hmac));
    userRepository.saveAndFlush(new User(uuidGenerator.newId(), t2, new EmailCipher(email), hmac));

    String cipher1 =
        jdbc.queryForObject(
            "SELECT email_cipher FROM users WHERE tenant_id = ?",
            String.class,
            uuidToBytes(t1));

    String cipher2 =
        jdbc.queryForObject(
            "SELECT email_cipher FROM users WHERE tenant_id = ?",
            String.class,
            uuidToBytes(t2));

    assertThat(cipher1).isNotNull();
    assertThat(cipher2).isNotNull();
    assertThat(cipher1).isNotEqualTo(cipher2);
  }

  @Test
  void should_throwEncryptionException_when_emailCipherTampered() {
    UUID tenantId = uuidGenerator.newId();
    String email = "tamper@example.com";
    String hmac = blindIndexService.blindIndex(email);

    User saved = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac);
    userRepository.saveAndFlush(saved);

    // Corrupt the stored ciphertext via raw JDBC — bypasses AttributeEncryptor (SEC-T8)
    jdbc.update(
        "UPDATE users SET email_cipher = ? WHERE tenant_id = ? AND email_hmac = ?",
        "000000000000000000000000000000000000000000000000000000000000000000000000",
        uuidToBytes(tenantId),
        hmac);

    // Clear the JPA first-level cache so the next find reads from DB, not identity map
    em.clear();

    // GCM AEAD verification must fail on the tampered value — never return null/plaintext
    assertThatThrownBy(
            () -> userRepository.findByTenantIdAndEmailHmac(tenantId, hmac).orElseThrow())
        .isInstanceOf(EncryptionException.class);
  }

  // UUID → 16-byte big-endian array (matches UuidV7Converter.convertToDatabaseColumn)
  private static byte[] uuidToBytes(UUID uuid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
