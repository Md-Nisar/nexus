package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.identity.domain.EmailCipher;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

@Tag("UnitTest")
class AttributeEncryptorTest {

  // EXAMPLE values — not real credentials
  private static final String TEST_PASSWORD = "exactly-16-chars-pw!";
  private static final String TEST_SALT = "deadbeefdeadbeefdeadbeefdeadbeef";

  private final TextEncryptor textEncryptor = Encryptors.text(TEST_PASSWORD, TEST_SALT);
  private final AttributeEncryptor encryptor = new AttributeEncryptor(textEncryptor);

  @Test
  void should_encryptEmailCipher_when_convertToDatabaseColumnCalled() {
    EmailCipher cipher = new EmailCipher("user@example.com");

    String result = encryptor.convertToDatabaseColumn(cipher);

    assertThat(result).isNotNull();
    assertThat(result).isNotEqualTo("user@example.com");
  }

  @Test
  void should_decryptToOriginal_when_convertToEntityAttributeCalled() {
    EmailCipher original = new EmailCipher("user@example.com");
    String encrypted = encryptor.convertToDatabaseColumn(original);

    EmailCipher result = encryptor.convertToEntityAttribute(encrypted);

    assertThat(result).isNotNull();
    assertThat(result.value()).isEqualTo("user@example.com");
  }

  @Test
  void should_returnNull_when_nullEmailCipherConverted() {
    assertThat(encryptor.convertToDatabaseColumn(null)).isNull();
  }

  @Test
  void should_returnNull_when_nullStringConverted() {
    assertThat(encryptor.convertToEntityAttribute(null)).isNull();
  }

  @Test
  void should_throwEncryptionException_when_corruptCiphertextDecrypted() {
    String tampered = "this-is-not-valid-ciphertext-at-all";

    assertThatThrownBy(() -> encryptor.convertToEntityAttribute(tampered))
        .isInstanceOf(EncryptionException.class)
        .hasMessageNotContaining(tampered);
  }

  @Test
  void should_notIncludePiiInErrorMessage_when_decryptionFails() {
    String tampered = "corrupt-cipher-value-xyz";

    assertThatThrownBy(() -> encryptor.convertToEntityAttribute(tampered))
        .isInstanceOf(EncryptionException.class)
        .satisfies(
            ex -> {
              String msg = ex.getMessage();
              assertThat(msg).doesNotContain("email");
              assertThat(msg).doesNotContain(tampered);
              assertThat(msg).doesNotContain("user@example.com");
            });
  }

  @Test
  void should_throwEncryptionException_when_encryptionFails() {
    // A broken TextEncryptor that always throws triggers the catch block in
    // convertToDatabaseColumn (SEC-T8 — never surface raw exceptions)
    TextEncryptor broken =
        new TextEncryptor() {
          @Override
          public String encrypt(String text) {
            throw new RuntimeException("simulated encrypt failure");
          }

          @Override
          public String decrypt(String encryptedText) {
            throw new RuntimeException("simulated decrypt failure");
          }
        };
    AttributeEncryptor brokenEncryptor = new AttributeEncryptor(broken);

    assertThatThrownBy(() -> brokenEncryptor.convertToDatabaseColumn(new EmailCipher("x@y.com")))
        .isInstanceOf(EncryptionException.class)
        .hasMessage("Failed to encrypt attribute");
  }
}
