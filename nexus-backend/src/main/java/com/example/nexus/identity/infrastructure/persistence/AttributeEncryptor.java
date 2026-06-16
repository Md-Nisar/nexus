package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.EmailCipher;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.crypto.encrypt.TextEncryptor;

/**
 * JPA converter that transparently encrypts/decrypts {@link EmailCipher} values using AES-256-GCM
 * (ADR-0006). Applied automatically to all {@link EmailCipher} columns — domain entities declare
 * no {@code @Convert} annotation.
 */
@Converter(autoApply = true)
public class AttributeEncryptor implements AttributeConverter<EmailCipher, String> {

  private final TextEncryptor textEncryptor;

  public AttributeEncryptor(TextEncryptor textEncryptor) {
    this.textEncryptor = textEncryptor;
  }

  @Override
  public String convertToDatabaseColumn(EmailCipher emailCipher) {
    if (emailCipher == null) {
      return null;
    }
    try {
      return textEncryptor.encrypt(emailCipher.value());
    } catch (Exception e) {
      throw new EncryptionException("Failed to encrypt attribute");
    }
  }

  @Override
  public EmailCipher convertToEntityAttribute(String dbData) {
    if (dbData == null) {
      return null;
    }
    try {
      return new EmailCipher(textEncryptor.decrypt(dbData));
    } catch (Exception e) {
      throw new EncryptionException("Failed to decrypt attribute");
    }
  }
}
