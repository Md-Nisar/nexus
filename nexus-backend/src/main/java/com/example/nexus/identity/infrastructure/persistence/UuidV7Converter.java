package com.example.nexus.identity.infrastructure.persistence;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * JPA converter that maps {@link UUID} to 16-byte big-endian {@code BINARY(16)} for storage
 * (ADR-0005). Applied automatically to all {@link UUID} columns.
 */
@Converter(autoApply = true)
public class UuidV7Converter implements AttributeConverter<UUID, byte[]> {

  @Override
  public byte[] convertToDatabaseColumn(UUID uuid) {
    if (uuid == null) {
      return null;
    }
    ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
    bb.putLong(uuid.getMostSignificantBits());
    bb.putLong(uuid.getLeastSignificantBits());
    return bb.array();
  }

  @Override
  public UUID convertToEntityAttribute(byte[] bytes) {
    if (bytes == null) {
      return null;
    }
    if (bytes.length != 16) {
      throw new IllegalArgumentException(
          "Expected 16 bytes for UUID BINARY(16) column, got " + bytes.length);
    }
    ByteBuffer bb = ByteBuffer.wrap(bytes);
    return new UUID(bb.getLong(), bb.getLong());
  }
}
