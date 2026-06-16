package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UuidV7ConverterTest {

  private final UuidV7Converter converter = new UuidV7Converter();

  @Test
  void should_return16Bytes_when_uuidConverted() {
    UUID uuid = UUID.randomUUID();

    byte[] bytes = converter.convertToDatabaseColumn(uuid);

    assertThat(bytes).hasSize(16);
  }

  @Test
  void should_roundTrip_when_uuidConvertedAndBack() {
    UUID original = UUID.randomUUID();

    UUID result = converter.convertToEntityAttribute(converter.convertToDatabaseColumn(original));

    assertThat(result).isEqualTo(original);
  }

  @Test
  void should_preserveBigEndianOrder_when_uuidEncoded() {
    long msb = 0x0123456789ABCDEFL;
    long lsb = 0xFEDCBA9876543210L;
    UUID uuid = new UUID(msb, lsb);

    byte[] bytes = converter.convertToDatabaseColumn(uuid);

    ByteBuffer bb = ByteBuffer.wrap(bytes);
    long readMsb = bb.getLong();
    long readLsb = bb.getLong();
    assertThat(readMsb).isEqualTo(msb);
    assertThat(readLsb).isEqualTo(lsb);
  }

  @Test
  void should_returnNull_when_nullUuidConverted() {
    assertThat(converter.convertToDatabaseColumn(null)).isNull();
  }

  @Test
  void should_returnNull_when_nullBytesConverted() {
    assertThat(converter.convertToEntityAttribute(null)).isNull();
  }

  @Test
  void should_throw_when_wrongLengthBytesConverted() {
    assertThatThrownBy(() -> converter.convertToEntityAttribute(new byte[8]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Expected 16 bytes");
  }
}
