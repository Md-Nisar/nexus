package com.example.nexus.identity.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class UuidV7GeneratorTest {

  private UuidV7Generator generator;

  @BeforeEach
  void setUp() {
    generator = new UuidV7Generator();
  }

  @Test
  void should_returnNonNull_when_newIdCalled() {
    UUID id = generator.newId();

    assertThat(id).isNotNull();
  }

  @Test
  void should_returnDistinctIds_when_calledTwice() {
    UUID first = generator.newId();
    UUID second = generator.newId();

    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void should_beVersion7_when_newIdGenerated() {
    UUID id = generator.newId();

    assertThat(id.version()).isEqualTo(7);
  }

  @Test
  void should_beTimeOrdered_when_calledSuccessively() {
    List<UUID> ids = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      ids.add(generator.newId());
    }

    for (int i = 1; i < ids.size(); i++) {
      long prevMsb = ids.get(i - 1).getMostSignificantBits();
      long currMsb = ids.get(i).getMostSignificantBits();
      // UUIDv7 MSB encodes timestamp in the high bits — later IDs must have MSB >= prior MSB
      assertThat(Long.compareUnsigned(currMsb, prevMsb))
          .as("UUID[%d] MSB should be >= UUID[%d] MSB", i, i - 1)
          .isGreaterThanOrEqualTo(0);
    }
  }
}
