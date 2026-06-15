package com.example.nexus.identity.infrastructure.crypto;

import com.example.nexus.identity.domain.UuidGenerator;
import com.github.f4b6a3.uuid.UuidCreator;
import java.util.UUID;
import org.springframework.stereotype.Component;

/** Production {@link UuidGenerator} implementation using UUIDv7 via uuid-creator (see ADR-0005). */
@Component
public class UuidV7Generator implements UuidGenerator {

  @Override
  public UUID newId() {
    return UuidCreator.getTimeOrderedEpoch();
  }
}
