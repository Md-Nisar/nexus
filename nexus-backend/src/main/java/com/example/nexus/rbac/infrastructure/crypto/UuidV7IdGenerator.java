package com.example.nexus.rbac.infrastructure.crypto;

import com.example.nexus.rbac.domain.IdGenerator;
import com.github.f4b6a3.uuid.UuidCreator;
import java.util.UUID;
import org.springframework.stereotype.Component;

/** Production {@link IdGenerator} implementation using UUIDv7 via uuid-creator (see ADR-0005). */
@Component
public class UuidV7IdGenerator implements IdGenerator {

  @Override
  public UUID newId() {
    return UuidCreator.getTimeOrderedEpoch();
  }
}
