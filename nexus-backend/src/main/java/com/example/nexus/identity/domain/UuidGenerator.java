package com.example.nexus.identity.domain;

import java.util.UUID;

/** Port for generating UUIDs; the production implementation uses UUIDv7 (see ADR-0005). */
@FunctionalInterface
public interface UuidGenerator {

  UUID newId();
}
