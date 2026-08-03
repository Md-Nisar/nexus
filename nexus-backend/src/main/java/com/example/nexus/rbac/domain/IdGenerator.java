package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * Rbac-local id-generation port. {@code identity.domain.UuidGenerator} already provides this
 * capability, but {@code rbac} may not import from {@code identity} (ArchUnit-enforced), so this
 * is a deliberately duplicated port rather than a cross-context import; consolidation into a
 * shared {@code common.domain.UuidGenerator} is deferred to a future story.
 */
@FunctionalInterface
public interface IdGenerator {
  UUID newId();
}
