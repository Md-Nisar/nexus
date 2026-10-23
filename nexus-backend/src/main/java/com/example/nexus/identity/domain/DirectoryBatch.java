package com.example.nexus.identity.domain;

import java.util.List;

/**
 * A directory batch read (US-019 P-31): the tenant's users among the requested ids, plus how many
 * of those ids exist in any tenant, both read in one transaction so the two cannot skew.
 *
 * @param found the tenant's users, ordered by id
 * @param existingAnywhere how many requested ids exist in any tenant; only feeds the cross-tenant
 *     WARN, never a response
 */
public record DirectoryBatch(List<DirectoryUserView> found, long existingAnywhere) {

  public DirectoryBatch {
    found = List.copyOf(found);
  }

  /** The ids that exist but belong to another tenant; never negative. */
  public long omittedForeign() {
    return Math.max(0, existingAnywhere - found.size());
  }
}
