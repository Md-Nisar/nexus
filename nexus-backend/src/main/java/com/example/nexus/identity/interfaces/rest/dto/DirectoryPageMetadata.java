package com.example.nexus.identity.interfaces.rest.dto;

import com.example.nexus.identity.domain.DirectoryPage;

/**
 * The {@code page} object of the directory envelope: identity's copy of RBAC's {@code
 * PageMetadata} (design §4.6), kept in step by {@code PagingEnvelopeShapeTest}.
 */
public record DirectoryPageMetadata(int size, int number, long totalElements, int totalPages) {

  public static DirectoryPageMetadata of(DirectoryPage<?> page) {
    return new DirectoryPageMetadata(
        page.size(), page.page(), page.totalElements(), page.totalPages());
  }

  /** A batch of {@code count} users: one page holding all of them, or no page when empty. */
  public static DirectoryPageMetadata ofBatch(int count) {
    return new DirectoryPageMetadata(count, 0, count, count > 0 ? 1 : 0);
  }
}
