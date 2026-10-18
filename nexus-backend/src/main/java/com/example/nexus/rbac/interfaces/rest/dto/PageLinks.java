package com.example.nexus.rbac.interfaces.rest.dto;

import com.example.nexus.rbac.domain.PageResult;

/**
 * The {@code links} object of the collection envelope: relative URLs ({@code /api/v1/...}) of the
 * next and previous page, or {@code null} when there is none. The object itself is always present.
 * The {@code size} is carried so a non-default size survives paging.
 *
 * <p>{@code basePath} is built by the controller from constants and already-parsed UUIDs, never
 * from a raw request string.
 */
public record PageLinks(String next, String prev) {

  public static PageLinks of(String basePath, PageResult<?> result) {
    int page = result.page();
    int totalPages = result.totalPages();
    String next = page + 1 < totalPages ? link(basePath, page + 1, result.size()) : null;
    // A page past the end links back to the last real page, not to another empty one.
    String prev =
        page > 0 ? link(basePath, Math.min(page - 1, Math.max(totalPages - 1, 0)), result.size()) : null;
    return new PageLinks(next, prev);
  }

  private static String link(String basePath, int page, int size) {
    return basePath + "?page=" + page + "&size=" + size;
  }
}
