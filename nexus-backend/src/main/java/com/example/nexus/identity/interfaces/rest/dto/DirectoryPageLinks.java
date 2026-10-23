package com.example.nexus.identity.interfaces.rest.dto;

import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.UserStatus;

/**
 * The {@code links} object of the directory envelope: relative URLs of the next and previous page,
 * or {@code null}. Unlike RBAC's {@code PageLinks} it echoes the {@code status} filter. It is built
 * only from the base path constant, the parsed enum and ints, so a link never carries an email or
 * any other raw request text.
 */
public record DirectoryPageLinks(String next, String prev) {

  /** Links of a batch, which is always a single page. */
  public static final DirectoryPageLinks NONE = new DirectoryPageLinks(null, null);

  /**
   * @param status the filter to echo, or {@code null} when the list is unfiltered
   */
  public static DirectoryPageLinks of(String basePath, UserStatus status, DirectoryPage<?> page) {
    int number = page.page();
    int totalPages = page.totalPages();
    String next = number + 1 < totalPages ? link(basePath, status, number + 1, page.size()) : null;
    // A page past the end links back to the last real page, not to another empty one.
    String prev =
        number > 0
            ? link(basePath, status, Math.min(number - 1, Math.max(totalPages - 1, 0)), page.size())
            : null;
    return new DirectoryPageLinks(next, prev);
  }

  private static String link(String basePath, UserStatus status, int page, int size) {
    String filter = status == null ? "" : "status=" + status.name() + "&";
    return basePath + "?" + filter + "page=" + page + "&size=" + size;
  }
}
