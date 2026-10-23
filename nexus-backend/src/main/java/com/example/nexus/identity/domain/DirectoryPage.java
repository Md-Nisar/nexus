package com.example.nexus.identity.domain;

import java.util.List;

/**
 * One page of a directory read (US-019 design §4.6): identity's own copy of RBAC's {@code
 * PageResult}, so identity never imports another context's types. Framework-free; the adapter
 * converts Spring Data's page into this and the REST layer maps it to the envelope.
 *
 * @param items the rows of the requested page, possibly empty
 * @param totalElements the total number of rows over all pages
 * @param page the 0-based page number that was requested
 * @param size the page size that was requested
 */
public record DirectoryPage<T>(List<T> items, long totalElements, int page, int size) {

  public DirectoryPage {
    items = List.copyOf(items);
  }

  /** The number of pages: {@code ceil(totalElements / size)}, 0 when there is nothing. */
  public int totalPages() {
    return size <= 0 ? 0 : (int) ((totalElements + size - 1) / size);
  }
}
