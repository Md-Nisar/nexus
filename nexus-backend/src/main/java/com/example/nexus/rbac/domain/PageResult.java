package com.example.nexus.rbac.domain;

import java.util.List;
import java.util.function.Function;

/**
 * One page of a stable-ordered read, as the application layer sees it (US-018 C2). Framework-free
 * on purpose: the persistence adapters convert Spring Data's {@code Page} into this, and the REST
 * layer maps it to the response envelope, so neither a {@code Page} nor a DTO crosses a layer.
 *
 * @param items the rows of the requested page, possibly empty
 * @param totalElements the total number of rows over all pages
 * @param page the 0-based page number that was requested
 * @param size the page size that was requested
 */
public record PageResult<T>(List<T> items, long totalElements, int page, int size) {

  public PageResult {
    items = List.copyOf(items);
  }

  /** The number of pages: {@code ceil(totalElements / size)}, 0 when there is nothing. */
  public int totalPages() {
    return size <= 0 ? 0 : (int) ((totalElements + size - 1) / size);
  }

  /** The same page with each item mapped, for a projection that must change shape. */
  public <R> PageResult<R> map(Function<? super T, ? extends R> mapper) {
    return new PageResult<>(items.stream().<R>map(mapper).toList(), totalElements, page, size);
  }
}
