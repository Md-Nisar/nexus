package com.example.nexus.rbac.interfaces.rest.dto;

import com.example.nexus.rbac.domain.PageResult;

/**
 * The {@code page} object of the collection envelope (api-design skill, Collections): {@code size},
 * 0-based {@code number}, {@code totalElements} and {@code totalPages}. Shared by every paged RBAC
 * list (US-018 C2 and C3).
 */
public record PageMetadata(int size, int number, long totalElements, int totalPages) {

  public static PageMetadata of(PageResult<?> result) {
    return new PageMetadata(
        result.size(), result.page(), result.totalElements(), result.totalPages());
  }
}
