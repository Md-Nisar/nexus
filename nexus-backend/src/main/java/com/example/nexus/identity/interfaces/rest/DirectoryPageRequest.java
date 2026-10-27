package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.identity.domain.UserStatus;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The validated query of {@code GET /api/v1/users} (US-019 B1, B2; design §4.1, §4.2): either a
 * {@link ListPage} or a {@link Batch}. Raw values are {@code String}s parsed here (house style
 * D15), so a malformed value is a 400 {@code VALIDATION_FAILED}, never a type-mismatch 500.
 * Paging follows RBAC's {@code PageParams}: default 20, at most 100, rejected rather than clamped.
 * No validation message ever echoes a request value.
 */
sealed interface DirectoryPageRequest
    permits DirectoryPageRequest.ListPage, DirectoryPageRequest.Batch {

  int DEFAULT_SIZE = 20;
  int MAX_SIZE = 100;
  /** Bounds the OFFSET of a deep page (RC-63(c)). */
  long MAX_OFFSET = 10_000;
  int MAX_IDS = 100;
  String VALIDATION_FAILED = "VALIDATION_FAILED";
  Pattern CANONICAL_UUID =
      Pattern.compile(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

  /**
   * List mode.
   *
   * @param status the filter, or {@code null} for every status
   */
  record ListPage(UserStatus status, int page, int size) implements DirectoryPageRequest {}

  /** {@code ids} mode: 1 to 100 distinct ids, in first-occurrence order. */
  record Batch(List<UUID> ids) implements DirectoryPageRequest {
    public Batch {
      ids = List.copyOf(ids);
    }
  }

  static DirectoryPageRequest parse(
      String rawStatus, String rawPage, String rawSize, String rawIds, String rawEmail) {
    if (rawEmail != null) {
      throw new FieldValidationException(
          VALIDATION_FAILED, "email", "is not accepted here; use POST /api/v1/users/lookup");
    }
    if (rawIds != null) {
      if (rawStatus != null || rawPage != null || rawSize != null) {
        throw new FieldValidationException(
            VALIDATION_FAILED, "ids", "must not be combined with status, page or size");
      }
      return new Batch(parseIds(rawIds));
    }
    UserStatus status = rawStatus == null ? null : parseStatus(rawStatus);
    int page = parseInt(rawPage, "page", 0);
    int size = parseInt(rawSize, "size", DEFAULT_SIZE);
    if (page < 0) {
      throw new FieldValidationException(VALIDATION_FAILED, "page", "must be 0 or greater");
    }
    if (size < 1 || size > MAX_SIZE) {
      throw new FieldValidationException(
          VALIDATION_FAILED, "size", "must be between 1 and " + MAX_SIZE);
    }
    if ((long) page * (long) size > (long) MAX_OFFSET) {
      throw new FieldValidationException(
          VALIDATION_FAILED, "page", "page times size must not exceed " + MAX_OFFSET);
    }
    return new ListPage(status, page, size);
  }

  private static UserStatus parseStatus(String raw) {
    for (UserStatus status : UserStatus.values()) {
      if (status.name().equals(raw)) {
        return status;
      }
    }
    throw new FieldValidationException(
        VALIDATION_FAILED,
        "status",
        "must be one of "
            + Arrays.stream(UserStatus.values()).map(Enum::name).collect(Collectors.joining(", ")));
  }

  private static List<UUID> parseIds(String raw) {
    if (raw.isEmpty()) {
      throw new FieldValidationException(
          VALIDATION_FAILED, "ids", "must list 1 to " + MAX_IDS + " ids");
    }
    String[] parts = raw.split(",", -1);
    if (parts.length > MAX_IDS) {
      throw new FieldValidationException(
          VALIDATION_FAILED, "ids", "must list at most " + MAX_IDS + " ids");
    }
    Set<UUID> ids = new LinkedHashSet<>();
    for (String part : parts) {
      if (!CANONICAL_UUID.matcher(part).matches()) {
        throw new FieldValidationException(
            VALIDATION_FAILED, "ids", "must be comma-separated canonical UUIDs");
      }
      ids.add(UUID.fromString(part));
    }
    return new ArrayList<>(ids);
  }

  private static int parseInt(String raw, String field, int defaultValue) {
    if (raw == null || raw.isEmpty()) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new FieldValidationException(VALIDATION_FAILED, field, "must be an integer");
    }
  }
}
