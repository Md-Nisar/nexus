package com.example.nexus.rbac.application;

import java.util.regex.Pattern;

/**
 * The operator-supplied change reference of a break-glass grant (US-018 A7, RC-47), the only
 * operator attribution in the audit row (Decision 10). Canonical form {@code
 * ^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$}: no leading zeros, so one ticket has exactly one spelling.
 *
 * <p>A rejection never echoes the value: a rejected argument is untrusted free text and must not
 * reach logs or audit metadata through an exception message.
 *
 * @param value the canonical reference, for example {@code OPS-42}
 */
public record ChangeRef(String value) {

  private static final Pattern CANONICAL = Pattern.compile("[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}");

  /**
   * Validates {@code value} against the canonical pattern.
   *
   * @throws IllegalArgumentException if {@code value} is {@code null} or not canonical; the
   *     message never contains {@code value}
   */
  public ChangeRef {
    if (value == null || !CANONICAL.matcher(value).matches()) {
      throw new IllegalArgumentException(
          "changeRef must match ^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$ (RC-47)");
    }
  }
}
