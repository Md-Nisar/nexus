package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * US-018 A7 (RC-47; 06-code-review-M5-T007.md finding 2): the break-glass change reference must
 * match {@code ^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$}, and a rejection never echoes the raw value.
 */
@Tag("UnitTest")
class ChangeRefTest {

  @ParameterizedTest
  @ValueSource(strings = {"OPS-42", "AB-1", "A1-9", "ABCDEFGHIJ-12345678", "INC2024-10"})
  void should_accept_when_valueMatchesTheCanonicalPattern(String value) {
    assertThat(new ChangeRef(value).value()).isEqualTo(value);
  }

  @Test
  void should_reject_when_null() {
    assertThatThrownBy(() -> new ChangeRef(null)).isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "ops-42", // lowercase
        "ABC-0", // zero
        "ABC-01", // leading zero
        "fix tenant", // free text
        "ABCDEFGHIJK-1", // prefix over length
        "ABC-123456789", // number over length
        "ABC-1\nINJECTED", // embedded newline
        "ABC-1\n", // trailing newline
        "ABC-1 ", // trailing whitespace
        " ABC-1", // leading whitespace
        "A-1", // prefix too short
        "1BC-1" // prefix starts with a digit
      })
  void should_rejectWithoutEchoingTheValue_when_valueDoesNotMatch(String value) {
    assertThatThrownBy(() -> new ChangeRef(value))
        .isInstanceOf(IllegalArgumentException.class)
        .satisfies(e -> assertThat(e.getMessage()).doesNotContain(value));
  }

  @Test
  void should_reject_when_empty() {
    assertThatThrownBy(() -> new ChangeRef("")).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_notEchoAFreeTextValue_when_rejected() {
    assertThatThrownBy(() -> new ChangeRef("drop table users"))
        .isInstanceOf(IllegalArgumentException.class)
        .satisfies(e -> assertThat(e.getMessage()).doesNotContain("drop table"));
  }
}
