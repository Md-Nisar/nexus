package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.domain.PreconditionRequiredException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * US-019 T-018 (design §10.5, RC-55.2, RC-55.4): {@code If-Match} accepts exactly one strong
 * entity-tag. Anything else, including a list of tags, is 428, so a client can never offer the
 * versions of several states.
 */
@Tag("UnitTest")
class IfMatchHeaderTest {

  @Test
  void should_returnTheOpaqueTag_when_exactlyOneStrongTagIsSent() {
    assertThat(IfMatchHeader.parse("\"rp1-abc_DEF-123\"")).isEqualTo("rp1-abc_DEF-123");
  }

  @Test
  void should_ignoreSurroundingWhitespace_when_oneStrongTagIsSent() {
    assertThat(IfMatchHeader.parse("  \"rp1-abc\"\t")).isEqualTo("rp1-abc");
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(
      strings = {
        "",
        "   ",
        "*",
        "\"rp1-a\", \"rp1-b\"",
        "\"rp1-a\",\"rp1-b\"",
        "W/\"rp1-a\"",
        "w/\"rp1-a\"",
        "rp1-a",
        "\"rp1-a",
        "rp1-a\"",
        "\"\"",
        "\"rp1 a\"",
        "\"rp1-a\" garbage",
        "\"rp1-é\""
      })
  void should_throwPreconditionRequired_when_theHeaderIsNotExactlyOneStrongTag(String raw) {
    assertThatThrownBy(() -> IfMatchHeader.parse(raw))
        .isInstanceOf(PreconditionRequiredException.class)
        .hasFieldOrPropertyWithValue("code", "PRECONDITION_REQUIRED");
  }
}
