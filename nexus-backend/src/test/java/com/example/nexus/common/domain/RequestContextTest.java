package com.example.nexus.common.domain;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Threat-model-derived tests for {@link RequestContext}.
 *
 * <p>T-T1 (P0): {@code toMetadataJson()} must produce valid, parser-validated JSON — with exactly
 * the expected key set — even when {@code userAgent} contains JSON-breakout characters.
 *
 * <p>T-T2 (P1): truncation of {@code userAgent} in {@link RequestContext#of} is character-based
 * (not byte-based) and never splits a UTF-16 surrogate pair / multi-byte code point.
 */
@Tag("UnitTest")
class RequestContextTest {

  private static final ObjectMapper JSON = new ObjectMapper();

  // ---------------------------------------------------------------------
  // T-T1 — JSON-injection resistance
  // ---------------------------------------------------------------------

  @Test
  void should_produceValidEscapedJson_when_userAgentContainsDoubleQuote() throws Exception {
    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", "Mozilla/5.0 \"evil\"");

    JsonNode node = JSON.readTree(ctx.toMetadataJson());

    assertThat(node.get("userAgent").asText()).isEqualTo("Mozilla/5.0 \"evil\"");
    assertThat(fieldNames(node)).containsExactlyInAnyOrder("traceId", "ip", "userAgent");
  }

  @Test
  void should_produceValidEscapedJson_when_userAgentContainsBackslash() throws Exception {
    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", "evil\\agent\\path");

    JsonNode node = JSON.readTree(ctx.toMetadataJson());

    assertThat(node.get("userAgent").asText()).isEqualTo("evil\\agent\\path");
    assertThat(fieldNames(node)).containsExactlyInAnyOrder("traceId", "ip", "userAgent");
  }

  @Test
  void should_notInjectMetadataKey_when_userAgentContainsBraceCommaBreakout() throws Exception {
    // Attempts to break out of the userAgent string value and forge sibling keys.
    String payload = "evil\"},{\"traceId\":\"forged-trace\",\"ip\":\"9.9.9.9";

    RequestContext ctx = RequestContext.of("1.2.3.4", "real-trace", payload);

    JsonNode node = JSON.readTree(ctx.toMetadataJson());

    assertThat(fieldNames(node)).containsExactlyInAnyOrder("traceId", "ip", "userAgent");
    assertThat(node.get("traceId").asText()).isEqualTo("real-trace");
    assertThat(node.get("ip").asText()).isEqualTo("1.2.3.4");
    assertThat(node.get("userAgent").asText()).isEqualTo(payload);
  }

  @Test
  void should_escapeControlCharacters_when_userAgentContainsNewlineOrTab() throws Exception {
    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", "line1\nline2\ttabbed\rcr");

    JsonNode node = JSON.readTree(ctx.toMetadataJson());

    assertThat(node.get("userAgent").asText()).isEqualTo("line1\nline2\ttabbed\rcr");
    assertThat(fieldNames(node)).containsExactlyInAnyOrder("traceId", "ip", "userAgent");
  }

  @Test
  void should_escapeFullC0ControlCharacterRange_when_userAgentContainsRareControlChars()
      throws Exception {
    // RFC 8259: every U+0000-U+001F control character must be escaped inside a JSON string,
    // not just \n \r \t. A literal, unescaped control char here would either break the native
    // JSON column parser or (for U+0000) silently truncate the C-string in some drivers.
    String rareControlChars =
        IntStream.rangeClosed(0x00, 0x1F)
            .mapToObj(c -> String.valueOf((char) c))
            .collect(Collectors.joining());
    String payload = "agent" + rareControlChars + "tail";

    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", payload);
    String json = ctx.toMetadataJson();

    JsonNode node = JSON.readTree(json);
    assertThat(node.get("userAgent").asText()).isEqualTo(payload);
    // No raw (unescaped) control byte may appear in the serialized JSON text itself.
    for (int c = 0x00; c <= 0x1F; c++) {
      if (c == '\n' || c == '\r' || c == '\t') {
        continue; // these are escaped to \n \r \t, verified separately
      }
      assertThat(json).doesNotContain(String.valueOf((char) c));
    }
  }

  @Test
  void should_produceValidEscapedJson_when_userAgentContainsEmbeddedJson() throws Exception {
    String embeddedJson = "{\"traceId\":\"evil-trace\",\"ip\":\"9.9.9.9\"}";

    RequestContext ctx = RequestContext.of("1.2.3.4", "real-trace", embeddedJson);

    JsonNode node = JSON.readTree(ctx.toMetadataJson());

    assertThat(fieldNames(node)).containsExactlyInAnyOrder("traceId", "ip", "userAgent");
    assertThat(node.get("traceId").asText()).isEqualTo("real-trace");
    assertThat(node.get("ip").asText()).isEqualTo("1.2.3.4");
    assertThat(node.get("userAgent").asText()).isEqualTo(embeddedJson);
  }

  @Test
  void should_omitUserAgentKey_when_userAgentIsNull() throws Exception {
    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", null);

    JsonNode node = JSON.readTree(ctx.toMetadataJson());

    assertThat(fieldNames(node)).containsExactlyInAnyOrder("traceId", "ip");
    assertThat(node.has("userAgent")).isFalse();
  }

  // ---------------------------------------------------------------------
  // T-T2 — multi-byte-safe, character-based 512 truncation
  // ---------------------------------------------------------------------

  @Test
  void should_returnUserAgentUnchanged_when_underCap() {
    String shortUa = "Mozilla/5.0 (Windows NT 10.0)";

    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", shortUa);

    assertThat(ctx.userAgent()).isEqualTo(shortUa);
  }

  @Test
  void should_returnUserAgentUnchanged_when_exactly512Characters() {
    String exact512 = "a".repeat(512);

    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", exact512);

    assertThat(ctx.userAgent()).hasSize(512);
    assertThat(ctx.userAgent()).isEqualTo(exact512);
  }

  @Test
  void should_truncateToExactly512Characters_when_overCap() {
    String over = "a".repeat(600);

    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", over);

    assertThat(ctx.userAgent()).hasSize(512);
    assertThat(ctx.userAgent()).isEqualTo("a".repeat(512));
  }

  @Test
  void should_notSplitSurrogatePair_when_truncationBoundaryFallsMidCodePoint() {
    // Build a 511-char ASCII prefix, then a 2-char (UTF-16 surrogate pair) emoji straddling the
    // 511/512 boundary, then more filler -- the naive substring(0, 512) would cut the pair
    // in half and leave a lone unpaired surrogate (invalid UTF-16 / cannot re-encode to UTF-8).
    String prefix = "a".repeat(511);
    String emoji = "😀"; // U+1F600 GRINNING FACE, 2 UTF-16 chars
    String suffix = "b".repeat(50);
    String ua = prefix + emoji + suffix;

    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", ua);
    String result = ctx.userAgent();

    assertThat(result.length()).isLessThanOrEqualTo(512);
    // The result must not end in a lone high surrogate (which would indicate a split pair).
    char lastChar = result.charAt(result.length() - 1);
    assertThat(Character.isHighSurrogate(lastChar)).isFalse();
    // The result must round-trip cleanly through UTF-8 with no replacement characters.
    byte[] utf8Bytes = result.getBytes(UTF_8);
    String roundTripped = new String(utf8Bytes, UTF_8);
    assertThat(roundTripped).isEqualTo(result);
    assertThat(roundTripped).doesNotContain("�"); // U+FFFD REPLACEMENT CHARACTER
  }

  @Test
  void should_omitUserAgentKey_when_userAgentIsNullEvenAfterOfFactory() {
    RequestContext ctx = RequestContext.of("1.2.3.4", "trace-1", null);

    assertThat(ctx.userAgent()).isNull();
  }

  private static Set<String> fieldNames(JsonNode node) {
    Set<String> names = new java.util.HashSet<>();
    node.fieldNames().forEachRemaining(names::add);
    return names;
  }
}
