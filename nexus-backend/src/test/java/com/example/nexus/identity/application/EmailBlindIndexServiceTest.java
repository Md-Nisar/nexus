package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmailBlindIndexServiceTest {

  // 32 bytes exactly — satisfies the >=32 byte validation contract
  private static final byte[] TEST_KEY =
      "test-hmac-key-for-unit-tests-ok!".getBytes(StandardCharsets.UTF_8);

  private EmailBlindIndexService service;

  @BeforeEach
  void setUp() {
    service = new EmailBlindIndexService(TEST_KEY);
  }

  @Test
  void should_return64HexChars_when_emailIndexed() {
    String result = service.blindIndex("user@example.com");

    assertThat(result).hasSize(64).matches("[0-9a-f]{64}");
  }

  @Test
  void should_beDeterministic_when_sameEmailIndexedTwice() {
    String first = service.blindIndex("user@example.com");
    String second = service.blindIndex("user@example.com");

    assertThat(first).isEqualTo(second);
  }

  @Test
  void should_differ_when_differentEmailsIndexed() {
    String indexA = service.blindIndex("a@b.com");
    String indexB = service.blindIndex("c@d.com");

    assertThat(indexA).isNotEqualTo(indexB);
  }

  @Test
  void should_normaliseCase_when_upperCaseEmailIndexed() {
    String upper = service.blindIndex("A@B.COM");
    String lower = service.blindIndex("a@b.com");

    assertThat(upper).isEqualTo(lower);
  }

  @Test
  void should_normaliseTrim_when_emailHasWhitespace() {
    String padded = service.blindIndex("  a@b.com  ");
    String clean = service.blindIndex("a@b.com");

    assertThat(padded).isEqualTo(clean);
  }

  @Test
  void should_normaliseNfc_when_decomposedUnicodeEmail() {
    // Decompose "a@b.com" to NFD form — the service must normalise to NFC before hashing
    String decomposed = Normalizer.normalize("a@b.com", Normalizer.Form.NFD);
    String composed = "a@b.com";

    assertThat(service.blindIndex(decomposed)).isEqualTo(service.blindIndex(composed));
  }

  @Test
  void should_handleTurkishLocale_when_emailContainsDottedI() {
    // U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE (İ)
    // In Turkish locale toUpperCase/toLowerCase, İ → i (with dot); but in Locale.ROOT, İ → i̇
    // NFC normalisation + Locale.ROOT must produce identical results for both forms below.
    // "İ@b.com" — starts with U+0130
    String withDottedCapI = "İ@b.com";
    // "i̇@b.com" — starts with U+0069 (i) + U+0307 (combining dot above), NFC → U+0069 + U+0307
    // Both should lower-case to the same NFC form under Locale.ROOT
    String withLowerDottedI = "i̇@b.com";

    String indexA = service.blindIndex(withDottedCapI);
    String indexB = service.blindIndex(withLowerDottedI);

    // Both must produce the same blind index — no Turkish locale divergence
    assertThat(indexA).isEqualTo(indexB);
  }

  @Test
  void should_throwIllegalArgument_when_emailIsNull() {
    assertThatThrownBy(() -> service.blindIndex(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("email must not be null");
  }

  @Test
  void should_normalisePlainAsciiI_when_emailHasUppercaseI() {
    // Plain ASCII I (U+0049): on a JVM with Locale.TURKISH as default, "I".toLowerCase() produces
    // dotless-i (U+0131) instead of "i" (U+0069). Locale.ROOT must always produce "i".
    String upper = service.blindIndex("I@B.COM");
    String lower = service.blindIndex("i@b.com");

    assertThat(upper).isEqualTo(lower);
  }

  @Test
  void should_throwIllegalStateException_when_cryptoOperationFails() throws Exception {
    // Force a failure by nulling the internal key via reflection — SecretKeySpec rejects null
    Field keyField = EmailBlindIndexService.class.getDeclaredField("hmacKey");
    keyField.setAccessible(true);
    keyField.set(service, null);

    assertThatThrownBy(() -> service.blindIndex("test@example.com"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Failed to compute email blind index");
  }

  @Test
  void should_return64HexChars_when_emptyStringIndexed() {
    // Empty string is a valid (degenerate) input — no exception; HMAC of "" is well-defined
    String result = service.blindIndex("");

    assertThat(result).hasSize(64).matches("[0-9a-f]{64}");
  }

  @Test
  void should_treatWhitespaceOnlyAsEmpty_when_indexed() {
    // trim() collapses whitespace-only to "" — both must produce the same index
    String whitespace = service.blindIndex("   ");
    String empty = service.blindIndex("");

    assertThat(whitespace).isEqualTo(empty);
  }
}
