package com.example.nexus.identity.interfaces.rest.dto;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * US-020 follow-up F-5 (widened by D-1): registration must refuse an address that contains a
 * hidden, direction-control or look-alike space character, because the console and the audit
 * surfaces render addresses and such characters can reorder or hide part of them.
 */
@Tag("UnitTest")
class RegisterRequestValidationTest {

  private static final Validator VALIDATOR =
      Validation.buildDefaultValidatorFactory().getValidator();

  private static String withCodePoint(int codePoint) {
    return "ab" + new String(Character.toChars(codePoint)) + "cd@example.com";
  }

  static Stream<Integer> hiddenCodePoints() {
    return Stream.of(
        0x202E, // right-to-left override
        0x202A, // left-to-right embedding
        0x2066, // left-to-right isolate
        0x200B, // zero width space
        0x200D, // zero width joiner
        0xFEFF, // byte order mark
        0x00AD, // soft hyphen
        0x2060, // word joiner
        0x00A0, // no-break space
        0x3000, // ideographic space
        0x2028, // line separator
        0x2029, // paragraph separator
        0x3164, // hangul filler
        0x034F); // combining grapheme joiner
  }

  @ParameterizedTest
  @MethodSource("hiddenCodePoints")
  void should_rejectAddress_when_itContainsAHiddenOrDirectionCharacter(int codePoint) {
    var request = new RegisterRequest(withCodePoint(codePoint), "a-long-enough-password", true);

    var violations = VALIDATOR.validate(request);

    assertThat(violations).anyMatch(v -> v.getPropertyPath().toString().equals("email"));
  }

  @Test
  void should_acceptAddress_when_itIsPlainAscii() {
    var request = new RegisterRequest("plain.user@example.com", "a-long-enough-password", true);

    assertThat(VALIDATOR.validate(request)).isEmpty();
  }

  @Test
  void should_acceptAddress_when_itHasNonAsciiLettersAndNoHiddenCharacters() {
    var request = new RegisterRequest("josé@example.com", "a-long-enough-password", true);

    assertThat(VALIDATOR.validate(request)).isEmpty();
  }
}
