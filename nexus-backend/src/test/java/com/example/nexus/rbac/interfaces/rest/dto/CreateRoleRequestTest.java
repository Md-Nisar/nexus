package com.example.nexus.rbac.interfaces.rest.dto;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Bean Validation-only tests for {@link CreateRoleRequest} (03-design.md §8.1/D6,
 * threat-model.md T-T8/T-T9/RC-3). No MockMvc, no controller — this class exists to prove the
 * {@code @Pattern} allow-lists reject the adversarial corpus at the DTO layer, independent of
 * whichever downstream sink (Jackson-serialised audit JSON, structured logs) they defend.
 *
 * <p>Adversarial characters are built via {@link Character#toString(int)} rather than embedded as
 * raw source-file Unicode escapes, so the corpus is unambiguous regardless of editor/tooling
 * Unicode-escape handling.
 */
@Tag("UnitTest")
class CreateRoleRequestTest {

  private static ValidatorFactory factory;
  private static Validator validator;

  @BeforeAll
  static void setUpValidator() {
    factory = Validation.buildDefaultValidatorFactory();
    validator = factory.getValidator();
  }

  @AfterAll
  static void tearDownValidator() {
    factory.close();
  }

  /**
   * The subset of the mandated adversarial corpus that {@code description}'s broader RC-3 pattern
   * ({@code ^[^\p{Cntrl}  ]*$}) actually excludes: control characters, U+2028 LINE
   * SEPARATOR, U+2029 PARAGRAPH SEPARATOR. Deliberately does NOT include quotes/backslash —
   * threat-model.md T-T9 is explicit that {@code description}'s allow-list is intentionally
   * broader than {@code name}'s and permits both, relying on Jackson (not this pattern) as the
   * sole defence for those two characters.
   */
  static Stream<Arguments> descriptionAdversarialStrings() {
    return Stream.of(
        Arguments.of("BEL control char", "has" + Character.toString(0x0007) + "a bell"),
        Arguments.of("NUL control char", "has" + Character.toString(0x0000) + "a nul"),
        Arguments.of("DEL control char", "has" + Character.toString(0x007F) + "a del"),
        Arguments.of(
            "U+2028 line separator", "has" + Character.toString(0x2028) + "a line separator"),
        Arguments.of(
            "U+2029 paragraph separator",
            "has" + Character.toString(0x2029) + "a paragraph separator"));
  }

  /** The full mandated adversarial corpus (threat-model.md T-T8): quotes, backslashes, control
   * characters, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR — all excluded by {@code
   * name}'s strict ASCII allow-list. */
  static Stream<Arguments> nameAdversarialStrings() {
    return Stream.concat(
        Stream.of(
            Arguments.of("double-quote", "has \"a quote\""),
            Arguments.of("backslash", "has \\a backslash")),
        descriptionAdversarialStrings());
  }

  // ── description: broader RC-3 pattern, adversarial corpus ──────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("descriptionAdversarialStrings")
  void should_rejectDescription_when_containsAdversarialCharacter(String label, String description) {
    CreateRoleRequest request = new CreateRoleRequest("Billing Manager", description);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations)
        .as(label)
        .anyMatch(v -> v.getPropertyPath().toString().equals("description"));
  }

  @Test
  void should_acceptDescription_when_ordinaryProse() {
    CreateRoleRequest request =
        new CreateRoleRequest("Billing Manager", "Manages invoices and payment methods, 24/7.");

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).isEmpty();
  }

  @Test
  void should_acceptDescription_when_null() {
    CreateRoleRequest request = new CreateRoleRequest("Billing Manager", null);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).isEmpty();
  }

  /**
   * Documents the known, deliberate gap RC-3/T-T9 discusses: {@code description}'s pattern does
   * NOT exclude quotes or backslashes (unlike {@code name}'s) — Jackson is the sole defence for
   * those two characters on this field. If this test starts failing because the pattern was
   * tightened, that's fine; it should not fail because the pattern silently loosened elsewhere.
   */
  @Test
  void should_acceptDescription_when_containingQuotesAndBackslashes() {
    CreateRoleRequest request =
        new CreateRoleRequest("Billing Manager", "Has \"quotes\" and a \\backslash");

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).isEmpty();
  }

  // ── name: stricter D6 allow-list, full adversarial corpus ──────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("nameAdversarialStrings")
  void should_rejectName_when_containsAdversarialCharacter(String label, String name) {
    CreateRoleRequest request = new CreateRoleRequest(name, null);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations)
        .as(label)
        .anyMatch(v -> v.getPropertyPath().toString().equals("name"));
  }

  @Test
  void should_rejectName_when_leadingSpace() {
    CreateRoleRequest request = new CreateRoleRequest(" Billing Manager", null);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).anyMatch(v -> v.getPropertyPath().toString().equals("name"));
  }

  @Test
  void should_rejectName_when_blank() {
    CreateRoleRequest request = new CreateRoleRequest("", null);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).anyMatch(v -> v.getPropertyPath().toString().equals("name"));
  }

  @Test
  void should_rejectName_when_over64Characters() {
    CreateRoleRequest request = new CreateRoleRequest("A".repeat(65), null);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).anyMatch(v -> v.getPropertyPath().toString().equals("name"));
  }

  @Test
  void should_acceptName_when_ordinaryAllowedCharacters() {
    CreateRoleRequest request = new CreateRoleRequest("Billing Manager v2.1_ops-team", null);

    Set<ConstraintViolation<CreateRoleRequest>> violations = validator.validate(request);

    assertThat(violations).isEmpty();
  }
}
