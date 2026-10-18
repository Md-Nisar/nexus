package com.example.nexus.rbac.interfaces.rest.dto;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Bean Validation-only tests for {@link UpdateRoleRequest} (US-018 T-027): an empty body, both
 * fields null, oversize and bad-pattern values are violations; the boundaries pass.
 */
@Tag("UnitTest")
class UpdateRoleRequestTest {

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

  private static Set<ConstraintViolation<UpdateRoleRequest>> violations(
      String name, String description) {
    return validator.validate(new UpdateRoleRequest(name, description));
  }

  @Test
  void should_reject_when_bothFieldsAreNull() {
    assertThat(violations(null, null))
        .extracting(v -> v.getPropertyPath().toString())
        .containsExactly("atLeastOneFieldPresent");
  }

  @Test
  void should_accept_when_onlyTheNameIsPresent() {
    assertThat(violations("Billing Manager", null)).isEmpty();
  }

  @Test
  void should_accept_when_onlyTheDescriptionIsPresent() {
    assertThat(violations(null, "Manages invoices")).isEmpty();
  }

  /** An empty description is valid: it clears the description. */
  @Test
  void should_accept_when_theDescriptionIsEmpty() {
    assertThat(violations(null, "")).isEmpty();
  }

  @Test
  void should_reject_when_theNameIsEmpty() {
    assertThat(violations("", null)).isNotEmpty();
  }

  @Test
  void should_acceptTheBoundaries_when_nameIs64AndDescriptionIs255Characters() {
    assertThat(violations("a".repeat(64), "d".repeat(255))).isEmpty();
  }

  @Test
  void should_reject_when_theNameIs65Characters() {
    assertThat(violations("a".repeat(65), null))
        .extracting(v -> v.getPropertyPath().toString())
        .containsExactly("name");
  }

  @Test
  void should_reject_when_theDescriptionIs256Characters() {
    assertThat(violations(null, "d".repeat(256)))
        .extracting(v -> v.getPropertyPath().toString())
        .containsExactly("description");
  }

  @ParameterizedTest
  @ValueSource(strings = {" leading", "-leading", "bad\nname", "bad\rname", "semi;colon", "<b>"})
  void should_reject_when_theNameBreaksTheAllowList(String name) {
    assertThat(violations(name, null))
        .extracting(v -> v.getPropertyPath().toString())
        .contains("name");
  }

  @Test
  void should_reject_when_theDescriptionHasControlCharactersOrLineSeparators() {
    assertThat(violations(null, "line\nbreak")).isNotEmpty();
    assertThat(violations(null, "sep" + Character.toString(0x2028))).isNotEmpty();
    assertThat(violations(null, "sep" + Character.toString(0x2029))).isNotEmpty();
  }
}
