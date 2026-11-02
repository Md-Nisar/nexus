package com.example.nexus.rbac.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.domain.FieldValidationException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

/** Boundary values of the shared {@code page}/{@code size} rule (api-design: default 20, max 100). */
@Tag("UnitTest")
class PageParamsTest {

  @Test
  void should_defaultToPage0Size20_when_bothAbsent() {
    assertThat(PageParams.parse(null, null)).isEqualTo(new PageParams(0, 20));
  }

  @ParameterizedTest
  @NullAndEmptySource
  void should_useTheDefaults_when_theValuesAreNullOrEmpty(String raw) {
    assertThat(PageParams.parse(raw, raw)).isEqualTo(new PageParams(0, 20));
  }

  @ParameterizedTest
  @CsvSource({"0,1", "0,100", "7,50", "2147483647,20"})
  void should_accept_when_withinTheBoundaries(String page, String size) {
    PageParams parsed = PageParams.parse(page, size);

    assertThat(parsed.page()).isEqualTo(Integer.parseInt(page));
    assertThat(parsed.size()).isEqualTo(Integer.parseInt(size));
  }

  @Test
  void should_reject_size_exceeding_maximum_allowed_limit_preventing_unbounded_allocation() {
    assertThatThrownBy(() -> PageParams.parse("0", "1000000"))
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> {
              assertThat(e.code()).isEqualTo("VALIDATION_FAILED");
              assertThat(e.field()).isEqualTo("size");
            });
  }

  @ParameterizedTest
  @CsvSource({"-1,20,page", "x,20,page", "1.5,20,page", "0,0,size", "0,101,size", "0,-1,size", "0,abc,size"})
  void should_rejectWithTheOffendingField_when_outOfRangeOrNotAnInteger(
      String page, String size, String field) {
    assertThatThrownBy(() -> PageParams.parse(page, size))
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> {
              assertThat(e.code()).isEqualTo("VALIDATION_FAILED");
              assertThat(e.field()).isEqualTo(field);
            });
  }
}
