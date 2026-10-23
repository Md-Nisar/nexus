package com.example.nexus.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumMap;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * US-019 B7 (design §9.2): every internal {@link DenialReason} has exactly one wire value, and the
 * opaque cases never say more than {@code UNSPECIFIED} (T-I22, RES-47).
 */
@Tag("UnitTest")
class CallerFacingDenialReasonTest {

  private static final Map<DenialReason, CallerFacingDenialReason> EXPECTED =
      new EnumMap<>(Map.of(
          DenialReason.GRANT_EXCEEDS_CALLER, CallerFacingDenialReason.GRANT_EXCEEDS_CALLER,
          DenialReason.SELF_ASSIGNMENT, CallerFacingDenialReason.SELF_ASSIGNMENT,
          DenialReason.NOT_TENANT_ADMIN, CallerFacingDenialReason.ADMINISTRATOR_REQUIRED,
          DenialReason.PERMISSION_ABSENT, CallerFacingDenialReason.UNSPECIFIED,
          DenialReason.MALFORMED_AUTHENTICATION, CallerFacingDenialReason.UNSPECIFIED,
          DenialReason.MISSING_TENANT, CallerFacingDenialReason.UNSPECIFIED,
          DenialReason.CROSS_TENANT_TARGET, CallerFacingDenialReason.UNSPECIFIED));

  @Test
  void should_listAnExpectedWireValueForEveryDenialReason_when_theEnumGrows() {
    assertThat(EXPECTED.keySet()).containsExactlyInAnyOrder(DenialReason.values());
  }

  @ParameterizedTest
  @EnumSource(DenialReason.class)
  void should_mapToTheDesignedWireValue_when_givenEachDenialReason(DenialReason reason) {
    assertThat(CallerFacingDenialReason.of(reason)).isEqualTo(EXPECTED.get(reason));
  }

  @Test
  void should_exposeOnlyTheFourDesignedWireValues_when_enumerated() {
    assertThat(CallerFacingDenialReason.values())
        .extracting(Enum::name)
        .containsExactlyInAnyOrder(
            "GRANT_EXCEEDS_CALLER", "SELF_ASSIGNMENT", "ADMINISTRATOR_REQUIRED", "UNSPECIFIED");
  }
}
