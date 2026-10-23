package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.interfaces.rest.DirectoryPageRequest.Batch;
import com.example.nexus.identity.interfaces.rest.DirectoryPageRequest.ListPage;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/** US-019 T-004 (design §4.1, §4.2): bounds, {@code ids} parsing and combination rules. */
@Tag("UnitTest")
class DirectoryPageRequestTest {

  private static final String ID_A = "019f6839-0000-7000-8000-00000000000a";
  private static final String ID_B = "019f6839-0000-7000-8000-00000000000b";

  // ── list mode ─────────────────────────────────────────────────────────────────────────

  @Test
  void should_defaultToFirstPageOfTwentyWithoutStatus_when_nothingIsGiven() {
    assertThat(DirectoryPageRequest.parse(null, null, null, null, null))
        .isEqualTo(new ListPage(null, 0, 20));
  }

  @Test
  void should_defaultPageAndSize_when_theyAreEmpty() {
    assertThat(DirectoryPageRequest.parse(null, "", "", null, null))
        .isEqualTo(new ListPage(null, 0, 20));
  }

  @ParameterizedTest
  @EnumSource(UserStatus.class)
  void should_acceptStatus_when_itIsAnEnumValue(UserStatus status) {
    assertThat(DirectoryPageRequest.parse(status.name(), "1", "50", null, null))
        .isEqualTo(new ListPage(status, 1, 50));
  }

  @ParameterizedTest
  @ValueSource(strings = {"active", "Active", "UNKNOWN", "", " ACTIVE"})
  void should_reject_when_statusIsNotAnEnumValue(String status) {
    assertRejected(() -> DirectoryPageRequest.parse(status, null, null, null, null), "status");
  }

  @ParameterizedTest
  @ValueSource(strings = {"1", "100"})
  void should_acceptSize_when_itIsWithinOneToOneHundred(String size) {
    assertThat(DirectoryPageRequest.parse(null, null, size, null, null))
        .isEqualTo(new ListPage(null, 0, Integer.parseInt(size)));
  }

  @ParameterizedTest
  @ValueSource(strings = {"0", "101", "-1", "abc", "1.5"})
  void should_rejectRatherThanClamp_when_sizeIsOutOfRangeOrNotAnInteger(String size) {
    assertRejected(() -> DirectoryPageRequest.parse(null, null, size, null, null), "size");
  }

  @ParameterizedTest
  @ValueSource(strings = {"-1", "abc", "99999999999"})
  void should_reject_when_pageIsNegativeOrNotAnInteger(String page) {
    assertRejected(() -> DirectoryPageRequest.parse(null, page, null, null, null), "page");
  }

  @Test
  void should_accept_when_pageTimesSizeIsExactlyTenThousand() {
    assertThat(DirectoryPageRequest.parse(null, "100", "100", null, null))
        .isEqualTo(new ListPage(null, 100, 100));
    assertThat(DirectoryPageRequest.parse(null, "500", "20", null, null))
        .isEqualTo(new ListPage(null, 500, 20));
  }

  @Test
  void should_reject_when_pageTimesSizeExceedsTenThousand() {
    assertRejected(() -> DirectoryPageRequest.parse(null, "501", "20", null, null), "page");
    assertRejected(() -> DirectoryPageRequest.parse(null, "101", "100", null, null), "page");
  }

  @Test
  void should_rejectWithoutOverflow_when_pageIsHuge() {
    assertRejected(
        () -> DirectoryPageRequest.parse(null, String.valueOf(Integer.MAX_VALUE), "100", null, null),
        "page");
  }

  // ── email on GET ──────────────────────────────────────────────────────────────────────

  @ParameterizedTest
  @ValueSource(strings = {"sentinel-local-part@example.test", ""})
  void should_pointToLookupWithoutEchoingTheValue_when_emailIsPresent(String email) {
    assertThatThrownBy(() -> DirectoryPageRequest.parse(null, null, null, null, email))
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> {
              assertThat(e.field()).isEqualTo("email");
              assertThat(e.getMessage()).contains("POST /api/v1/users/lookup");
              assertThat(e.getMessage()).doesNotContain("sentinel", "example.test");
            });
  }

  @Test
  void should_rejectEmail_when_itIsCombinedWithIds() {
    assertRejected(() -> DirectoryPageRequest.parse(null, null, null, ID_A, "x@y.test"), "email");
  }

  // ── ids mode ──────────────────────────────────────────────────────────────────────────

  @Test
  void should_parseBatch_when_idsAreCanonicalUuids() {
    assertThat(DirectoryPageRequest.parse(null, null, null, ID_A + "," + ID_B, null))
        .isEqualTo(new Batch(List.of(UUID.fromString(ID_A), UUID.fromString(ID_B))));
  }

  @Test
  void should_deduplicateIdsKeepingFirstOccurrenceOrder_when_anIdRepeats() {
    assertThat(DirectoryPageRequest.parse(null, null, null, ID_B + "," + ID_A + "," + ID_B, null))
        .isEqualTo(new Batch(List.of(UUID.fromString(ID_B), UUID.fromString(ID_A))));
  }

  @Test
  void should_accept_when_thereAreExactlyOneHundredIds() {
    assertThat(DirectoryPageRequest.parse(null, null, null, ids(100), null))
        .isInstanceOfSatisfying(Batch.class, batch -> assertThat(batch.ids()).hasSize(100));
  }

  @Test
  void should_reject_when_thereAreMoreThanOneHundredIds() {
    assertRejected(() -> DirectoryPageRequest.parse(null, null, null, ids(101), null), "ids");
  }

  @Test
  void should_reject_when_moreThanOneHundredEntriesCollapseToFewerDistinctIds() {
    String repeated = String.join(",", java.util.Collections.nCopies(101, ID_A));
    assertRejected(() -> DirectoryPageRequest.parse(null, null, null, repeated, null), "ids");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        ",",
        "not-a-uuid",
        "019f683900007000800000000000000a",
        "019f6839-0000-7000-8000-00000000000a,",
        "019f6839-0000-7000-8000-00000000000a,,019f6839-0000-7000-8000-00000000000b",
        " 019f6839-0000-7000-8000-00000000000a"
      })
  void should_reject_when_idsAreEmptyOrMalformed(String ids) {
    assertRejected(() -> DirectoryPageRequest.parse(null, null, null, ids, null), "ids");
  }

  @Test
  void should_reject_when_idsAreCombinedWithStatus() {
    assertRejected(() -> DirectoryPageRequest.parse("ACTIVE", null, null, ID_A, null), "ids");
  }

  @Test
  void should_reject_when_idsAreCombinedWithPage() {
    assertRejected(() -> DirectoryPageRequest.parse(null, "0", null, ID_A, null), "ids");
  }

  @Test
  void should_reject_when_idsAreCombinedWithSize() {
    assertRejected(() -> DirectoryPageRequest.parse(null, null, "20", ID_A, null), "ids");
  }

  // ── helpers ───────────────────────────────────────────────────────────────────────────

  private static String ids(int count) {
    return IntStream.range(0, count)
        .mapToObj(i -> String.format("019f6839-0000-7000-8000-%012x", i))
        .collect(Collectors.joining(","));
  }

  private static void assertRejected(
      org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String field) {
    assertThatThrownBy(call)
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> {
              assertThat(e.code()).isEqualTo("VALIDATION_FAILED");
              assertThat(e.field()).isEqualTo(field);
            });
  }
}
