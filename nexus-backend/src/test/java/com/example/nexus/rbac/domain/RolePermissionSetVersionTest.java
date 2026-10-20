package com.example.nexus.rbac.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * US-019 T-018 (design §10.2, T-T22): the permission-set ETag is a strong, order-independent,
 * role-bound content hash. The expected vectors were computed outside Java (Python {@code hashlib}
 * over the 16-byte big-endian ids), so they pin the byte layout and the unsigned id order.
 */
@Tag("UnitTest")
class RolePermissionSetVersionTest {

  // Arbitrary ids, deliberately not the seeded ones (SeededPermissionLiteralScanTest).
  private static final UUID ROLE = UUID.fromString("019f6839-2810-7000-8000-00000000000a");
  private static final UUID PERMISSION_A = UUID.fromString("019f6839-2804-7000-8000-000000000005");
  private static final UUID PERMISSION_B = UUID.fromString("019f6839-2805-7000-8000-000000000006");

  @Test
  void should_matchTheStableVector_when_hashingTwoPermissions() {
    assertThat(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_B, PERMISSION_A)))
        .isEqualTo("rp1-MEtcGxqNa5Sd9IJN1N5GnN5OeQUtywOKrSb8JBNcazA");
  }

  @Test
  void should_matchTheStableVector_when_theSetIsEmpty() {
    assertThat(RolePermissionSetVersion.of(ROLE, List.of()))
        .isEqualTo("rp1-lKZi-dfjaeGFZmoNSfrG2orvdT_eJIfwuPTPnluPwLc");
  }

  @Test
  void should_orderIdsAsUnsignedBytes_when_anIdHasTheHighBitSet() {
    UUID role = UUID.fromString("00000000-0000-7000-8000-000000000009");
    UUID high = UUID.fromString("ffffffff-0000-7000-8000-000000000001");
    UUID low = UUID.fromString("00000000-0000-7000-8000-000000000001");

    assertThat(RolePermissionSetVersion.of(role, List.of(high, low)))
        .isEqualTo("rp1-II5o-CUaPzE2JCUM7AqdZ8duskkaPhAVqPtz-iP3tCI");
  }

  @Test
  void should_returnTheSameVersion_when_theIdsArriveInAnotherOrder() {
    assertThat(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A, PERMISSION_B)))
        .isEqualTo(RolePermissionSetVersion.of(ROLE, Set.of(PERMISSION_B, PERMISSION_A)));
  }

  @Test
  void should_differ_when_theSameSetBelongsToAnotherRole() {
    UUID otherRole = UUID.fromString("019f6839-2811-7000-8000-00000000000b");

    assertThat(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A)))
        .isNotEqualTo(RolePermissionSetVersion.of(otherRole, List.of(PERMISSION_A)));
  }

  @Test
  void should_differ_when_onePermissionIsAdded() {
    assertThat(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A)))
        .isNotEqualTo(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A, PERMISSION_B)));
  }

  @Test
  void should_ignoreRepeatedIds_when_theCollectionHasDuplicates() {
    assertThat(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A, PERMISSION_A)))
        .isEqualTo(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A)));
  }

  @Test
  void should_beAnUnpaddedBase64UrlTagWithThePrefix_when_computed() {
    assertThat(RolePermissionSetVersion.of(ROLE, List.of(PERMISSION_A)))
        .matches("rp1-[A-Za-z0-9_-]{43}");
  }
}
