package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Pins the Redis key shapes that the Java adapters and the Lua scripts must agree on (ADR 0016 D3,
 * US-018 design §9.2, §9.4): a drift would make the script's DEL miss the entry a mint wrote.
 */
@Tag("UnitTest")
class RbacRedisKeysTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID USER = UUID.fromString("00000000-0000-7000-8000-0000000000bb");

  private final RbacRedisKeys keys = new RbacRedisKeys("nexus-test");

  @Test
  void should_buildTenantScopedEpochKey() {
    assertThat(keys.epoch(TENANT, USER))
        .isEqualTo("nexus-test:rbac:epoch:" + TENANT + ":" + USER);
  }

  @Test
  void should_appendEpochToStem_when_buildingCacheKeys() {
    assertThat(keys.roleset(TENANT, USER, 1_796_000_000_000L))
        .isEqualTo(keys.rolesetStem(TENANT, USER) + "1796000000000");
    assertThat(keys.permset(TENANT, USER, 0L)).isEqualTo(keys.permsetStem(TENANT, USER) + "0");
  }

  @Test
  void should_separateRolesetFromPermsetAndTenantFromTenant() {
    UUID otherTenant = UUID.fromString("00000000-0000-7000-8000-0000000000ab");

    assertThat(keys.rolesetStem(TENANT, USER)).isNotEqualTo(keys.permsetStem(TENANT, USER));
    assertThat(keys.permsetStem(TENANT, USER)).isNotEqualTo(keys.permsetStem(otherTenant, USER));
    assertThat(keys.epoch(TENANT, USER)).isNotEqualTo(keys.epoch(otherTenant, USER));
  }

  @Test
  void should_renderSixteenDigitEpochAsPlainDigits() {
    assertThat(keys.permset(TENANT, USER, RedisPermissionEpochAdapter.MAX_EPOCH))
        .endsWith(":9007199254740990");
  }
}
