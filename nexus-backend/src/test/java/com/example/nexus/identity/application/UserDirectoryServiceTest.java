package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.application.port.out.UserDirectoryQueryPort;
import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserStatus;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * US-019 T-004 (design §4.2): tenant-scoped reads, the by-id miss path that runs {@code existsById}
 * on every miss, and the batch parity count that only ever feeds the cross-tenant WARN.
 */
@Tag("UnitTest")
class UserDirectoryServiceTest {

  private static final String CROSS_TENANT_MISS = "nexus.identity.directory.cross_tenant_miss";
  private static final UUID TENANT = UUID.fromString("019f6839-0000-7000-8000-0000000000a1");
  private static final UUID ACTOR = UUID.fromString("019f6839-0000-7000-8000-0000000000a2");
  private static final UUID USER_1 = UUID.fromString("019f6839-0000-7000-8000-0000000000b1");
  private static final UUID USER_2 = UUID.fromString("019f6839-0000-7000-8000-0000000000b2");
  private static final UUID FOREIGN = UUID.fromString("019f6839-0000-7000-8000-0000000000c1");

  private final UserDirectoryQueryPort port = mock(UserDirectoryQueryPort.class);
  private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
  private final UserDirectoryService service = new UserDirectoryService(port, meterRegistry);

  private ListAppender<ILoggingEvent> appender;

  @BeforeEach
  void startLogCapture() {
    appender = new ListAppender<>();
    appender.start();
    logger().addAppender(appender);
  }

  @AfterEach
  void stopLogCapture() {
    logger().detachAppender(appender);
    appender.stop();
  }

  // ── list ──────────────────────────────────────────────────────────────────────────────

  @Test
  void should_returnThePortsTenantScopedPage_when_listing() {
    DirectoryPage<DirectoryUserView> page = new DirectoryPage<>(List.of(view(USER_1)), 41, 2, 20);
    when(port.findPageByTenant(TENANT, UserStatus.DISABLED, 2, 20)).thenReturn(page);

    assertThat(service.list(TENANT, UserStatus.DISABLED, 2, 20)).isSameAs(page);
  }

  @Test
  void should_passNoStatus_when_listingWithoutAFilter() {
    DirectoryPage<DirectoryUserView> page = new DirectoryPage<>(List.of(), 0, 0, 20);
    when(port.findPageByTenant(TENANT, null, 0, 20)).thenReturn(page);

    assertThat(service.list(TENANT, null, 0, 20)).isSameAs(page);
  }

  // ── by id ─────────────────────────────────────────────────────────────────────────────

  @Test
  void should_returnTheUserWithoutAnExistenceProbe_when_theIdIsInTheCallersTenant() {
    when(port.findByTenantAndId(TENANT, USER_1)).thenReturn(Optional.of(view(USER_1)));

    assertThat(service.get(TENANT, ACTOR, USER_1)).isEqualTo(view(USER_1));
    verify(port, never()).existsById(any());
  }

  @Test
  void should_throwUserNotFoundWithoutWarn_when_theIdDoesNotExist() {
    when(port.findByTenantAndId(TENANT, FOREIGN)).thenReturn(Optional.empty());
    when(port.existsById(FOREIGN)).thenReturn(false);

    assertThatThrownBy(() -> service.get(TENANT, ACTOR, FOREIGN))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");
    verify(port).existsById(FOREIGN);
    assertThat(warnings()).isEmpty();
    assertThat(crossTenantMisses()).isZero();
  }

  @Test
  void should_throwTheSameUserNotFoundAndWarn_when_theIdBelongsToAnotherTenant() {
    when(port.findByTenantAndId(TENANT, FOREIGN)).thenReturn(Optional.empty());
    when(port.existsById(FOREIGN)).thenReturn(true);
    UUID missing = UUID.fromString("019f6839-0000-7000-8000-0000000000d1");
    when(port.findByTenantAndId(TENANT, missing)).thenReturn(Optional.empty());

    Throwable foreign = catchThrowable(() -> service.get(TENANT, ACTOR, FOREIGN));
    Throwable absent = catchThrowable(() -> service.get(TENANT, ACTOR, missing));

    assertThat(foreign).isInstanceOf(ResourceNotFoundException.class);
    assertThat(foreign).hasMessage(absent.getMessage());
    assertThat(((ResourceNotFoundException) foreign).code())
        .isEqualTo(((ResourceNotFoundException) absent).code());
    assertThat(warnings())
        .singleElement()
        .satisfies(
            event ->
                assertThat(keyValues(event))
                    .containsEntry("event", "IDENTITY_DIRECTORY_CROSS_TENANT_TARGET")
                    .containsEntry("operation", "GET")
                    .containsEntry("tenantId", TENANT)
                    .containsEntry("actorUserId", ACTOR)
                    .doesNotContainKey("targetUserId"));
    assertThat(crossTenantMisses()).isEqualTo(1.0);
  }

  // ── batch ─────────────────────────────────────────────────────────────────────────────

  @Test
  void should_returnOnlyTheTenantScopedRowsWithoutWarn_when_everyIdIsInTheCallersTenant() {
    List<UUID> ids = List.of(USER_1, USER_2);
    when(port.findByTenantAndIds(TENANT, ids)).thenReturn(List.of(view(USER_1), view(USER_2)));
    when(port.countByIdIn(ids)).thenReturn(2L);

    assertThat(service.batch(TENANT, ACTOR, ids)).containsExactly(view(USER_1), view(USER_2));
    assertThat(warnings()).isEmpty();
    assertThat(crossTenantMisses()).isZero();
  }

  @Test
  void should_runTheParityCountOnEveryBatch_when_nothingIsOmitted() {
    List<UUID> ids = List.of(USER_1);
    when(port.findByTenantAndIds(TENANT, ids)).thenReturn(List.of(view(USER_1)));
    when(port.countByIdIn(ids)).thenReturn(1L);

    service.batch(TENANT, ACTOR, ids);

    verify(port).countByIdIn(ids);
  }

  @Test
  void should_returnTheUnchangedTenantScopedRowsAndWarnWithOmittedCount_when_idsAreForeign() {
    List<UUID> ids = List.of(USER_1, FOREIGN, USER_2);
    when(port.findByTenantAndIds(TENANT, ids)).thenReturn(List.of(view(USER_1)));
    when(port.countByIdIn(ids)).thenReturn(3L);

    assertThat(service.batch(TENANT, ACTOR, ids))
        .as("the unscoped count never feeds the response (RC-61.2)")
        .containsExactly(view(USER_1));
    assertThat(warnings())
        .singleElement()
        .satisfies(
            event ->
                assertThat(keyValues(event))
                    .containsEntry("event", "IDENTITY_DIRECTORY_CROSS_TENANT_TARGET")
                    .containsEntry("operation", "BATCH")
                    .containsEntry("omittedCount", 2L)
                    .containsEntry("tenantId", TENANT)
                    .containsEntry("actorUserId", ACTOR));
    assertThat(crossTenantMisses()).isEqualTo(1.0);
  }

  @Test
  void should_notWarn_when_omittedIdsDoNotExistAnywhere() {
    List<UUID> ids = List.of(USER_1, FOREIGN);
    when(port.findByTenantAndIds(TENANT, ids)).thenReturn(List.of(view(USER_1)));
    when(port.countByIdIn(ids)).thenReturn(1L);

    assertThat(service.batch(TENANT, ACTOR, ids)).containsExactly(view(USER_1));
    assertThat(warnings()).isEmpty();
    assertThat(crossTenantMisses()).isZero();
  }

  // ── view ──────────────────────────────────────────────────────────────────────────────

  @Test
  void should_redactTheEmail_when_aViewIsPrinted() {
    assertThat(view(USER_1).toString()).doesNotContain("reader@example.test", "reader");
  }

  // ── helpers ───────────────────────────────────────────────────────────────────────────

  private static DirectoryUserView view(UUID id) {
    return new DirectoryUserView(
        id,
        "reader@example.test",
        UserStatus.ACTIVE,
        Instant.parse("2026-01-02T03:04:05Z"),
        Instant.parse("2026-01-01T00:00:00Z"));
  }

  private static Throwable catchThrowable(
      org.assertj.core.api.ThrowableAssert.ThrowingCallable call) {
    return org.assertj.core.api.Assertions.catchThrowable(call);
  }

  private double crossTenantMisses() {
    var counter = meterRegistry.find(CROSS_TENANT_MISS).counter();
    return counter == null ? 0.0 : counter.count();
  }

  private List<ILoggingEvent> warnings() {
    return appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }

  private static Logger logger() {
    return (Logger) LoggerFactory.getLogger(UserDirectoryService.class);
  }
}
