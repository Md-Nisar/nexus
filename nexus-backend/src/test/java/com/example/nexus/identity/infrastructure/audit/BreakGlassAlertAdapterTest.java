package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert.Outcome;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * US-018 T-007 (03-design.md §7.2): every break-glass invocation emits one ERROR {@code
 * RBAC_BREAK_GLASS_USED} — the log-based page.
 */
@Tag("UnitTest")
class BreakGlassAlertAdapterTest {

  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID TARGET_USER_ID = UUID.randomUUID();

  private final BreakGlassAlertAdapter adapter = new BreakGlassAlertAdapter();
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

  @Test
  void should_logErrorWithRbacBreakGlassUsedMarkerAndAllFields_when_granted() {
    adapter.alert(new BreakGlassAlert(TENANT_ID, TARGET_USER_ID, Outcome.GRANTED, null, "OPS-1"));

    ILoggingEvent event = singleErrorEvent();
    assertThat(keyValueMap(event))
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("tenantId", TENANT_ID)
        .containsEntry("targetUserId", TARGET_USER_ID)
        .containsEntry("outcome", "GRANTED")
        .containsEntry("changeRef", "OPS-1")
        .doesNotContainKey("reason");
  }

  @Test
  void should_logErrorWithReason_when_refused() {
    adapter.alert(
        new BreakGlassAlert(TENANT_ID, TARGET_USER_ID, Outcome.REFUSED, "TENANT_HAS_ADMIN", "OPS-1"));

    assertThat(keyValueMap(singleErrorEvent()))
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", "TENANT_HAS_ADMIN");
  }

  @Test
  void should_omitNullFields_when_tenantOrTargetUnknown() {
    adapter.alert(new BreakGlassAlert(null, null, Outcome.REFUSED, "TARGET_USER_NOT_FOUND", null));

    Map<String, Object> keyValues = keyValueMap(singleErrorEvent());
    assertThat(keyValues)
        .doesNotContainKeys("tenantId", "targetUserId", "changeRef")
        .containsEntry("reason", "TARGET_USER_NOT_FOUND");
    assertThat(keyValues.values()).doesNotContainNull();
  }

  @Test
  void should_notThrow_when_logging() {
    assertThatCode(() -> adapter.alert(new BreakGlassAlert(null, null, null, null, null)))
        .doesNotThrowAnyException();
    assertThat(singleErrorEvent()).isNotNull();
  }

  private ILoggingEvent singleErrorEvent() {
    List<ILoggingEvent> errors =
        appender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
    assertThat(errors).hasSize(1);
    return errors.get(0);
  }

  private static Logger logger() {
    return (Logger) LoggerFactory.getLogger(BreakGlassAlertAdapter.class);
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }
}
