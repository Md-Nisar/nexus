package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/** Unit tests for {@link BreakGlassAlertAdapter} (US-018 A7, ADR-0025 6). */
@Tag("UnitTest")
class BreakGlassAlertAdapterTest {

  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID TARGET_USER_ID = UUID.randomUUID();

  private final BreakGlassAlertAdapter adapter = new BreakGlassAlertAdapter();
  private ListAppender<ILoggingEvent> appender;

  @BeforeEach
  void setUp() {
    Logger logger = (Logger) LoggerFactory.getLogger(BreakGlassAlertAdapter.class);
    appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
  }

  @AfterEach
  void tearDown() {
    Logger logger = (Logger) LoggerFactory.getLogger(BreakGlassAlertAdapter.class);
    logger.detachAppender(appender);
    appender.stop();
  }

  @Test
  void should_logOneErrorWithMarkerAndAllFields_when_grantAlertRaised() {
    adapter.raise(
        new BreakGlassAlert(TENANT_ID, TARGET_USER_ID, BreakGlassAlert.OUTCOME_GRANTED, null, "OPS-1"));

    assertThat(appender.list).hasSize(1);
    ILoggingEvent logged = appender.list.get(0);
    assertThat(logged.getLevel()).isEqualTo(Level.ERROR);
    assertThat(logged.getFormattedMessage())
        .startsWith("RBAC_BREAK_GLASS_USED")
        .contains("outcome=GRANTED")
        .contains("tenantId=" + TENANT_ID)
        .contains("targetUserId=" + TARGET_USER_ID)
        .contains("changeRef=OPS-1")
        .doesNotContain("reason=");
  }

  @Test
  void should_carryReason_when_refusalAlertRaised() {
    adapter.raise(
        new BreakGlassAlert(
            TENANT_ID, TARGET_USER_ID, BreakGlassAlert.OUTCOME_REFUSED, "TENANT_HAS_ADMIN", "OPS-1"));

    assertThat(appender.list.get(0).getFormattedMessage())
        .contains("outcome=REFUSED")
        .contains("reason=TENANT_HAS_ADMIN");
  }

  @Test
  void should_omitTargetAndChangeRefAndTenant_when_theyAreNull() {
    adapter.raise(
        new BreakGlassAlert(null, null, BreakGlassAlert.OUTCOME_REFUSED, "INVALID_ARGUMENT", null));

    String message = appender.list.get(0).getFormattedMessage();
    assertThat(message)
        .isEqualTo("RBAC_BREAK_GLASS_USED outcome=REFUSED reason=INVALID_ARGUMENT");
    assertThat(appender.list.get(0).getKeyValuePairs())
        .extracting(kv -> kv.key)
        .containsExactlyInAnyOrder("event", "outcome", "reason");
  }

  @Test
  void should_emitMarkerAsEventKeyValue_for_structuredAppenders() {
    adapter.raise(new BreakGlassAlert(null, null, BreakGlassAlert.OUTCOME_REFUSED, "WEB_CONTEXT", null));

    assertThat(appender.list.get(0).getKeyValuePairs())
        .anySatisfy(
            kv -> {
              assertThat(kv.key).isEqualTo("event");
              assertThat(kv.value).isEqualTo("RBAC_BREAK_GLASS_USED");
            });
  }
}
