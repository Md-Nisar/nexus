package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.example.nexus.identity.domain.UserDirectoryCeilingExceededException;
import com.example.nexus.identity.domain.UserDirectoryThrottledException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * US-019 T-005/T-006 (design §4.5): the lookup throttle (30 per 60 s, USER_DIR_001) and the
 * per-actor ceiling (600 per 60 s, USER_DIR_002), each with one WARN per window and no PII.
 */
@Tag("UnitTest")
class DirectoryAccessGuardTest {

  private static final UUID TENANT = UUID.fromString("019f6839-0000-7000-8000-0000000000a1");
  private static final UUID ACTOR = UUID.fromString("019f6839-0000-7000-8000-0000000000a2");
  private static final String LOOKUP = "DIR_LOOKUP:" + TENANT + ":" + ACTOR;
  private static final String LOOKUP_WARN = "DIR_LOOKUP_WARN:" + TENANT + ":" + ACTOR;
  private static final String ALL = "DIR_ALL:" + TENANT + ":" + ACTOR;
  private static final String ALL_WARN = "DIR_ALL_WARN:" + TENANT + ":" + ACTOR;

  private final RateLimitStore store = mock(RateLimitStore.class);
  private final DirectoryAccessGuard guard = new DirectoryAccessGuard(store, 30, 60, 600, 60);

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
  void should_consumeTheCeilingBucket_when_checkingTheCeiling() {
    when(store.tryConsume(ALL, 60, 600)).thenReturn(RateLimitResult.permit());

    assertThatCode(() -> guard.checkCeiling(TENANT, ACTOR)).doesNotThrowAnyException();
    verify(store).tryConsume(ALL, 60, 600);
  }

  @Test
  void should_throwUserDir002WithRetryAfter_when_theCeilingIsExceeded() {
    when(store.tryConsume(ALL, 60, 600)).thenReturn(RateLimitResult.reject(41));
    when(store.tryConsume(ALL_WARN, 60, 1)).thenReturn(RateLimitResult.permit());

    assertThatThrownBy(() -> guard.checkCeiling(TENANT, ACTOR))
        .isInstanceOfSatisfying(
            UserDirectoryCeilingExceededException.class,
            e -> {
              assertThat(e.code()).isEqualTo("USER_DIR_002");
              assertThat(e.retryAfterSeconds()).isEqualTo(41);
              assertThat(e.selfReported()).isTrue();
            });
  }

  @Test
  void should_warnOncePerWindow_when_theCeilingIsExceededRepeatedly() {
    when(store.tryConsume(ALL, 60, 600)).thenReturn(RateLimitResult.reject(5));
    when(store.tryConsume(ALL_WARN, 60, 1))
        .thenReturn(RateLimitResult.permit(), RateLimitResult.reject(5));

    for (int i = 0; i < 3; i++) {
      org.assertj.core.api.Assertions.catchThrowable(() -> guard.checkCeiling(TENANT, ACTOR));
    }

    assertThat(warnings())
        .singleElement()
        .satisfies(
            event ->
                assertThat(keyValues(event))
                    .containsEntry("event", "IDENTITY_DIRECTORY_THROTTLED")
                    .containsEntry("tenantId", TENANT)
                    .containsEntry("actorUserId", ACTOR)
                    .containsEntry("bucket", "DIR_ALL"));
  }

  @Test
  void should_throwUserDir001_when_theLookupBucketIsExceeded() {
    when(store.tryConsume(LOOKUP, 60, 30)).thenReturn(RateLimitResult.reject(17));
    when(store.tryConsume(LOOKUP_WARN, 60, 1)).thenReturn(RateLimitResult.permit());

    assertThatThrownBy(() -> guard.checkLookup(TENANT, ACTOR))
        .isInstanceOfSatisfying(
            UserDirectoryThrottledException.class,
            e -> {
              assertThat(e.code()).isEqualTo("USER_DIR_001");
              assertThat(e.retryAfterSeconds()).isEqualTo(17);
              assertThat(e.selfReported()).isTrue();
            });
  }

  @Test
  void should_warnOncePerWindow_when_lookupsAreThrottledRepeatedly() {
    when(store.tryConsume(LOOKUP, 60, 30)).thenReturn(RateLimitResult.reject(5));
    when(store.tryConsume(LOOKUP_WARN, 60, 1))
        .thenReturn(RateLimitResult.permit(), RateLimitResult.reject(5));

    for (int i = 0; i < 3; i++) {
      org.assertj.core.api.Assertions.catchThrowable(() -> guard.checkLookup(TENANT, ACTOR));
    }

    assertThat(warnings())
        .singleElement()
        .satisfies(
            event ->
                assertThat(keyValues(event))
                    .containsEntry("event", "IDENTITY_DIRECTORY_THROTTLED")
                    .containsEntry("bucket", "DIR_LOOKUP"));
  }

  private java.util.List<ILoggingEvent> warnings() {
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
    return (Logger) LoggerFactory.getLogger(DirectoryAccessGuard.class);
  }
}
