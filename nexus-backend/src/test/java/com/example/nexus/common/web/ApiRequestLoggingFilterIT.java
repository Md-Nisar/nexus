package com.example.nexus.common.web;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

/**
 * {@link ApiRequestLoggingFilter}'s doc/swagger noise-suppression exclusion, exercised through
 * the real filter chain against a running server. {@code ApiRequestLoggingFilterTest} only proves
 * this for the {@code /actuator} prefix via mocks; the {@code /v3/api-docs} branch was previously
 * unexercised by any test (JaCoCo: lines 36-38 partially covered).
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class ApiRequestLoggingFilterIT {

  @Value("${local.server.port:0}") private int port;

  @Test
  void should_notLogApiRequestCompleted_when_pathIsApiDocs() {
    RestTemplate restTemplate = new RestTemplate();
    ListAppender<ILoggingEvent> appender = startLogCapture();

    ResponseEntity<String> response =
        restTemplate.getForEntity("http://localhost:" + port + "/v3/api-docs", String.class);

    stopLogCapture(appender);

    assertThat(response.getStatusCode().value())
        .as("/v3/api-docs is permitAll (SecurityConfig) and must resolve to a real response")
        .isEqualTo(200);

    boolean apiRequestLogged = appender.list.stream()
        .anyMatch(e -> e.getFormattedMessage().contains("API Request Completed"));
    assertThat(apiRequestLogged)
        .as("ApiRequestLoggingFilter must skip logging for excluded api-docs paths"
            + " (doFilterInternal's swagger/api-docs exclusion)")
        .isFalse();
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    root.addAppender(appender);
    return appender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.detachAppender(appender);
    appender.stop();
  }
}
