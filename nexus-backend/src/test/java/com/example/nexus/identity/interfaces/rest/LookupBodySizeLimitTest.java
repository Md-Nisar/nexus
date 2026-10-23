package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.StringHttpMessageConverter;

/** US-019 T-005 (RC-59.3): the lookup body is capped at 1 KiB before it is parsed. */
@Tag("UnitTest")
class LookupBodySizeLimitTest {

  private final LookupBodySizeLimit limit = new LookupBodySizeLimit();

  @Test
  void should_applyOnlyToTheLookupBody_when_askedWhetherItSupportsATargetType() {
    assertThat(limit.supports(null, UserLookupRequest.class, StringHttpMessageConverter.class)).isTrue();
    assertThat(limit.supports(null, String.class, StringHttpMessageConverter.class)).isFalse();
  }

  @Test
  void should_replayTheBodyAndHeaders_when_theBodyIsExactly1024Bytes() throws IOException {
    byte[] body = "x".repeat(LookupBodySizeLimit.MAX_BODY_BYTES).getBytes(StandardCharsets.UTF_8);
    HttpHeaders headers = new HttpHeaders();
    headers.setContentLength(body.length);

    HttpInputMessage replayed = limit.beforeBodyRead(message(headers, body), null, UserLookupRequest.class, null);

    assertThat(replayed.getBody().readAllBytes()).isEqualTo(body);
    assertThat(replayed.getHeaders()).isSameAs(headers);
  }

  @Test
  void should_rejectWithoutReading_when_theDeclaredContentLengthExceeds1024() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentLength(LookupBodySizeLimit.MAX_BODY_BYTES + 1L);
    HttpInputMessage unreadable =
        new HttpInputMessage() {
          @Override
          public InputStream getBody() {
            throw new AssertionError("the body must not be read");
          }

          @Override
          public HttpHeaders getHeaders() {
            return headers;
          }
        };

    assertThatThrownBy(() -> limit.beforeBodyRead(unreadable, null, UserLookupRequest.class, null))
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> assertThat(e.code()).isEqualTo("VALIDATION_FAILED"));
  }

  @Test
  void should_rejectWithAFixedMessage_when_aBodyWithoutContentLengthExceeds1024Bytes() {
    byte[] body =
        ("{\"email\":\"sentinel@example.test\"" + " ".repeat(1100) + "}").getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(
            () -> limit.beforeBodyRead(message(new HttpHeaders(), body), null, UserLookupRequest.class, null))
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> {
              assertThat(e.code()).isEqualTo("VALIDATION_FAILED");
              assertThat(e.getMessage()).doesNotContain("sentinel");
            });
  }

  private static HttpInputMessage message(HttpHeaders headers, byte[] body) {
    return new HttpInputMessage() {
      @Override
      public InputStream getBody() {
        return new ByteArrayInputStream(body);
      }

      @Override
      public HttpHeaders getHeaders() {
        return headers;
      }
    };
  }
}
