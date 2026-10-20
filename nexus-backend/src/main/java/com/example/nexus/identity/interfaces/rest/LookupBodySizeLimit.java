package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

/**
 * Caps the {@code POST /api/v1/users/lookup} body at 1 KiB before Jackson parses it (US-019
 * RC-59.3, design §4.2). A declared {@code Content-Length} over the cap is refused without reading;
 * otherwise at most cap + 1 bytes are read, so a chunked body cannot stream past it. Either way the
 * answer is 400 {@code VALIDATION_FAILED} with a fixed message that never echoes the body.
 */
@ControllerAdvice(assignableTypes = UserDirectoryController.class)
@ConditionalOnProperty(name = "feature.nexus-us019-user-directory.enabled", havingValue = "true")
class LookupBodySizeLimit extends RequestBodyAdviceAdapter {

  static final int MAX_BODY_BYTES = 1024;

  private static final String CODE_VALIDATION_FAILED = "VALIDATION_FAILED";
  private static final String FIELD_BODY = "body";
  private static final String MESSAGE_TOO_LARGE = "Request body must not exceed 1024 bytes.";

  @Override
  public boolean supports(
      MethodParameter methodParameter,
      Type targetType,
      Class<? extends HttpMessageConverter<?>> converterType) {
    return targetType == UserLookupRequest.class;
  }

  @Override
  public HttpInputMessage beforeBodyRead(
      HttpInputMessage inputMessage,
      MethodParameter parameter,
      Type targetType,
      Class<? extends HttpMessageConverter<?>> converterType)
      throws IOException {
    if (inputMessage.getHeaders().getContentLength() > MAX_BODY_BYTES) {
      throw tooLarge();
    }
    byte[] body = inputMessage.getBody().readNBytes(MAX_BODY_BYTES + 1);
    if (body.length > MAX_BODY_BYTES) {
      throw tooLarge();
    }
    return new BufferedMessage(inputMessage.getHeaders(), body);
  }

  private static FieldValidationException tooLarge() {
    return new FieldValidationException(CODE_VALIDATION_FAILED, FIELD_BODY, MESSAGE_TOO_LARGE);
  }

  /** The already-read body, replayed to the message converter. */
  private static final class BufferedMessage implements HttpInputMessage {

    private final HttpHeaders headers;
    private final byte[] body;

    private BufferedMessage(HttpHeaders headers, byte[] body) {
      this.headers = headers;
      this.body = body;
    }

    @Override
    public InputStream getBody() {
      return new ByteArrayInputStream(body);
    }

    @Override
    public HttpHeaders getHeaders() {
      return headers;
    }
  }
}
