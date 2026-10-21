package com.example.nexus.common.web;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Documents one {@code ProblemDetail} error response of a handler in the generated OpenAPI spec:
 * the HTTP status, the stable {@code code}s the response can carry, and when it happens. {@code
 * OpenApiConfig} turns it into an {@code application/problem+json} response and lists the codes in
 * the operation's {@code x-nexus-error-codes} extension.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Repeatable(ProblemResponses.class)
public @interface ProblemResponse {

  /** The HTTP status code of the error response. */
  int status();

  /** The machine-readable {@code code} values this response can carry. */
  String[] codes();

  /** When the response is returned. */
  String description();
}
