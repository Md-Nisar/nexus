package com.example.nexus.common.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a REST handler that anonymous callers may reach (US-018 A8, design §3.1).
 *
 * <p>This is a marker only: there is no AOP behind it and it grants nothing by itself. Anonymous
 * access is granted by the {@code permitAll} list in {@code SecurityConfig}; this annotation
 * declares that the handler is meant to be on that list. The two are kept in step by {@code
 * EndpointClassificationWebTest}, which sends an anonymous request to every handler and fails if
 * a {@code @PublicEndpoint} handler gets the authentication entry point's 401 or if any other
 * handler does not.
 *
 * <p>{@code PublicEndpointRequestMatcher} is built from the handlers carrying this annotation and
 * is the single source of "is this request public" for request filters (RC-24.1).
 *
 * <p>Every handler in a {@code @RestController} carries exactly one of {@link RequiresPermission},
 * {@link AuthenticatedEndpoint} or this annotation; {@code HexagonalArchitectureTest} fails the
 * build otherwise. Do not use this for an endpoint that needs a signed-in caller but no
 * permission; that is {@link AuthenticatedEndpoint}.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface PublicEndpoint {}
