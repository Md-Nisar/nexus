package com.example.nexus.identity.infrastructure.web;

import com.example.nexus.common.security.PublicEndpoint;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * Decides whether a request addresses a {@link PublicEndpoint} handler (US-018 A8, design §3.1,
 * RC-24.1, RC-44.1). It is the one source of "public" for request filters, so no filter keeps its
 * own list of anonymous paths.
 *
 * <p>Built once, at startup, from every mapping in the MVC {@link RequestMappingHandlerMapping}.
 * A mapping is public only if its handler method carries {@code @PublicEndpoint}, it declares at
 * least one HTTP method and it has a path-patterns condition.
 *
 * <p><b>Fails closed.</b> A false positive would exempt a non-public request from the checks of
 * the filter that consults this matcher, so every doubt answers "not public":
 *
 * <ul>
 *   <li>The HTTP method and the path pattern are matched together, never the path alone, using
 *       the same path parsing as MVC dispatch ({@link ServletRequestPathUtils#parseAndCache}).
 *   <li>A request is public only if at least one public mapping matches it and no other mapping
 *       does. A non-public mapping without a path-patterns condition cannot be evaluated and is
 *       treated as matching.
 *   <li>Any runtime exception while matching returns {@code false} and increments {@code
 *       nexus.security.public_match_failed_closed} (no path tag, to keep cardinality bounded).
 * </ul>
 *
 * <p>Only the method and path-pattern conditions are evaluated. Consumes, produces, headers and
 * params conditions are ignored on purpose: a request that lacks a {@code Content-Type} still
 * addresses the login handler, and must not be treated as non-public because MVC would answer it
 * with 415 rather than dispatch it.
 *
 * <p>The request's cached parsed path is restored afterwards, so calling this from a filter does
 * not change what later MVC dispatch sees.
 *
 * <p><b>Limits.</b> "Public" here means public <i>according to the {@code
 * requestMappingHandlerMapping} contents at construction time</i>, nothing wider:
 *
 * <ul>
 *   <li>Another {@link org.springframework.web.servlet.HandlerMapping} with higher precedence (for
 *       example actuator's, order -100) is not consulted. If it maps a request that matches a
 *       public pattern, it wins dispatch while this matcher still answers {@code true}.
 *   <li>A mapping added later through {@code registerMapping} is not seen, because the mapping
 *       list is copied once in the constructor.
 * </ul>
 *
 * <p>Neither overlaps a public pattern today. {@code EndpointClassificationWebTest} resolves every
 * public {@code (method, pattern)} through the ordered handler mappings that {@code
 * DispatcherServlet} uses and fails if the first one to answer is not the same {@code
 * @PublicEndpoint} handler. A runtime {@code registerMapping} call needs review.
 */
@Component
public class PublicEndpointRequestMatcher {

  private static final Logger log = LoggerFactory.getLogger(PublicEndpointRequestMatcher.class);

  private final List<Mapping> mappings;
  private final Counter failedClosed;

  /**
   * Builds the matcher from the handler methods registered at the time of construction.
   *
   * @param handlerMapping the MVC handler mapping that dispatches {@code @RestController} handlers
   * @param meterRegistry registry for the fail-closed counter
   */
  public PublicEndpointRequestMatcher(
      @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping,
      MeterRegistry meterRegistry) {
    this.mappings =
        handlerMapping.getHandlerMethods().entrySet().stream()
            .map(entry -> new Mapping(entry.getKey(), isPublic(entry.getKey(), entry.getValue())))
            .toList();
    this.failedClosed = Counter.builder("nexus.security.public_match_failed_closed")
        .description("Requests treated as non-public because public-endpoint matching failed")
        .register(meterRegistry);
  }

  /**
   * Returns whether {@code request} addresses a {@link PublicEndpoint} handler.
   *
   * @param request the incoming request
   * @return {@code true} only if a public mapping matches the request's method and path and no
   *     other mapping does; {@code false} otherwise, including on any exception
   */
  public boolean matches(HttpServletRequest request) {
    Object previousPath = request.getAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE);
    try {
      ServletRequestPathUtils.parseAndCache(request);
      boolean publicMappingMatches = false;
      for (Mapping mapping : mappings) {
        if (mayMatch(mapping.info(), request)) {
          if (!mapping.isPublic()) {
            return false;
          }
          publicMappingMatches = true;
        }
      }
      return publicMappingMatches;
    } catch (RuntimeException e) {
      failedClosed.increment();
      log.debug("public endpoint match failed closed exception={}", e.getClass().getSimpleName());
      return false;
    } finally {
      if (previousPath == null) {
        request.removeAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE);
      } else {
        request.setAttribute(ServletRequestPathUtils.PATH_ATTRIBUTE, previousPath);
      }
    }
  }

  private static boolean isPublic(RequestMappingInfo info, HandlerMethod handlerMethod) {
    return handlerMethod.hasMethodAnnotation(PublicEndpoint.class)
        && !info.getMethodsCondition().getMethods().isEmpty()
        && info.getPathPatternsCondition() != null;
  }

  private static boolean mayMatch(RequestMappingInfo info, HttpServletRequest request) {
    PathPatternsRequestCondition patterns = info.getPathPatternsCondition();
    if (patterns == null) {
      return true;
    }
    return info.getMethodsCondition().getMatchingCondition(request) != null
        && patterns.getMatchingCondition(request) != null;
  }

  private record Mapping(RequestMappingInfo info, boolean isPublic) {}
}
