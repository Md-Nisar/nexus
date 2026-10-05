package com.example.nexus.common.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a REST handler that requires a signed-in caller but no permission (US-018 A8, design
 * §3.1, Decision 1).
 *
 * <p>This is a marker only: there is no AOP behind it. Enforcement is {@code SecurityConfig}'s
 * {@code anyRequest().authenticated()}. Because no permission is checked, such a handler must only
 * read or change the caller's own data, addressed through the authenticated principal.
 *
 * <p>{@code HexagonalArchitectureTest} turns "own data only" into a build rule: a handler carrying
 * this annotation declares no {@code @PathVariable} at all and no {@code UUID}-typed {@code
 * @RequestParam}. An endpoint that takes an identifier of another resource must use {@link
 * RequiresPermission} instead.
 *
 * <p>Every handler in a {@code @RestController} carries exactly one of {@link RequiresPermission},
 * {@link PublicEndpoint} or this annotation.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthenticatedEndpoint {}
