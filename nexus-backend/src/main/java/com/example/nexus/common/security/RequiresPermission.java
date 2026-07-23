package com.example.nexus.common.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Method-level guard requiring the caller's resolved permission set (see {@link
 * TenantAwarePermissionEvaluator}) to contain {@link #value()}.
 *
 * <p><b>Single-permission scope (design §B9):</b> this annotation expresses exactly one required
 * permission. It does not support AND/OR composition of multiple permissions; stack the SpEL
 * expression directly with {@code @PreAuthorize} for compound checks instead.
 *
 * <p><b>Requires {@code AnnotationTemplateExpressionDefaults} (T-004):</b> the {@code {value}}
 * placeholder in the {@code @PreAuthorize} expression below is only substituted with this
 * annotation's {@link #value()} when an {@code AnnotationTemplateExpressionDefaults} bean is
 * registered in {@code MethodSecurityConfig}. Until that bean exists, Spring treats {@code
 * {value}} as a literal string, the SpEL expression never evaluates truthy, and every call fails
 * closed (access denied) regardless of the caller's actual permissions.
 *
 * <p><b>Self-invocation is not intercepted:</b> like all Spring AOP method security, a call to a
 * {@code @RequiresPermission}-annotated method from another method in the same class bypasses the
 * proxy and is not checked. See T-016 for the full developer-guide treatment of this pitfall.
 *
 * <p><b>Must be a {@code public}, non-{@code final} method on a Spring-managed bean:</b> Spring
 * AOP cannot proxy {@code final} or {@code private} methods, so an annotation placed on either
 * is silently never enforced — the method executes unguarded with no error, log, or exception.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@permissionEvaluator.hasPermission(authentication, '{value}')")
public @interface RequiresPermission {
  String value();
}
