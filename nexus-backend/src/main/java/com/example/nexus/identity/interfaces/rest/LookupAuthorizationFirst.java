package com.example.nexus.identity.interfaces.rest;

import static com.example.nexus.common.security.Permissions.USER_DIRECTORY_READ;

import com.example.nexus.common.security.TenantAwarePermissionEvaluator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Makes the {@code user:directory:read} check on {@code POST /api/v1/users/lookup} run before the
 * request body is read (US-019 review R2-2). {@code @RequiresPermission} is method security, so
 * Spring MVC resolves the arguments first: the {@link LookupBodySizeLimit} read, Jackson and bean
 * validation. A caller without the permission would then get a 400 for a bad body, and the server
 * would have read and parsed up to 1 KiB for them, before any 403. This interceptor runs ahead of
 * argument resolution and denies through the same evaluator, so the answer is the same 403 {@code
 * RBAC_001}. {@code @RequiresPermission} stays on the handler as the authoritative check.
 *
 * <p>The mapping does not declare {@code consumes}: that condition is matched while the handler is
 * looked up, before any interceptor, so a wrong {@code Content-Type} would answer 415 ahead of the
 * 403. Without it, the body converter still refuses a body that is not JSON with the same 415
 * {@code UNSUPPORTED_MEDIA_TYPE}, but only for a caller who passed the check.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "feature.nexus-us019-user-directory.enabled", havingValue = "true")
class LookupAuthorizationFirst implements WebMvcConfigurer, HandlerInterceptor {

  static final String LOOKUP_PATH = "/api/v1/users/lookup";

  private final TenantAwarePermissionEvaluator permissionEvaluator;

  LookupAuthorizationFirst(TenantAwarePermissionEvaluator permissionEvaluator) {
    this.permissionEvaluator = permissionEvaluator;
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(this).addPathPatterns(LOOKUP_PATH);
  }

  @Override
  public boolean preHandle(
      HttpServletRequest request, HttpServletResponse response, Object handler) {
    permissionEvaluator.hasPermission(
        SecurityContextHolder.getContext().getAuthentication(), USER_DIRECTORY_READ);
    return true;
  }
}
