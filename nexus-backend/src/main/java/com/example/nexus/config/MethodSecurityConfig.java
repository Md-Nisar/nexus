package com.example.nexus.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

/**
 * Activates method-level authorization (FR10) platform-wide and registers the meta-annotation
 * template-defaults bean {@code @RequiresPermission} (T-003) needs to substitute {@code {value}}
 * with its own attribute at each call site.
 *
 * <p>Deliberately separate from {@link SecurityConfig}: that class owns the HTTP filter chain and
 * {@code permitAll} list; this class owns only the method-security switch (design §B1).
 */
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class MethodSecurityConfig {

  /**
   * Enables {@code {value}}-style attribute substitution in {@code @PreAuthorize} meta-annotations
   * such as {@link com.example.nexus.common.security.RequiresPermission}. Without this bean, Spring
   * treats {@code {value}} as a literal string and every guarded call fails closed.
   */
  @Bean
  public AnnotationTemplateExpressionDefaults annotationTemplateExpressionDefaults() {
    return new AnnotationTemplateExpressionDefaults();
  }
}
