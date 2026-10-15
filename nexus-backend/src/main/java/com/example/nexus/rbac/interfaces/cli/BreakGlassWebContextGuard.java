package com.example.nexus.rbac.interfaces.cli;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * The web-context guard (US-018 A7, RC-37.6, RC-50(d), ADR-0025 1): a bean-initialization check
 * that fails the context refresh unless the effective {@code spring.main.web-application-type} is
 * {@code none}, so the {@code break-glass} profile can never be activated in a serving pod.
 *
 * <p>It checks the <b>actual</b> {@link ApplicationContext} as well as the property: a servlet or
 * reactive context fails even if the property reads {@code none}. It is {@link Lazy @Lazy(false)}
 * because nothing depends on it, so {@code spring.main.lazy-initialization=true} would otherwise
 * skip it while the runner still ran (M5 L-1).
 *
 * <p>The embedded server starts after singleton instantiation, so this fails the refresh before
 * any port is opened. It does <b>not</b> run before database access ({@code ddl-auto=validate}
 * reads the schema during the refresh). It pages with {@code reason=WEB_CONTEXT} and no
 * identifiers, then throws.
 */
@Component
@Profile("break-glass")
@Lazy(false)
public class BreakGlassWebContextGuard implements InitializingBean {

  private static final Logger log = LoggerFactory.getLogger(BreakGlassWebContextGuard.class);

  static final String WEB_APPLICATION_TYPE_PROPERTY = "spring.main.web-application-type";

  private final Environment environment;
  private final ApplicationContext applicationContext;
  private final BreakGlassAlertPort alertPort;

  public BreakGlassWebContextGuard(
      Environment environment,
      ApplicationContext applicationContext,
      BreakGlassAlertPort alertPort) {
    this.environment = environment;
    this.applicationContext = applicationContext;
    this.alertPort = alertPort;
  }

  @Override
  public void afterPropertiesSet() {
    String type = environment.getProperty(WEB_APPLICATION_TYPE_PROPERTY);
    boolean webContext =
        applicationContext instanceof WebApplicationContext
            || applicationContext instanceof WebServerApplicationContext;
    if ("none".equalsIgnoreCase(type) && !webContext) {
      return;
    }
    alertPort.raise(
        new BreakGlassAlert(
            null, null, BreakGlassAlert.OUTCOME_REFUSED, "WEB_CONTEXT", null));
    log.error(
        "break-glass profile refused: {} must be none and the context must not be a web context",
        WEB_APPLICATION_TYPE_PROPERTY);
    throw new IllegalStateException(
        "The break-glass profile requires " + WEB_APPLICATION_TYPE_PROPERTY + "=none");
  }
}
