package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.context.support.GenericWebApplicationContext;

/** Unit tests for {@link BreakGlassWebContextGuard} (US-018 A7, RC-37.6, RC-50(d)). */
@Tag("UnitTest")
class BreakGlassWebContextGuardTest {

  private final BreakGlassAlertPort alertPort = mock(BreakGlassAlertPort.class);

  private BreakGlassWebContextGuard guardFor(String webApplicationType) {
    return guardFor(webApplicationType, new GenericApplicationContext());
  }

  private BreakGlassWebContextGuard guardFor(
      String webApplicationType, ApplicationContext applicationContext) {
    MockEnvironment environment = new MockEnvironment();
    if (webApplicationType != null) {
      environment.setProperty("spring.main.web-application-type", webApplicationType);
    }
    return new BreakGlassWebContextGuard(environment, applicationContext, alertPort);
  }

  @ParameterizedTest
  @ValueSource(strings = {"servlet", "reactive", "SERVLET", "", "none ", "nonex"})
  void should_throwAndPage_when_webApplicationTypeIsNotNone(String type) {
    BreakGlassWebContextGuard guard = guardFor(type);

    assertThatThrownBy(guard::afterPropertiesSet).isInstanceOf(IllegalStateException.class);

    ArgumentCaptor<BreakGlassAlert> captor = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(alertPort).raise(captor.capture());
    assertThat(captor.getValue())
        .isEqualTo(new BreakGlassAlert(null, null, BreakGlassAlert.OUTCOME_REFUSED, "WEB_CONTEXT", null));
  }

  @Test
  void should_throwAndPage_when_webApplicationTypeIsUnset() {
    assertThatThrownBy(guardFor(null)::afterPropertiesSet).isInstanceOf(IllegalStateException.class);

    verify(alertPort).raise(any());
  }

  @ParameterizedTest
  @ValueSource(strings = {"none", "NONE", "None"})
  void should_pass_when_webApplicationTypeIsNone(String type) {
    assertThatCode(guardFor(type)::afterPropertiesSet).doesNotThrowAnyException();

    verifyNoInteractions(alertPort);
  }

  // M5 L-1: the property alone is not enough; the actual context must not be a web context.
  @Test
  void should_throwAndPage_when_contextIsAServletWebApplicationContextDespiteNoneProperty() {
    BreakGlassWebContextGuard guard = guardFor("none", new GenericWebApplicationContext());

    assertThatThrownBy(guard::afterPropertiesSet).isInstanceOf(IllegalStateException.class);

    verify(alertPort).raise(any());
  }

  @Test
  void should_throwAndPage_when_contextIsAWebServerApplicationContextDespiteNoneProperty() {
    BreakGlassWebContextGuard guard = guardFor("none", mock(WebServerApplicationContext.class));

    assertThatThrownBy(guard::afterPropertiesSet).isInstanceOf(IllegalStateException.class);

    verify(alertPort).raise(any());
  }

  @Test
  void should_notBeLazy_when_guardIsDeclared() {
    assertThat(BreakGlassWebContextGuard.class.getAnnotation(Lazy.class)).isNotNull();
    assertThat(BreakGlassWebContextGuard.class.getAnnotation(Lazy.class).value()).isFalse();
  }
}
