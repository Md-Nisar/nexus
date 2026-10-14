package com.example.nexus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.interfaces.cli.BreakGlassAdminRunner;
import com.example.nexus.rbac.interfaces.cli.BreakGlassExit;
import com.example.nexus.rbac.interfaces.cli.BreakGlassWebContextGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

// Deliberately untagged, like NexusSmokeTest: the H2, no-Docker, full-context boot check of the
// break-glass profile (US-018 A7), which must always run under Surefire. It proves what the unit
// tests cannot: that the whole application context (security configuration, scheduling, JPA)
// refreshes with NO web application, and that the guard refuses a serving context for real.
@SpringBootTest(
    properties = {
      "spring.main.web-application-type=none",
      "nexus.rbac.break-glass.log-flush-interval=0s"
    })
@ActiveProfiles({"smoke", "break-glass"})
class BreakGlassContextSmokeTest {

  @Autowired private ApplicationContext applicationContext;

  // Replaces the production exit (System.exit) so the runner, which ApplicationRunner semantics
  // invoke during startup, cannot end the test JVM.
  @MockitoBean private BreakGlassExit exit;

  @Test
  void should_refreshWithoutAWebApplication_when_breakGlassProfileIsActive() {
    assertThat(applicationContext).isNotInstanceOf(
        org.springframework.web.context.WebApplicationContext.class);
    assertThat(applicationContext.getBeansOfType(BreakGlassAdminRunner.class)).hasSize(1);
    assertThat(applicationContext.getBeansOfType(BreakGlassWebContextGuard.class)).hasSize(1);
  }

  @Test
  void should_failTheContextRefresh_when_breakGlassProfileRunsAsAServletApplication() {
    assertThatThrownBy(
            () -> {
              try (ConfigurableApplicationContext ignored =
                  new SpringApplicationBuilder(NexusApplication.class)
                      .profiles("smoke", "break-glass")
                      .properties(
                          "server.port=0", "spring.datasource.url=jdbc:h2:mem:break-glass-servlet")
                      // A command-line argument outranks the profile's web-application-type=none,
                      // which is exactly how an operator could try to override it.
                      .run("--spring.main.web-application-type=servlet")) {
                // never reached: the guard must have failed the refresh
              }
            })
        .hasRootCauseInstanceOf(IllegalStateException.class)
        .rootCause()
        .hasMessageContaining("spring.main.web-application-type=none");
  }
}
