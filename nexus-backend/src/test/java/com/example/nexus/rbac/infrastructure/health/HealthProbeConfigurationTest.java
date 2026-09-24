package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroup;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

/**
 * US-017 T-006(h): MC-J (design §11.2, §8.2 "Protected property 1" / "Protected property 2") --
 * mechanizes the two config-level guarantees FR-2's health indicator depends on, so a future PR
 * that regresses either fails this test rather than shipping silently:
 *
 * <ol>
 *   <li>{@code rbacZeroActiveAdmins} must stay OUT of the liveness/readiness probe groups (D11,
 *       RC-22.2/22.3) -- a widened DOWN population must remain a page, never a
 *       container-eviction outage.
 *   <li>{@code management.endpoint.health.cache.time-to-live} must remain at the M-2 value, 30s
 *       (RES-21) -- the TTL bounding an anonymous cross-tenant scan amplification on the
 *       {@code permitAll} {@code /actuator/health/**} path, more load-bearing under FR-2's
 *       two-query, four-table form.
 * </ol>
 *
 * <p>Introspects the bound Spring configuration objects ({@link HealthEndpointGroups}; {@link
 * Binder} over {@link Environment}) rather than string-matching {@code application.yml}'s raw
 * text, so the assertions survive an unrelated YAML reformat (design §11.2 MC-J, Risk (h)).
 *
 * <p>No Docker/Testcontainers: H2 in-memory, {@code create-drop} -- mirrors {@code
 * SecurityConfigWebTest}'s established no-Docker slice pattern.
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:nexus-mcj-test;DB_CLOSE_DELAY=-1",
      "spring.datasource.driver-class-name=org.h2.Driver",
      "spring.datasource.username=sa",
      "spring.datasource.password=",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "spring.flyway.enabled=false",
      "spring.mail.host=127.0.0.1",
      "spring.mail.properties.mail.smtp.connectiontimeout=200",
      "spring.mail.properties.mail.smtp.timeout=200",
      "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
      "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
      "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
      "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
      "nexus.identity.argon2.memory-kb=4096",
      "nexus.identity.argon2.iterations=1",
      "nexus.identity.argon2.parallelism=1",
      "nexus.mail.from-address=test@nexus.test",
      "nexus.frontend.base-url=http://localhost:2000",
      // No SMTP server on localhost -- disable mail health indicator to keep /actuator/health UP
      "management.health.mail.enabled=false"
    })
@Tag("WebSliceTest")
class HealthProbeConfigurationTest {

  @Autowired private HealthEndpointGroups healthEndpointGroups;
  @Autowired private Environment environment;

  @Test
  void should_excludeRbacZeroActiveAdminsFromLivenessAndReadinessGroups_MCJ() {
    HealthEndpointGroup liveness = healthEndpointGroups.get("liveness");
    HealthEndpointGroup readiness = healthEndpointGroups.get("readiness");

    assertThat(liveness).as("the liveness probe group must exist").isNotNull();
    assertThat(readiness).as("the readiness probe group must exist").isNotNull();
    assertThat(liveness.isMember("rbacZeroActiveAdmins"))
        .as(
            "D11: a widened DOWN population must remain a page, never a container-eviction"
                + " outage -- a future PR sweeping this indicator into the liveness group must"
                + " fail here")
        .isFalse();
    assertThat(readiness.isMember("rbacZeroActiveAdmins"))
        .as("same guarantee, readiness group (RC-22.3)")
        .isFalse();
  }

  @Test
  void should_keepActuatorHealthCacheTimeToLiveAt30Seconds_MCJ() {
    Duration ttl =
        Binder.get(environment).bind("management.endpoint.health.cache.time-to-live", Duration.class).get();

    assertThat(ttl)
        .as(
            "RES-21/07-security-review.md M-2: the TTL bounding an anonymous cross-tenant scan"
                + " amplification on the permitAll /actuator/health/** path must not be silently"
                + " shortened or removed")
        .isEqualTo(Duration.ofSeconds(30));
  }
}
