package com.example.nexus.rbac.infrastructure.health;

import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.rbac.application.FreshnessVerdict;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Integration test verifying that non-admin and standard tenant users are denied
 * health indicator details like affectedTenantCount on /actuator/health ([OR-12]).
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
        "spring.datasource.url=jdbc:h2:mem:nexus-health-sec-test;DB_CLOSE_DELAY=-1",
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
        "nexus.management.scrape-token=test-scrape-token-0123456789-abcdefghij",
        "management.health.mail.enabled=false",
        "management.endpoint.health.show-details=when-authorized",
        "management.endpoint.health.roles=SYSTEM_ADMIN"
    })
@ActiveProfiles("test")
@Tag("WebSliceTest")
class RbacHealthSecurityIT {

  @Autowired private WebApplicationContext context;
  @MockitoBean private JwtPort jwtPort;
  @MockitoBean private PermissionFreshnessService permissionFreshness;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void should_deny_health_details_to_standard_users() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    long now = Instant.now().getEpochSecond();
    JwtClaims standardUserClaims = new JwtClaims(
        userId.toString(), tenantId.toString(), false, List.of("MEMBER"), List.of(),
        now, now + 3600, "jwt-id", 0, JwtClaims.CURRENT_VERSION, 0L);

    when(jwtPort.verify(any())).thenReturn(standardUserClaims);
    when(permissionFreshness.check(any(), any(), anyLong(), anyLong()))
        .thenReturn(FreshnessVerdict.FRESH);

    // Standard user querying /actuator/health receives status but NO sensitive details
    mvc.perform(get("/actuator/health")
            .header(HttpHeaders.AUTHORIZATION, "Bearer standard.user.jwt"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").exists())
        .andExpect(jsonPath("$.details").doesNotExist())
        .andExpect(jsonPath("$.components").doesNotExist())
        .andExpect(content().string(not(org.hamcrest.Matchers.containsString("affectedTenantCount"))));
  }
}
