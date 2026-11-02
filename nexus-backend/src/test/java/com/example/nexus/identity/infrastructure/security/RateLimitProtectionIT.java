package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.example.nexus.TestcontainersConfiguration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
        "nexus.security.rate-limit.ip-max-attempts=3",
        "nexus.security.rate-limit.ip-window-seconds=10",
        "nexus.security.rate-limit.user-max-attempts=5",
        "nexus.security.rate-limit.user-window-seconds=10"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RateLimitProtectionIT {

  @Autowired private WebApplicationContext ctx;
  @Autowired private InMemoryRateLimitStore rateLimitStore;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(ctx)
        .apply(springSecurity())
        .build();
  }

  @Test
  void should_throttle_ip_before_allocating_user_rate_limit_keys() throws Exception {
    String spammerIp = "192.168.100.99";

    // Exhaust IP bucket (ip-max-attempts = 3)
    for (int i = 0; i < 3; i++) {
      String email = "victim-" + i + "-" + UUID.randomUUID() + "@example.com";
      mvc.perform(
          post("/api/v1/auth/login")
              .with(req -> {
                req.setRemoteAddr(spammerIp);
                return req;
              })
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"email\":\"" + email + "\",\"password\":\"WrongPass123!\"}"));
    }

    int initialStoreSize = rateLimitStore.storeSize();

    // Subsequent requests from the same spammer IP with randomized emails must be throttled
    // at the IP layer before allocating any new user-level rate limit keys.
    for (int i = 0; i < 5; i++) {
      String randomEmail = "spam-" + i + "-" + UUID.randomUUID() + "@example.com";
      var res = mvc.perform(
              post("/api/v1/auth/login")
                  .with(req -> {
                    req.setRemoteAddr(spammerIp);
                    return req;
                  })
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"email\":\"" + randomEmail + "\",\"password\":\"WrongPass123!\"}"))
          .andReturn()
          .getResponse();
      assertThat(res.getStatus()).isEqualTo(429);
    }

    // IP rate-limiting short-circuited before allocating user-level keys:
    // the store size did not increase despite 5 distinct random user identifiers.
    assertThat(rateLimitStore.storeSize()).isEqualTo(initialStoreSize);
  }
}
