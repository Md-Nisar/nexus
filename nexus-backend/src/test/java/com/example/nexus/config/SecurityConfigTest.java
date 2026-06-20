package com.example.nexus.config;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("smoke")
class SecurityConfigTest {

  @Autowired
  private WebApplicationContext wac;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(wac)
        .apply(springSecurity())
        .build();
  }

  @Test
  void authRegisterPath_returns404NotUnauthorized_whenUnauthenticated() throws Exception {
    // 404 = request passed Spring Security (no handler — controller not loaded with flag off)
    mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}"))
        .andExpect(status().isNotFound());
  }

  @Test
  void authVerifyEmailPath_returns404NotUnauthorized_whenUnauthenticated() throws Exception {
    mockMvc.perform(post("/api/v1/auth/verify-email")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}"))
        .andExpect(status().isNotFound());
  }

  @Test
  void authResendPath_returns404NotUnauthorized_whenUnauthenticated() throws Exception {
    mockMvc.perform(post("/api/v1/auth/resend-verification")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}"))
        .andExpect(status().isNotFound());
  }

  @Test
  void unknownPath_returns401_whenUnauthenticated() throws Exception {
    mockMvc.perform(get("/api/v1/some-protected-resource"))
        .andExpect(status().isUnauthorized());
  }
}
