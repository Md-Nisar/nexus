package com.example.nexus.identity.interfaces.rest;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.port.out.JwkSetPort;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class JwksControllerTest {

  private MockMvc mockMvc;
  private JwkSetPort jwkSetPort;

  @BeforeEach
  void setUp() {
    jwkSetPort = mock(JwkSetPort.class);
    mockMvc = MockMvcBuilders.standaloneSetup(new JwksController(jwkSetPort)).build();
  }

  @Test
  void jwks_returns200_withPublicKeyFieldsOnly() throws Exception {
    Map<String, Object> key = Map.of(
        "kty", "RSA", "use", "sig", "alg", "RS256",
        "kid", "key-id-1", "n", "base64-modulus", "e", "AQAB");
    when(jwkSetPort.getPublicKeySet()).thenReturn(Map.of("keys", List.of(key)));

    mockMvc.perform(get("/.well-known/jwks.json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
        .andExpect(jsonPath("$.keys[0].use").value("sig"))
        .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
        .andExpect(jsonPath("$.keys[0].kid").value("key-id-1"))
        .andExpect(jsonPath("$.keys[0].n").exists())
        .andExpect(jsonPath("$.keys[0].e").exists())
        .andExpect(jsonPath("$.keys[0].d").doesNotExist())
        .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("max-age=3600")));
  }
}
