package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

@Tag("UnitTest")
class JwkSetAdapterTest {

  private static RsaKeyConfig rsaKeyConfig;
  private static JwkSetAdapter adapter;

  @BeforeAll
  static void setUp() throws Exception {
    Environment devEnv = mock(Environment.class);
    when(devEnv.getActiveProfiles()).thenReturn(new String[] {"dev"});
    rsaKeyConfig = new RsaKeyConfig(devEnv);
    rsaKeyConfig.init();
    adapter = new JwkSetAdapter(rsaKeyConfig);
  }

  @Test
  void should_containNoPrivateFields_in_publicKeySet() {
    Map<String, Object> jwks = adapter.getPublicKeySet();

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
    assertThat(keys).hasSize(1);
    Map<String, Object> key = keys.get(0);

    assertThat(key).doesNotContainKey("d");
    assertThat(key).doesNotContainKey("p");
    assertThat(key).doesNotContainKey("q");
    assertThat(key).doesNotContainKey("dp");
    assertThat(key).doesNotContainKey("dq");
    assertThat(key).doesNotContainKey("qi");
  }

  @Test
  void should_containCorrectPublicKeyMetadata_in_publicKeySet() {
    Map<String, Object> jwks = adapter.getPublicKeySet();

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
    Map<String, Object> key = keys.get(0);

    assertThat(key.get("kty")).isEqualTo("RSA");
    assertThat(key.get("use")).isEqualTo("sig");
    assertThat(key.get("alg")).isEqualTo("RS256");
    assertThat(key.get("kid")).isEqualTo(rsaKeyConfig.getKid());
    assertThat(key.get("n")).isNotNull();
    assertThat(key.get("e")).isNotNull();
  }

  @Test
  void should_containKeysArray_in_publicKeySet() {
    Map<String, Object> jwks = adapter.getPublicKeySet();

    assertThat(jwks).containsKey("keys");
    assertThat(jwks.get("keys")).isInstanceOf(List.class);
  }
}
