package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

class RsaKeyConfigTest {

  private Environment devEnv() {
    Environment env = mock(Environment.class);
    when(env.getActiveProfiles()).thenReturn(new String[] {"dev"});
    return env;
  }

  private Environment prodEnv() {
    Environment env = mock(Environment.class);
    when(env.getActiveProfiles()).thenReturn(new String[] {"prod"});
    return env;
  }

  private static KeyPair generateKeyPair(int bits) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(bits);
    return kpg.generateKeyPair();
  }

  private static String encodePrivatePem(java.security.PrivateKey key) {
    String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded());
    return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
  }

  private static String encodePublicPem(java.security.PublicKey key) {
    String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded());
    return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
  }

  @Test
  void should_throwIllegalState_when_blankPemInProdProfile() {
    RsaKeyConfig config = new RsaKeyConfig(prodEnv());

    assertThatThrownBy(config::init)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("prod profile");
  }

  @Test
  void should_generateEphemeralKey_when_blankPemInDevProfile() throws Exception {
    RsaKeyConfig config = new RsaKeyConfig(devEnv());

    config.init();

    RSAPublicKey pub = (RSAPublicKey) config.getKeyPair().getPublic();
    assertThat(pub.getModulus().bitLength()).isGreaterThanOrEqualTo(2048);
  }

  @Test
  void should_throwIllegalArgument_when_keyBelowMinimumBits() throws Exception {
    KeyPair shortPair = generateKeyPair(1024);
    RsaKeyConfig config = new RsaKeyConfig(devEnv());
    config.setPrivateKeyPem(encodePrivatePem(shortPair.getPrivate()));
    config.setPublicKeyPem(encodePublicPem(shortPair.getPublic()));

    assertThatThrownBy(config::init)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("2048");
  }

  @Test
  void should_notContainBegin_in_toString() throws Exception {
    RsaKeyConfig config = new RsaKeyConfig(devEnv());
    config.init();

    assertThat(config.toString()).doesNotContain("BEGIN");
  }

  @Test
  void should_returnExactly8HexChars_for_getKid() throws Exception {
    RsaKeyConfig config = new RsaKeyConfig(devEnv());
    config.init();

    assertThat(config.getKid()).matches("[0-9a-f]{8}");
  }

  @Test
  void should_loadConfiguredKeyPair_when_validPemProvided() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    RsaKeyConfig config = new RsaKeyConfig(devEnv());
    config.setPrivateKeyPem(encodePrivatePem(pair.getPrivate()));
    config.setPublicKeyPem(encodePublicPem(pair.getPublic()));

    config.init();

    assertThat(config.getKeyPair().getPublic()).isNotNull();
    assertThat(config.getKeyPair().getPrivate()).isNotNull();
  }
}
