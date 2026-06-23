package com.example.nexus.identity.infrastructure.security;

import jakarta.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Loads or generates the RSA key pair used for JWT signing (RS256, see ADR-0007).
 *
 * <p>If {@code nexus.jwt.private-key-pem} and {@code nexus.jwt.public-key-pem} are both set,
 * parses them from PKCS#8 / X.509 PEM and validates that the modulus is ≥ 2048 bits. Otherwise,
 * generates an ephemeral 2048-bit key pair (dev/smoke only; startup is blocked in {@code prod}).
 *
 * <p>The {@code privateKeyPem} field is excluded from actuator responses by
 * {@link com.example.nexus.identity.infrastructure.crypto.IdentityActuatorSanitizer}.
 * The {@code toString()} implementation never exposes key material.
 */
@Configuration
@ConfigurationProperties(prefix = "nexus.jwt")
public class RsaKeyConfig {

  private static final Logger log = LoggerFactory.getLogger(RsaKeyConfig.class);
  private static final int MIN_KEY_BITS = 2048;

  private final Environment environment;

  private String privateKeyPem;
  private String publicKeyPem;
  private KeyPair keyPair;

  public RsaKeyConfig(Environment environment) {
    this.environment = environment;
  }

  /** Bound from {@code nexus.jwt.private-key-pem}. Sanitized by the actuator sanitizer. */
  public void setPrivateKeyPem(String privateKeyPem) {
    this.privateKeyPem = privateKeyPem;
  }

  /** Bound from {@code nexus.jwt.public-key-pem}. */
  public void setPublicKeyPem(String publicKeyPem) {
    this.publicKeyPem = publicKeyPem;
  }

  /**
   * Initialises the key pair from PEM configuration or generates an ephemeral key for non-prod
   * profiles. Fails fast if no key is configured in the {@code prod} profile.
   */
  @PostConstruct
  void init() {
    if (isNonBlank(privateKeyPem) && isNonBlank(publicKeyPem)) {
      loadConfiguredKeyPair();
    } else if (isProdProfile()) {
      throw new IllegalStateException(
          "JWT RSA key not configured — startup blocked in prod profile");
    } else {
      generateEphemeralKeyPair();
    }
  }

  /** Returns the active RSA key pair; never {@code null} after {@link #init()} completes. */
  public KeyPair getKeyPair() {
    return keyPair;
  }

  /**
   * Returns the first 8 hex characters of the SHA-256 digest of the encoded public key.
   * Identifies the key in JWT {@code kid} headers and in the JWKS endpoint.
   */
  public String getKid() {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(keyPair.getPublic().getEncoded());
      return HexFormat.of().formatHex(digest, 0, 4);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }

  @Override
  public String toString() {
    return "RsaKeyConfig{kid='" + getKid() + "'}";
  }

  private void loadConfiguredKeyPair() {
    try {
      byte[] privateBytes = decodePem(privateKeyPem);
      byte[] publicBytes = decodePem(publicKeyPem);
      var privateKey = KeyFactory.getInstance("RSA")
          .generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
      var publicKey = KeyFactory.getInstance("RSA")
          .generatePublic(new X509EncodedKeySpec(publicBytes));
      if (((RSAKey) privateKey).getModulus().bitLength() < MIN_KEY_BITS) {
        throw new IllegalArgumentException(
            "JWT RSA key modulus must be at least " + MIN_KEY_BITS + " bits");
      }
      this.keyPair = new KeyPair(publicKey, privateKey);
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to load JWT RSA key pair from PEM config", e);
    }
  }

  private void generateEphemeralKeyPair() {
    try {
      log.warn("Using ephemeral RSA-2048 key — NOT for production");
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(MIN_KEY_BITS);
      this.keyPair = kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("RSA not available", e);
    }
  }

  private static byte[] decodePem(String pem) {
    String stripped = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s+", "");
    return Base64.getDecoder().decode(stripped);
  }

  private static boolean isNonBlank(String s) {
    return s != null && !s.isBlank();
  }

  private boolean isProdProfile() {
    return Arrays.stream(environment.getActiveProfiles()).anyMatch("prod"::equals);
  }
}
