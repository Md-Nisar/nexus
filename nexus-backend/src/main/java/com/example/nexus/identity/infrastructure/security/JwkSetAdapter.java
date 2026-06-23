package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.JwkSetPort;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Publishes the active RSA public key in RFC 7517 (JWK Set) format.
 * Only public key components are included — private key fields ({@code d}, {@code p}, {@code q})
 * are never present.
 */
@Component
public class JwkSetAdapter implements JwkSetPort {

  private final RSAPublicKey publicKey;
  private final String kid;

  public JwkSetAdapter(RsaKeyConfig rsaKeyConfig) {
    this.publicKey = (RSAPublicKey) rsaKeyConfig.getKeyPair().getPublic();
    this.kid = rsaKeyConfig.getKid();
  }

  @Override
  public Map<String, Object> getPublicKeySet() {
    Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    String n = encoder.encodeToString(publicKey.getModulus().toByteArray());
    String e = encoder.encodeToString(publicKey.getPublicExponent().toByteArray());

    Map<String, Object> key = new LinkedHashMap<>();
    key.put("kty", "RSA");
    key.put("use", "sig");
    key.put("alg", "RS256");
    key.put("kid", kid);
    key.put("n", n);
    key.put("e", e);

    return Map.of("keys", List.of(key));
  }
}
