package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.JwkSetPort;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
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
    // BigInteger.toByteArray() uses two's-complement: strip the leading 0x00 sign byte so
    // the encoded length matches the key size (RFC 7518 §6.3.1.1 requires unsigned encoding).
    byte[] nBytes = publicKey.getModulus().toByteArray();
    if (nBytes.length > 0 && nBytes[0] == 0) {
      nBytes = Arrays.copyOfRange(nBytes, 1, nBytes.length);
    }
    byte[] eBytes = publicKey.getPublicExponent().toByteArray();
    if (eBytes.length > 0 && eBytes[0] == 0) {
      eBytes = Arrays.copyOfRange(eBytes, 1, eBytes.length);
    }
    String n = encoder.encodeToString(nBytes);
    String e = encoder.encodeToString(eBytes);

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
