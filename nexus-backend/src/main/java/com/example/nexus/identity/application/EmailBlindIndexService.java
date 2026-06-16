package com.example.nexus.identity.application;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/** Computes HMAC-SHA256 blind indexes for email addresses used in per-tenant lookups. */
@Service
public class EmailBlindIndexService {

  private static final String HMAC_SHA256 = "HmacSHA256";

  private final byte[] hmacKey;

  public EmailBlindIndexService(byte[] identityHmacKey) {
    this.hmacKey = identityHmacKey.clone();
  }

  /**
   * Computes a deterministic HMAC-SHA256 blind index for the given email address.
   *
   * <p>Normalisation contract (must be identical on every write and lookup): {@code trim → NFC →
   * toLowerCase(Locale.ROOT)}. This contract is shared across all stories; never re-implement
   * normalisation outside this service.
   *
   * @param email the raw email address
   * @return 64-character lowercase hex HMAC-SHA256 of the normalised email
   */
  public String blindIndex(String email) {
    if (email == null) {
      throw new IllegalArgumentException("email must not be null");
    }
    String normalised =
        Normalizer.normalize(email.trim(), Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
    try {
      Mac mac = Mac.getInstance(HMAC_SHA256); // fresh instance per call — avoids shared-state bugs
      mac.init(new SecretKeySpec(hmacKey, HMAC_SHA256));
      byte[] digest = mac.doFinal(normalised.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to compute email blind index", e);
    }
  }
}
