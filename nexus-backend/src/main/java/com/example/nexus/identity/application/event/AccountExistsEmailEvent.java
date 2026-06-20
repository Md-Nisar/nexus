package com.example.nexus.identity.application.event;

import com.example.nexus.common.domain.LogMaskingUtil;

/**
 * Domain event published when a registration attempt is made for an email that already exists in
 * the tenant (anti-enumeration, SEC-4 / REG-05).
 *
 * <p>The mail listener sends a "you already have an account" notice instead of returning a 409,
 * making it indistinguishable to the caller from a successful new registration.
 *
 * @param toEmail the recipient's plaintext email address
 */
public record AccountExistsEmailEvent(String toEmail) {

  @Override
  public String toString() {
    return "AccountExistsEmailEvent[toEmail=" + LogMaskingUtil.maskEmail(toEmail) + "]";
  }
}
