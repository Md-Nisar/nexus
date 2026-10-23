package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.domain.PreconditionRequiredException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses {@code If-Match} for the role permission-set replace (US-019 design §10.5, RC-55.2). It
 * accepts <b>exactly one strong entity-tag</b> and returns its opaque value without the quotes.
 * RFC 9110 allows a list and {@code *}; this API narrows it on purpose, because a list would let a
 * client offer the versions of several states. Absent, empty, {@code *}, a list, a weak tag, an
 * empty tag or anything unparseable is a {@link PreconditionRequiredException} (428), whose message
 * never echoes the header.
 */
final class IfMatchHeader {

  /** One quoted, non-empty opaque tag of visible ASCII other than the double quote. */
  private static final Pattern STRONG_TAG = Pattern.compile("\"([\\x21\\x23-\\x7E]+)\"");

  private IfMatchHeader() {}

  static String parse(String raw) {
    if (raw == null) {
      throw new PreconditionRequiredException();
    }
    Matcher matcher = STRONG_TAG.matcher(raw.strip());
    if (!matcher.matches()) {
      throw new PreconditionRequiredException();
    }
    return matcher.group(1);
  }
}
