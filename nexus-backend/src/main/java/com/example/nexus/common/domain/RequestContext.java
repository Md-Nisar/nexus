package com.example.nexus.common.domain;

/**
 * Carries per-request contextual data (IP address, trace ID, User-Agent) for audit-event
 * enrichment. Constructed at the interface layer and passed into application-layer use-cases.
 *
 * <p>{@code userAgent} is fully attacker-controlled, unbounded free text. Callers deriving this
 * record from a live HTTP request MUST use {@link #of} — it applies the 512-character cap and
 * JSON-escaping. The canonical (raw) record constructor performs no validation or truncation and
 * exists for sentinels/test literals; never construct directly from an HTTP-derived value.
 */
public record RequestContext(String ipAddress, String traceId, String userAgent) {

  private static final int USER_AGENT_MAX_LENGTH = 512;

  /** Upper bound (inclusive) of the JSON RFC 8259 control-character range U+0000-U+001F. */
  private static final int MAX_JSON_CONTROL_CHAR = 0x1F;

  /** Sentinel used in test contexts where no HTTP request is available. */
  public static final RequestContext UNKNOWN = new RequestContext("unknown", null, null);

  /**
   * Builds a {@link RequestContext} from request-derived values, truncating {@code userAgent} to
   * {@value #USER_AGENT_MAX_LENGTH} characters (by {@code char} count, not bytes, so a UTF-16
   * surrogate pair is never split mid-code-point) if it exceeds the cap.
   */
  public static RequestContext of(String ipAddress, String traceId, String userAgent) {
    return new RequestContext(ipAddress, traceId, truncate(userAgent));
  }

  private static String truncate(String value) {
    if (value == null || value.length() <= USER_AGENT_MAX_LENGTH) {
      return value;
    }
    int end = USER_AGENT_MAX_LENGTH;
    // Never split a UTF-16 surrogate pair: if the char just before the cut is a high surrogate
    // and the char at the cut is its low surrogate, back off one char so the pair stays intact.
    if (Character.isHighSurrogate(value.charAt(end - 1))
        && Character.isLowSurrogate(value.charAt(end))) {
      end--;
    }
    return value.substring(0, end);
  }

  /**
   * Produces a compact JSON string suitable for storage in {@code auth_events.metadata}. All
   * values are JSON-escaped to prevent injection into the native JSON column.
   */
  public String toMetadataJson() {
    StringBuilder sb = new StringBuilder("{");
    boolean appended = false;
    if (traceId != null) {
      sb.append("\"traceId\":\"").append(jsonEscape(traceId)).append("\"");
      appended = true;
    }
    if (ipAddress != null) {
      if (appended) sb.append(',');
      sb.append("\"ip\":\"").append(jsonEscape(ipAddress)).append("\"");
      appended = true;
    }
    if (userAgent != null) {
      if (appended) sb.append(',');
      sb.append("\"userAgent\":\"").append(jsonEscape(userAgent)).append("\"");
    }
    sb.append('}');
    return sb.toString();
  }

  private static String jsonEscape(String value) {
    StringBuilder escaped = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\' -> escaped.append("\\\\");
        case '"' -> escaped.append("\\\"");
        case '\n' -> escaped.append("\\n");
        case '\r' -> escaped.append("\\r");
        case '\t' -> escaped.append("\\t");
        default -> {
          // RFC 8259: every U+0000-U+001F control character must be escaped inside a JSON
          // string, not just \n \r \t -- an unescaped one would break the native JSON column
          // parser (and any downstream JSON parser), which is exactly the T-T1 threat.
          if (c <= MAX_JSON_CONTROL_CHAR) {
            escaped.append(String.format("\\u%04x", (int) c));
          } else {
            escaped.append(c);
          }
        }
      }
    }
    return escaped.toString();
  }
}
