package com.example.nexus.common.domain;

/**
 * Carries per-request contextual data (IP address, trace ID) for audit-event enrichment.
 * Constructed at the interface layer and passed into application-layer use-cases.
 */
public record RequestContext(String ipAddress, String traceId) {

  /** Sentinel used in test contexts where no HTTP request is available. */
  public static final RequestContext UNKNOWN = new RequestContext("unknown", null);

  /**
   * Produces a compact JSON string suitable for storage in {@code auth_events.metadata}.
   * Both values are JSON-escaped to prevent injection into the native JSON column.
   */
  public String toMetadataJson() {
    StringBuilder sb = new StringBuilder("{");
    if (traceId != null) {
      sb.append("\"traceId\":\"").append(jsonEscape(traceId)).append("\"");
    }
    if (ipAddress != null) {
      if (traceId != null) sb.append(',');
      sb.append("\"ip\":\"").append(jsonEscape(ipAddress)).append("\"");
    }
    sb.append('}');
    return sb.toString();
  }

  private static String jsonEscape(String value) {
    return value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t");
  }
}
