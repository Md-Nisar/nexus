package com.example.nexus.rbac.application.port.out;

/**
 * Answer of {@link RoleChangeThrottlePort#throttleStatus} (US-019 B7, design §9.3): whether the
 * actor is throttled and, if so, how many whole seconds remain until the throttle lifts.
 *
 * @param throttled whether the actor is currently throttled
 * @param retryAfterSeconds seconds until the throttle lifts, rounded up; {@code 0} when not
 *     throttled
 */
public record ThrottleStatus(boolean throttled, long retryAfterSeconds) {

  /** Not throttled; also the fail-safe answer when the throttle store is unavailable. */
  public static final ThrottleStatus NOT_THROTTLED = new ThrottleStatus(false, 0);
}
