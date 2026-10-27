package com.example.nexus.rbac.application.event;

import com.example.nexus.rbac.application.DegradedState;
import java.time.Instant;

/**
 * Event published asynchronously when {@link com.example.nexus.rbac.application.PermissionFreshnessService}
 * undergoes a circuit breaker state transition ([OR-2.1-09]).
 *
 * @param from previous circuit breaker state
 * @param to target circuit breaker state
 * @param cause reason for the state transition
 * @param timestamp timestamp when the transition occurred
 */
public record PermissionFreshnessStateTransitionEvent(
    DegradedState from,
    DegradedState to,
    String cause,
    Instant timestamp) {}
