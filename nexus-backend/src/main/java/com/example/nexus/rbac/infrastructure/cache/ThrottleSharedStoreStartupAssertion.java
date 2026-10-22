package com.example.nexus.rbac.infrastructure.cache;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Refuses to start when {@code nexus.rbac.throttle.require-shared-store} is true and the throttle
 * would live in one JVM (US-018 B8, RC-45.1). With {@code nexus.security.rate-limit.store-type=memory}
 * each replica keeps its own throttle state (RES-11), so a prober who is throttled on one replica is
 * not throttled on the next. The property is {@code false} by default and {@code true} under the
 * {@code prod} profile, which turns US-017's "deployment prerequisite" into a startup check.
 *
 * <p>The message names the properties to set and carries no value other than the store type.
 */
@Component
public class ThrottleSharedStoreStartupAssertion {

  static final String SHARED_STORE_TYPE = "redis";

  private final boolean requireSharedStore;
  private final String storeType;

  public ThrottleSharedStoreStartupAssertion(
      @Value("${nexus.rbac.throttle.require-shared-store:false}") boolean requireSharedStore,
      @Value("${nexus.security.rate-limit.store-type:memory}") String storeType) {
    this.requireSharedStore = requireSharedStore;
    this.storeType = storeType;
  }

  /** Runs once the bean is built, before the context accepts traffic. */
  @PostConstruct
  void verifyAtStartup() {
    verify(requireSharedStore, storeType);
  }

  /**
   * @param requireSharedStore {@code nexus.rbac.throttle.require-shared-store}
   * @param storeType {@code nexus.security.rate-limit.store-type}
   * @throws IllegalStateException if a shared store is required and the store type is not {@code
   *     redis}
   */
  static void verify(boolean requireSharedStore, String storeType) {
    if (requireSharedStore && !SHARED_STORE_TYPE.equals(storeType)) {
      throw new IllegalStateException(
          "nexus.rbac.throttle.require-shared-store=true but nexus.security.rate-limit.store-type="
              + storeType + "; set nexus.security.rate-limit.store-type=redis so the role-change "
              + "denial throttle is shared across replicas (RES-11, RC-45.1)");
    }
  }
}
