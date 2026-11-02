package com.example.nexus.rbac.application;

import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.function.BooleanSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The administrator-only rule for granting {@code user:directory:read} (US-019 03-design.md §4.8;
 * RC-60, RC-66). A request that would grant the permission, matched by its seeded id ({@link
 * RbacSeededPermissionIds#USER_DIRECTORY_READ}, never by {@code isSensitive}), requires the caller
 * to be an administrator (ADR-0021 D3). Callers evaluate it <b>after</b> A2/A3 (RC-66.1), so only a
 * caller who already holds every permission being granted can be told {@code NOT_TENANT_ADMIN};
 * everyone else gets A2/A3's {@code GRANT_EXCEEDS_CALLER} and learns nothing about the role.
 *
 * <p>The verbs keep their own denial posture (RC-66.2): attach throws with no audit row (Decision
 * 7), assign writes its {@code ROLE_ASSIGNMENT_DENIED} row and books a throttle denial. This class
 * only decides and emits the rule's own signals.
 *
 * <p>Switch {@code nexus.rbac.pii-grant-requires-administrator} (default {@code true}; D5 decides).
 * With {@code false} the startup WARN {@code RBAC_PII_GRANT_RULE_DISABLED} is logged (RC-66.4). The
 * detective signal is always on: a grant by a non-administrator that succeeds is reported after
 * commit by {@link #recordDelegated} (RC-60.2).
 */
@Component
public class PiiPermissionGrantRule {

  private static final Logger log = LoggerFactory.getLogger(PiiPermissionGrantRule.class);

  static final String PROPERTY = "nexus.rbac.pii-grant-requires-administrator";
  private static final String COUNTER_DELEGATED = "nexus.rbac.pii_permission_delegated";

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_ACTOR_USER_ID = "actorUserId";
  private static final String LOG_KEY_ROLE_ID = "roleId";
  private static final String LOG_KEY_TARGET_USER_ID = "targetUserId";

  /** What one grant request means under the rule. */
  enum Outcome {
    /** The granted ids do not include {@code user:directory:read}; the rule does not apply. */
    NOT_A_PII_GRANT,
    /** An administrator grants it: allowed, and nothing is emitted. */
    ADMINISTRATOR_GRANT,
    /** A non-administrator grants it while the rule is on: the caller must deny. */
    DENIED,
    /** A non-administrator grants it while the rule is off: allowed, and reported after commit. */
    DELEGATED
  }

  private final boolean enforced;
  private final Counter delegatedCounter;
  private final Set<UUID> piiPermissionIds;

  @Autowired
  public PiiPermissionGrantRule(
      @Value("${" + PROPERTY + ":true}") boolean enforced, MeterRegistry meterRegistry) {
    this(enforced, meterRegistry, Set.of(RbacSeededPermissionIds.USER_DIRECTORY_READ));
  }

  public PiiPermissionGrantRule(
      boolean enforced, MeterRegistry meterRegistry, Set<UUID> piiPermissionIds) {
    this.enforced = enforced;
    this.delegatedCounter = Counter.builder(COUNTER_DELEGATED).register(meterRegistry);
    this.piiPermissionIds =
        piiPermissionIds == null || piiPermissionIds.isEmpty()
            ? Set.of(RbacSeededPermissionIds.USER_DIRECTORY_READ)
            : Set.copyOf(piiPermissionIds);
  }

  /** RC-66.4: switching the rule off is never silent. */
  @PostConstruct
  void warnIfDisabled() {
    if (enforced) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_PII_GRANT_RULE_DISABLED")
        .addKeyValue("property", PROPERTY)
        .log("Granting user:directory:read no longer requires an administrator");
  }

  /**
   * The rule for one request that would grant {@code grantedPermissionIds}. {@code
   * callerIsAdministrator} is consulted only when the permission is among them, so the other paths
   * pay nothing; it must answer from the same authorization read the verb used (M13 per role, or
   * the set lock's rows), and a missing answer must mean {@code false}.
   */
  Outcome evaluate(Collection<UUID> grantedPermissionIds, BooleanSupplier callerIsAdministrator) {
    if (grantedPermissionIds == null
        || grantedPermissionIds.stream().noneMatch(piiPermissionIds::contains)) {
      return Outcome.NOT_A_PII_GRANT;
    }
    if (callerIsAdministrator.getAsBoolean()) {
      return Outcome.ADMINISTRATOR_GRANT;
    }
    return enforced ? Outcome.DENIED : Outcome.DELEGATED;
  }

  /** WARN {@code RBAC_PII_PERMISSION_GRANT_DENIED}, ids only. {@code targetUserId} is null on attach. */
  void warnDenied(
      UUID tenantId, UUID actorUserId, UUID roleId, UUID targetUserId, String operation) {
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_PII_PERMISSION_GRANT_DENIED")
        .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actorUserId)
        .addKeyValue(LOG_KEY_ROLE_ID, roleId)
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue("operation", operation)
        .log("Blocked a grant of user:directory:read by a caller who is not an administrator");
  }

  /**
   * RC-60.2, call after commit only: WARN {@code RBAC_PII_PERMISSION_DELEGATED} (ids only, ≥ 1-year
   * retention, RES-6) and the untagged counter {@code nexus.rbac.pii_permission_delegated}. {@code
   * targetUserId} is null on attach.
   */
  void recordDelegated(UUID tenantId, UUID actorUserId, UUID roleId, UUID targetUserId) {
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_PII_PERMISSION_DELEGATED")
        .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actorUserId)
        .addKeyValue(LOG_KEY_ROLE_ID, roleId)
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .log("A non-administrator granted user:directory:read");
    delegatedCounter.increment();
  }
}
