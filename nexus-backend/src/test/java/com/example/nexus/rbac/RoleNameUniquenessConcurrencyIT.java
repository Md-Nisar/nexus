package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleView;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * US-015 T-010 (Scenario 2's concurrent variant; 02-impact.md §11.1's concurrency-harness
 * template): proves {@link RoleManagementService#createRole}'s {@code
 * uq_roles_tenant_name}-violation translation into {@link DuplicateRoleNameException} (RBAC_006)
 * holds under genuine concurrency, not just sequential calls (already covered by {@code
 * RoleManagementIT}) or the raw-DB level (already covered by {@code RoleUniquenessIT}).
 *
 * <p>Concurrency harness mirrors {@code ActiveAssignmentIT#should_allowExactlyOneWinner_when_...}
 * / {@code RefreshTokenRotationIT#concurrent_rotation_single_winner} exactly: 8-thread {@code
 * ExecutorService} + {@code CyclicBarrier}, 5s barrier wait, 15s executor-termination timeout —
 * this is a genuine "N threads race a unique constraint simultaneously" property, unlike {@code
 * RoleManagementAdminGateIT}'s directed-ordering design, so the CyclicBarrier pattern is the
 * correct (and sufficient) fit here.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleNameUniquenessConcurrencyIT {

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_allowExactlyOneWinner_when_eightConcurrentCreatesRaceOnSameNameSameTenant()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    String sharedName = "RNU-CONC-" + UUID.randomUUID();
    int threadCount = 8;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<RoleView>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
      futures.add(
          executor.submit(
              (Callable<RoleView>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    return roleManagementService.createRole(
                        actor, sharedName, null, requestContext());
                  }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 8 threads must complete within the timeout").isTrue();

    int successCount = 0;
    List<Throwable> failures = new ArrayList<>();
    for (Future<RoleView> future : futures) {
      try {
        future.get();
        successCount++;
      } catch (Exception e) {
        failures.add(e);
      }
    }

    assertThat(successCount).as("exactly one concurrent create should win").isEqualTo(1);
    assertThat(successCount + failures.size()).isEqualTo(threadCount);
    failures.forEach(RoleNameUniquenessConcurrencyIT::assertLostRaceOnDuplicateRoleName);
  }

  private static void assertLostRaceOnDuplicateRoleName(Throwable executionException) {
    Throwable dive = executionException;
    while (dive != null && !(dive instanceof DuplicateRoleNameException)) {
      dive = dive.getCause();
    }
    assertThat(dive)
        .as("a losing concurrent create must fail specifically with DuplicateRoleNameException")
        .isInstanceOf(DuplicateRoleNameException.class);
  }

  // ── Cross-tenant-same-name positive case ────────────────────────────────────────────────

  @Test
  void should_allowSameNameInBothTenants_when_creatingViaServiceInDifferentTenants() {
    String sharedName = "RNU-XTENANT-" + UUID.randomUUID();
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    RoleChangeActor actorA = new RoleChangeActor(uuidGenerator.newId(), tenantA);
    RoleChangeActor actorB = new RoleChangeActor(uuidGenerator.newId(), tenantB);

    RoleView roleA = roleManagementService.createRole(actorA, sharedName, null, requestContext());
    RoleView roleB = roleManagementService.createRole(actorB, sharedName, null, requestContext());

    assertThat(roleA.name()).isEqualTo(sharedName);
    assertThat(roleB.name()).isEqualTo(sharedName);
    assertThat(roleA.id()).isNotEqualTo(roleB.id());
  }

  // ── F10: accent-insensitive collation collision ─────────────────────────────────────────

  /**
   * {@code uq_roles_tenant_name} runs under {@code utf8mb4_0900_ai_ci} — accent-insensitive as
   * well as case-insensitive, so {@code "RÔLE"} collides with {@code "ROLE"}. This is
   * deliberately kept out of the ordinary HTTP path by {@code CreateRoleRequest}'s ASCII-only
   * {@code @Pattern} (D6) — but the underlying uniqueness MECHANISM must still be proven correct
   * for any caller that reaches the service directly (bean validation is enforced only at the
   * DTO/controller boundary, not inside {@link RoleManagementService} itself), which is exactly
   * what this test proves by calling the service directly, bypassing that DTO validation layer.
   */
  @Test
  void should_throwDuplicateRoleNameException_when_accentOnlyDiffersFromExistingName() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    String base = "ACCENT-" + UUID.randomUUID().toString().replace("-", "");
    roleManagementService.createRole(actor, base + "-ROLE", null, requestContext());

    assertThatThrownBy(
            () ->
                roleManagementService.createRole(
                    actor, base + "-RÔLE", null, requestContext()))
        .isInstanceOf(DuplicateRoleNameException.class);
  }

  private RequestContext requestContext() {
    return RequestContext.of(
        "127.0.0.1", "trace-" + UUID.randomUUID(), "RoleNameUniquenessConcurrencyIT");
  }
}
