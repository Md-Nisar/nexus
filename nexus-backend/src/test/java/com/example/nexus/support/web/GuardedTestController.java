package com.example.nexus.support.web;

import com.example.nexus.common.security.RequiresPermission;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only fixture proving AC5/AC7 (design §B6): {@code @RequiresPermission} applied to an
 * arbitrary method, with zero bespoke wiring beyond the annotation itself, compiles and enforces.
 * Registered exclusively via {@link GuardedTestControllerConfig}; never component-scanned in
 * production — this class lives under {@code src/test/java} and is never packaged in the
 * application artifact.
 */
@RestController
public class GuardedTestController {

  @GetMapping("/internal-test/guarded")
  @RequiresPermission("tenant:write")
  public ResponseEntity<Void> guarded() {
    return ResponseEntity.ok().build();
  }

  @GetMapping("/internal-test/guarded-user-read")
  @RequiresPermission("user:read")
  public ResponseEntity<Void> guardedUserRead() {
    return ResponseEntity.ok().build();
  }

  /**
   * Externally-callable twin of {@link #guardedViaSelfInvocation()}, used to prove that method
   * security genuinely enforces the annotation when the method is invoked the normal way (through
   * the proxy, i.e. via an HTTP call), in contrast with {@link #selfInvokeGuardedMethod()} below —
   * see {@code RequiresPermission}'s documented self-invocation limitation.
   */
  @GetMapping("/internal-test/guarded-external-only")
  @RequiresPermission("tenant:write")
  public ResponseEntity<Void> guardedViaSelfInvocation() {
    return ResponseEntity.ok().build();
  }

  /**
   * Demonstrates the documented Spring AOP self-invocation limitation ({@code RequiresPermission}
   * Javadoc, threat-model T-05): calling {@link #guardedViaSelfInvocation()} from within the same
   * bean bypasses the method-security proxy entirely, so the permission check never runs, even
   * though the same method enforces correctly when called externally (see {@link
   * #guardedViaSelfInvocation()}'s own mapping).
   */
  @GetMapping("/internal-test/self-invoke")
  public ResponseEntity<Void> selfInvokeGuardedMethod() {
    return guardedViaSelfInvocation();
  }

  /**
   * Demonstrates the documented Spring AOP final-method limitation ({@code RequiresPermission}
   * Javadoc, security-review finding F-1): Spring Boot's default CGLIB proxy cannot override a
   * {@code final} method, so the method-security interceptor never runs and the annotation is
   * silently never enforced — the method executes unguarded regardless of the caller's
   * permissions.
   */
  @GetMapping("/internal-test/guarded-final")
  @RequiresPermission("tenant:write")
  public final ResponseEntity<Void> guardedFinal() {
    return ResponseEntity.ok().build();
  }
}
