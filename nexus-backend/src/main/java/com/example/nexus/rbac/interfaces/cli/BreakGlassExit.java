package com.example.nexus.rbac.interfaces.cli;

/**
 * Ends the break-glass process with an exit code (US-018 A7). A seam so the runner is testable
 * without killing the test JVM; the production bean is {@link SpringBreakGlassExit}.
 */
@FunctionalInterface
public interface BreakGlassExit {

  void exit(int exitCode);
}
