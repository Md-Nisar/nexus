import { test } from '@playwright/test';

export const apiBase = process.env['E2E_API_BASE_URL'] ?? 'http://localhost:1000';

/**
 * Probes the backend. With `E2E_REQUIRE_BACKEND=1` an unreachable backend throws, so CI can
 * never go green on skipped tests; otherwise the calling test is skipped (local convenience).
 *
 * The readiness group is probed, not the aggregate: the aggregate also reports optional
 * dependencies (mail), which says nothing about whether the API can serve a test.
 */
export async function requireBackend(): Promise<void> {
  let reachable: boolean;
  try {
    const response = await fetch(`${apiBase}/actuator/health/readiness`, {
      signal: AbortSignal.timeout(3_000),
    });
    reachable = response.ok;
  } catch {
    reachable = false;
  }
  if (reachable) return;
  if (process.env['E2E_REQUIRE_BACKEND'] === '1') {
    throw new Error(`Backend not reachable at ${apiBase} and E2E_REQUIRE_BACKEND=1`);
  }
  test.skip(true, `Backend not reachable at ${apiBase}`);
}
