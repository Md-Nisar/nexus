import { test, expect } from '@playwright/test';

/**
 * E2E: US-004 — silent session renewal (proactive refresh path).
 *
 * Prerequisites:
 *   - Angular dev server running on :2000  (handled by playwright.config.ts webServer)
 *   - Spring Boot backend running on :1000 (start manually: ./mvnw spring-boot:run)
 *   - Pre-seeded, email-verified test user:
 *       email:    process.env.E2E_TEST_USER_EMAIL    (default: test@example.com)
 *       password: process.env.E2E_TEST_USER_PASSWORD (default: TestPass99!)
 *
 * Backend-dependent tests skip automatically when :1000 is not reachable.
 */

const EMAIL = process.env['E2E_TEST_USER_EMAIL'] ?? 'test@example.com';
const PASSWORD = process.env['E2E_TEST_USER_PASSWORD'] ?? 'TestPass99!';

async function isBackendUp(request: import('@playwright/test').APIRequestContext): Promise<boolean> {
  try {
    const resp = await request.get('http://localhost:1000/actuator/health', { timeout: 2_000 });
    return resp.ok();
  } catch {
    return false;
  }
}

test.describe('US-004 — silent session renewal', () => {
  test.beforeEach(async ({ request }, testInfo) => {
    if (!(await isBackendUp(request))) {
      testInfo.skip();
    }
  });

  test('TS-1 — proactive refresh fires before expiry; protected request succeeds without login prompt', async ({
    page,
    context,
  }) => {
    // ── Step 1: intercept the login response to return a 5-second access-token TTL.
    // This makes expiresAt = now + 5_000 ms in AuthStore — immediately within the
    // 2-min proactive threshold so the next intercepted HTTP call triggers a refresh.
    await context.route('**/api/v1/auth/login', async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as Record<string, unknown>;
      await route.fulfill({
        status: response.status(),
        headers: { ...response.headers(), 'content-type': 'application/json' },
        body: JSON.stringify({ ...body, expiresIn: 5 }),
      });
    });

    // ── Step 2: count proactive refresh calls (pass-through to real backend).
    let refreshCallCount = 0;
    await context.route('**/api/v1/auth/refresh', async (route) => {
      refreshCallCount++;
      const response = await route.fetch();
      await route.fulfill({
        status: response.status(),
        headers: response.headers(),
        body: await response.body(),
      });
    });

    // ── Step 3: log in — session is stored with expiresAt = now + 5 000 ms.
    await page.goto('/auth/login');
    await page.locator('input[autocomplete="email"]').fill(EMAIL);
    await page.locator('input[autocomplete="current-password"]').fill(PASSWORD);
    await page.locator('[data-testid="login-submit"]').click();

    // LoginFormComponent.submit() calls router.navigate(['/dashboard']) on success.
    await page.waitForURL(/\/dashboard/, { timeout: 10_000 });

    // ── Step 4: dashboard ngOnInit calls GET /api/v1/users/me; the interceptor sees
    // expiresAt - now < 120_000 ms and fires authService.refresh() proactively.
    // Wait for network idle to ensure both the proactive refresh and /users/me have settled.
    await page.waitForLoadState('networkidle', { timeout: 10_000 });

    await context.unroute('**/api/v1/auth/login');
    await context.unroute('**/api/v1/auth/refresh');

    // ── Assertions ─────────────────────────────────────────────────────────────
    await expect(page).not.toHaveURL(/\/auth\/login/);
    await expect(page.locator('[data-testid="dashboard-root"]')).toBeVisible({ timeout: 5_000 });
    expect(refreshCallCount).toBeGreaterThanOrEqual(1);
  });

  test('TS-4 — replay of revoked refresh token clears session and redirects to login', async ({
    page,
  }) => {
    // ── Step 1: log in normally (full-TTL session, no intercepted login response).
    await page.goto('/auth/login');
    await page.locator('input[autocomplete="email"]').fill(EMAIL);
    await page.locator('input[autocomplete="current-password"]').fill(PASSWORD);
    await page.locator('[data-testid="login-submit"]').click();

    // Confirm the SPA navigation to /dashboard succeeded.
    await page.waitForURL(/\/dashboard/, { timeout: 10_000 });

    // ── Step 2: mock the refresh endpoint to return AUTH_004 (revoked family).
    await page.route('**/api/v1/auth/refresh', (route) =>
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'AUTH_004', detail: 'Refresh token invalid.' }),
      }),
    );

    // Mock /users/me to return 401 — this triggers the reactive interceptor path.
    await page.route('**/api/v1/users/me', (route) =>
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'AUTH_003', detail: 'Token invalid.' }),
      }),
    );

    // ── Step 3: full browser navigation reloads Angular and resets the in-memory
    // session to null. Dashboard ngOnInit calls /users/me → 401 → reactive interceptor
    // fires → /auth/refresh → 401 AUTH_004 → clearSession() + navigate(['/auth/login']).
    await page.goto('/dashboard');

    await expect(page).toHaveURL(/\/auth\/login/, { timeout: 5_000 });
  });
});
