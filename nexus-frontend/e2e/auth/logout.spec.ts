import { test, expect } from '@playwright/test';
import { requireBackend } from '../fixtures/backend';

/**
 * E2E: US-005 — logout with refresh token revocation.
 *
 * Prerequisites:
 *   - Angular dev server running on :2000  (handled by playwright.config.ts webServer)
 *   - Spring Boot backend running on :1000 (start manually: ./mvnw spring-boot:run)
 *   - Pre-seeded, email-verified test user:
 *       email:    process.env.E2E_TEST_USER_EMAIL    (default: test@example.com)
 *       password: process.env.E2E_TEST_USER_PASSWORD (default: TestPass99!)
 *
 * Backend-dependent tests skip locally when :1000 is not reachable and fail when
 * E2E_REQUIRE_BACKEND=1 (CI).
 */

const EMAIL = process.env['E2E_TEST_USER_EMAIL'] ?? 'test@example.com';
const PASSWORD = process.env['E2E_TEST_USER_PASSWORD'] ?? 'TestPass99!';

async function openUserMenu(page: import('@playwright/test').Page): Promise<void> {
  await page.locator('[data-testid="nx-menu-trigger"]').click();
}

async function login(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('/auth/login');
  await page.locator('input[autocomplete="email"]').fill(EMAIL);
  await page.locator('input[autocomplete="current-password"]').fill(PASSWORD);
  await page.locator('[data-testid="login-submit"]').click();
  await page.waitForURL(/\/dashboard/, { timeout: 10_000 });
}

test.describe('US-005 — logout with refresh token revocation', () => {
  test.beforeEach(async () => {
    await requireBackend();
  });

  test('TS-1 — golden path: logout redirects to /auth/login and shows confirmation toast', async ({
    page,
  }) => {
    await login(page);

    await openUserMenu(page);
    await page.locator('[data-testid="logout-button"]').click();

    // URL assertion first — deterministic; avoids toast-timing flakiness (R7).
    await expect(page).toHaveURL(/\/auth\/login/, { timeout: 10_000 });

    // Dashboard must not be visible after redirect.
    await expect(page.locator('[data-testid="dashboard-root"]')).not.toBeVisible();

    // Toast confirmation (softer assertion — Material snackbar may animate out).
    await expect(page.locator('.nx-toast--success')).toBeVisible({ timeout: 5_000 });
  });

  test('TS-2 — back button after logout does not restore the dashboard', async ({ page }) => {
    await login(page);

    await openUserMenu(page);
    await page.locator('[data-testid="logout-button"]').click();
    await expect(page).toHaveURL(/\/auth\/login/, { timeout: 10_000 });

    // Navigate back — authGuard must intercept and redirect back to /auth/login.
    await page.goBack();

    await expect(page).toHaveURL(/\/auth\/login/, { timeout: 5_000 });
    await expect(page.locator('[data-testid="dashboard-root"]')).not.toBeVisible();
  });

  test('TS-3 — refresh_token cookie is cleared after logout; subsequent /refresh returns 401', async ({
    page,
    context,
    request,
  }) => {
    await login(page);

    // Capture the refresh_token cookie value before logout.
    const cookiesBefore = await context.cookies();
    const refreshBefore = cookiesBefore.find((c) => c.name === 'refresh_token');
    expect(refreshBefore).toBeDefined();
    const capturedRefreshToken = refreshBefore!.value;

    await openUserMenu(page);
    await page.locator('[data-testid="logout-button"]').click();
    await expect(page).toHaveURL(/\/auth\/login/, { timeout: 10_000 });

    // The cookie must be gone (Max-Age=0 causes the browser to expire it).
    const cookiesAfter = await context.cookies();
    const refreshAfter = cookiesAfter.find(
      (c) => c.name === 'refresh_token' && c.path === '/api/v1/auth',
    );
    expect(refreshAfter).toBeUndefined();

    // Direct API call with the pre-logout cookie must return 401 — server-side revocation.
    const refreshResp = await request.post('http://localhost:1000/api/v1/auth/refresh', {
      headers: { Cookie: `refresh_token=${capturedRefreshToken}` },
    });
    expect(refreshResp.status()).toBe(401);
  });
});
