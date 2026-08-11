import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * E2E: US-002 registration happy path + accessibility.
 *
 * Prerequisites for the full golden path:
 *   - Angular dev server running on :2000  (handled by playwright.config.ts webServer)
 *   - Spring Boot backend running on :1000 (start manually: ./mvnw spring-boot:run)
 *   - MailHog running on :1025/:8025      (docker compose up -d mailhog)
 *
 * The accessibility test always runs (no backend needed).
 * Backend-dependent tests skip automatically when :1000 is not reachable.
 * The email-verification step skips automatically when MailHog is not reachable.
 */

const MAILHOG_API = 'http://localhost:8025/api/v2/messages';

async function isBackendUp(request: import('@playwright/test').APIRequestContext): Promise<boolean> {
  try {
    const resp = await request.get('http://localhost:1000/actuator/health', { timeout: 2_000 });
    return resp.ok();
  } catch {
    return false;
  }
}

// Poll MailHog for an email to `toAddress`, retrying up to `attempts` times.
async function fetchVerificationToken(
  request: import('@playwright/test').APIRequestContext,
  toAddress: string,
  attempts = 6,
  intervalMs = 1_000,
): Promise<string | null> {
  for (let i = 0; i < attempts; i++) {
    if (i > 0) await new Promise((r) => setTimeout(r, intervalMs));
    try {
      const resp = await request.get(MAILHOG_API, { timeout: 3_000 });
      if (!resp.ok()) continue;
      const { items } = (await resp.json()) as { items: MailHogMessage[] };
      const msg = items?.find((m) =>
        m.To?.some((t) => `${t.Mailbox}@${t.Domain}` === toAddress),
      );
      if (msg) {
        const body = msg.Content?.Body ?? '';
        const match = body.match(/token=([0-9a-f]{64})/);
        if (match) return match[1];
      }
    } catch {
    }
  }
  return null;
}


interface MailHogMessage {
  To?: Array<{ Mailbox: string; Domain: string }>;
  Content?: { Body: string };
}

test.describe('registration', () => {
  test('registration form has zero critical accessibility violations (AC-7)', async ({ page }) => {
    await page.goto('/auth/register');
    await expect(page.getByLabel('Email address')).toBeVisible();

    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();

    const critical = results.violations.filter((v) => v.impact === 'critical');
    expect(
      critical,
      `Critical a11y violations:\n${critical.map((v) => `  [${v.id}] ${v.description}\n    ${v.nodes[0]?.html}`).join('\n')}`,
    ).toHaveLength(0);
  });

  test('happy path — fill form, see success, verify email', async ({ page, request }) => {
    if (!(await isBackendUp(request))) {
      test.skip(true, 'Backend is not reachable');
      return;
    }
    const email = `e2e-${Date.now()}@example.com`;

    // ── 1. Navigate and fill the registration form ──────────────────────────
    await page.goto('/auth/register');
    await expect(page.getByLabel('Email address')).toBeVisible();

    await page.locator('input[autocomplete="email"]').fill(email);
    await page.locator('input[autocomplete="new-password"]').fill('ValidPassphrase_99!');
    await page.locator('.reg-form__consent-check input[type="checkbox"]').check();

    // ── 2. Submit and assert "check your inbox" success state ───────────────
    await page.locator('[data-testid="reg-submit"]').click();

    await expect(page.locator('[data-testid="reg-success"]')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('[data-testid="reg-success"]')).toContainText('Check your inbox');

    // ── 3. Fetch verification token from MailHog (skip if unavailable) ──────
    const token = await fetchVerificationToken(request, email, 10, 2_000);
    if (!token) {
      test.skip(true, 'MailHog is not reachable');
      return;
    }

    // ── 4. Navigate to verification URL and assert success page ─────────────
    await page.goto(`/auth/verify-email?token=${token}`);

    // The component shows a verifying spinner first, then resolves.
    await expect(page.locator('[data-testid="verif-success"]')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('[data-testid="verif-success"]')).toContainText('Email verified');
  });

  test('expired / invalid token shows error with resend link', async ({ page, request }) => {
    if (!(await isBackendUp(request))) {
      test.skip(true, 'Backend is not reachable');
      return;
    }
    // 63 f-chars — invalid format, backend returns 410 AUTH_VRF_002
    const badToken = 'f'.repeat(64);

    await page.goto(`/auth/verify-email?token=${badToken}`);

    await expect(page.locator('[data-testid="verif-error"]')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('[data-testid="verif-resend"]')).toBeVisible();
  });
});
