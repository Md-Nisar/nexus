import { Page } from '@playwright/test';
import { requireBackend } from '../fixtures/backend';
import { PERSONAS, PERSONA_PASSWORD } from '../fixtures/personas';
import { enterAddress } from '../fixtures/secret-input';
import { expect, test } from '../fixtures/test';

// These specs render the dashboard, whose header shows the signed-in persona's address; a retry
// trace would carry it into the uploaded report and fail the PII scan. No trace is recorded
// (file-level: Playwright does not allow a trace override inside a describe group).
test.use({ trace: 'off' });

async function signIn(page: Page): Promise<void> {
  await enterAddress(page.getByLabel('Email address'), PERSONAS.member.email);
  await page.getByLabel('Password', { exact: true }).fill(PERSONA_PASSWORD);
  await page.getByTestId('login-submit').click();
}

test.describe('returnUrl round trip', () => {
  test.beforeEach(async () => {
    await requireBackend();
  });

  test('signing in lands on the URL that was requested while signed out', async ({ page }) => {
    await page.goto('/no/such/page?tab=1');
    await expect(page).toHaveURL(/\/auth\/login\?returnUrl=/);
    await signIn(page);
    await expect(page).toHaveURL(/\/no\/such\/page\?tab=1$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
  });

  test('an off-site returnUrl is ignored and sign-in lands on the dashboard', async ({ page }) => {
    await page.goto('/auth/login?returnUrl=%2F%2Fevil.example%2Fphish');
    await signIn(page);
    await expect(page).toHaveURL(/localhost:\d+\/dashboard$/);
  });
});

/**
 * US-020 RC-70 (D-2): a return URL whose first segment, as the router decodes it, is the
 * unavailable view is replaced by the dashboard, so sign-in can never land on that view.
 */
test.describe('returnUrl never targets the unavailable view', () => {
  test.beforeEach(async () => {
    await requireBackend();
  });

  for (const [name, encoded] of [
    ['the unavailable view', '%2Funavailable%3FreturnUrl%3D%252Fadmin'],
    ['an encoded first segment that decodes to unavailable', '%2F%2575navailable'],
  ] as const) {
    test(`a returnUrl pointing at ${name} signs in to the dashboard`, async ({ page }) => {
      await page.goto(`/auth/login?returnUrl=${encoded}`);
      await signIn(page);
      await expect(page).toHaveURL(/localhost:\d+\/dashboard$/);
    });
  }
});
