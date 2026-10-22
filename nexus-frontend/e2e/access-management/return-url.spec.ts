import { Page } from '@playwright/test';
import { requireBackend } from '../fixtures/backend';
import { PERSONAS, PERSONA_PASSWORD } from '../fixtures/personas';
import { expect, test } from '../fixtures/test';

async function signIn(page: Page): Promise<void> {
  await page.getByLabel('Email address').fill(PERSONAS.member.email);
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
