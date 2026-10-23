import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { SIGN_IN_PERSONAS, PersonaKey } from '../fixtures/personas';
import { expect, test } from '../fixtures/test';

/**
 * Nav labels each persona sees against the dev build (console switched on). "Access management"
 * is shown to a persona holding role:read or user:directory:read; the member holds neither. The
 * filtering rules themselves are proved by the gated-nav cases in
 * src/app/core/layout/shell/shell.spec.ts.
 */
const NAV_LABELS: Readonly<Record<PersonaKey, readonly string[]>> = {
  admin: ['Dashboard', 'Access management'],
  admin2: ['Dashboard', 'Access management'],
  member: ['Dashboard'],
  roleManager: ['Dashboard', 'Access management'],
  userManager: ['Dashboard', 'Access management'],
  locked: [],
  pending: [],
  otherTenantAdmin: [],
};

test.describe('signed-in shell', () => {
  for (const key of SIGN_IN_PERSONAS) {
    test.describe(`persona ${key}`, () => {
      test('shows exactly its navigation entries', async ({ personaContext }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await page.goto('/dashboard');
          const nav = page.getByRole('navigation', { name: 'Primary' });
          await expect(nav.getByRole('link')).toHaveCount(NAV_LABELS[key].length);
          for (const label of NAV_LABELS[key]) {
            await expect(nav.getByRole('link', { name: label, exact: true })).toBeVisible();
          }
        } finally {
          await page.close();
        }
      });

      test('dashboard has no serious accessibility violations', async ({ personaContext }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await page.goto('/dashboard');
          await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible();
          await expectNoSeriousA11yViolations(page);
        } finally {
          await page.close();
        }
      });
    });
  }

  test('exposes landmarks and a skip link that moves focus to main', async ({ personaContext }) => {
    const page = await (await personaContext('member')).newPage();
    try {
      await page.goto('/dashboard');
      await expect(page.getByRole('banner')).toBeVisible();
      await expect(page.getByRole('navigation', { name: 'Primary' })).toBeVisible();
      await expect(page.getByRole('main')).toBeVisible();

      await page.keyboard.press('Tab');
      const skipLink = page.getByTestId('skip-link');
      await expect(skipLink).toBeFocused();
      await expect(skipLink).toBeVisible();

      await page.keyboard.press('Enter');
      await expect(page.locator('#main-content')).toBeFocused();
    } finally {
      await page.close();
    }
  });

  test('shows the signed-in role in the header', async ({ personaContext }) => {
    const page = await (await personaContext('member')).newPage();
    try {
      await page.goto('/dashboard');
      await expect(page.getByTestId('user-label')).toContainText('MEMBER');
    } finally {
      await page.close();
    }
  });
});
