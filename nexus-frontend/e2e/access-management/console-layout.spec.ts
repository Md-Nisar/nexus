import { Page, Request } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { PersonaKey } from '../fixtures/personas';
import { expect, test } from '../fixtures/test';

// The console renders signed-in data; no trace is recorded, so nothing personal reaches the
// uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

const PROFILE_PATH = '/api/v1/users/me/authorization';

/**
 * US-020 T-006: console entry through the layout. `/admin/access` sends a role reader to Roles
 * (firstAreaRedirect), the area sub-nav shows the areas each persona's JWT holds, and the live
 * profile is read exactly once per entry. Needs the Roles page (T-007), which ships in the same
 * S1e PR.
 */
const AREAS: Readonly<Partial<Record<PersonaKey, readonly string[]>>> = {
  admin: ['Roles', 'Permissions', 'Users'],
  roleManager: ['Roles', 'Permissions'],
};

function isProfileRead(request: Request): boolean {
  return request.method() === 'GET' && new URL(request.url()).pathname === PROFILE_PATH;
}

function areaNav(page: Page) {
  // mat-tab-nav-bar with a tab panel is exposed as a tablist, not a navigation landmark.
  return page.getByRole('tablist', { name: 'Access management areas' });
}

test.describe('access console layout', () => {
  for (const [key, labels] of Object.entries(AREAS) as [PersonaKey, readonly string[]][]) {
    test.describe(`persona ${key}`, () => {
      test('enters on Roles with its areas and exactly one profile read, no read-only banner', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        const profileReads: Request[] = [];
        page.on('request', (request) => {
          if (isProfileRead(request)) profileReads.push(request);
        });
        try {
          const profile = page.waitForResponse((response) => isProfileRead(response.request()));
          await page.goto('/admin/access');
          await expect(page).toHaveURL(/\/admin\/access\/roles$/);
          expect((await profile).status()).toBe(200);

          const nav = areaNav(page);
          await expect(nav.getByRole('tab')).toHaveCount(labels.length);
          for (const label of labels) {
            await expect(nav.getByRole('tab', { name: label, exact: true })).toBeVisible();
          }
          await expect(page.getByTestId('access-console-read-only')).toHaveCount(0);
          expect(profileReads).toHaveLength(1);
        } finally {
          await page.close();
        }
      });

      for (const scheme of ['light', 'dark'] as const) {
        test(`has no serious accessibility violations in ${scheme} mode`, async ({
          personaContext,
        }) => {
          const page = await (await personaContext(key)).newPage();
          try {
            await page.emulateMedia({ colorScheme: scheme });
            await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
            await page.goto('/admin/access');
            await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
            await expect(areaNav(page)).toBeVisible();
            await expectNoSeriousA11yViolations(page);
          } finally {
            await page.close();
          }
        });
      }
    });
  }
});
