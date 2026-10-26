import { Page } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { expect, test } from '../fixtures/test';

// The catalogue lists tenant-independent permission codes, but no trace is recorded so nothing
// personal reaches the uploaded report (file-level: Playwright does not allow a trace override
// inside a group).
test.use({ trace: 'off' });

/** US-020 T-008: the permission catalogue, read-only, for a role reader. */
async function openCatalogue(page: Page, query = ''): Promise<void> {
  const loaded = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      new URL(response.url()).pathname === '/api/v1/permissions' &&
      response.ok(),
  );
  await page.goto(`/admin/access/permissions${query}`);
  await loaded;
  await expect(page.getByTestId('catalogue-count')).toBeVisible();
}

test.describe('permission catalogue', () => {
  test('lists the permissions grouped by resource, with Sensitive explained as visible text', async ({
    personaContext,
  }) => {
    const page = await (await personaContext('roleManager')).newPage();
    try {
      await openCatalogue(page);

      await expect(page.getByRole('heading', { level: 1, name: 'Permissions' })).toBeVisible();
      await expect(page.getByRole('heading', { level: 2, name: 'Tenant' })).toBeVisible();
      await expect(page.getByRole('heading', { level: 2, name: 'Roles' })).toBeVisible();
      await expect(
        page.getByTestId('permission-code').filter({ hasText: /^role:read$/ }),
      ).toBeVisible();
      await expect(page.getByTestId('sensitive-badge').first()).toBeVisible();

      await page.getByText('What does Sensitive mean?').click();
      await expect(page.getByTestId('sensitive-definition')).toContainText(
        'Sensitive permissions control users, roles',
      );
    } finally {
      await page.close();
    }
  });

  test('search writes q to the URL, narrows the list, and survives a reload', async ({
    personaContext,
  }) => {
    const page = await (await personaContext('roleManager')).newPage();
    try {
      await openCatalogue(page);
      const search = page.getByRole('searchbox', { name: 'Search permissions' });
      await search.fill('audit');
      await search.press('Enter');
      await expect(page).toHaveURL(/[?&]q=audit(&|$)/);
      await expect(page.getByTestId('permission-code')).toHaveText(['audit:read']);

      await page.reload();
      await expect(page.getByRole('searchbox', { name: 'Search permissions' })).toHaveValue(
        'audit',
      );
      await expect(page.getByTestId('permission-code')).toHaveText(['audit:read']);
    } finally {
      await page.close();
    }
  });

  test('shows "No permissions match your search" for a search nothing matches', async ({
    personaContext,
  }) => {
    const page = await (await personaContext('roleManager')).newPage();
    try {
      await openCatalogue(page, '?q=zz-no-such-permission-zz');
      await expect(page.getByTestId('nx-empty-state')).toContainText(
        'No permissions match your search',
      );
    } finally {
      await page.close();
    }
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      const page = await (await personaContext('roleManager')).newPage();
      try {
        await page.emulateMedia({ colorScheme: scheme });
        await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
        await openCatalogue(page);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await page.getByText('What does Sensitive mean?').click();
        await expectNoSeriousA11yViolations(page);
      } finally {
        await page.close();
      }
    });
  }
});
