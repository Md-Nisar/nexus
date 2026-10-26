import { Page, Response } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { PersonaKey } from '../fixtures/personas';
import { expect, test } from '../fixtures/test';

// The role detail renders tenant data; no trace is recorded, so nothing personal reaches the
// uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-009: the role detail page and its read-only permission matrix, for a system role and a
 * custom role. Both personas hold role:read and role:write. Reads only: nothing here creates or
 * changes a role ("Edit permissions" and "Clone" are asserted, never followed).
 */
const PERSONAS_UNDER_TEST: readonly PersonaKey[] = ['admin', 'roleManager'];

/** Seeded by the dev profile: a system role, and the custom role the role manager holds. */
const SYSTEM_ROLE = 'TENANT_ADMIN';
const CUSTOM_ROLE = 'Role Manager';

const ROLE_PATH = /^\/api\/v1\/roles\/[^/]+$/;
const SET_PATH = /^\/api\/v1\/roles\/[^/]+\/permissions$/;

function isGet(response: Response, path: RegExp): boolean {
  return (
    response.request().method() === 'GET' &&
    path.test(new URL(response.url()).pathname) &&
    response.ok()
  );
}

/** Opens a role from the roles list by its exact name, and waits for its two reads. */
async function openRole(page: Page, name: string): Promise<void> {
  await page.goto(`/admin/access/roles?q=${encodeURIComponent(name)}`);
  const link = page.getByRole('link', { name, exact: true });
  await expect(link).toBeVisible();
  const role = page.waitForResponse((response) => isGet(response, ROLE_PATH));
  const set = page.waitForResponse((response) => isGet(response, SET_PATH));
  await link.click();
  await Promise.all([role, set]);
  await expect(page).toHaveURL(/\/admin\/access\/roles\/[^/]+\/permissions$/);
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
}

test.describe('role detail', () => {
  for (const key of PERSONAS_UNDER_TEST) {
    test.describe(`persona ${key}`, () => {
      test('a system role shows the banner and Clone, and no edit control at all', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRole(page, SYSTEM_ROLE);

          await expect(page.getByTestId('system-role-badge')).toHaveAttribute(
            'data-kind',
            'system',
          );
          await expect(page.getByTestId('role-system-banner')).toContainText(
            "This is a system role. Its permissions can't be changed.",
          );
          await expect(page.getByTestId('role-edit')).toHaveCount(0);
          await expect(page.getByText('Edit permissions')).toHaveCount(0);
          await expect(page.getByTestId('role-clone')).toBeVisible();

          const breadcrumb = page.getByRole('navigation', { name: 'Breadcrumb' });
          await expect(breadcrumb.getByRole('link', { name: 'Roles' })).toBeVisible();
          await expect(breadcrumb.locator('[aria-current="page"]')).toHaveText(SYSTEM_ROLE);

          const matrix = page.getByRole('table', { name: `Permissions granted by ${SYSTEM_ROLE}` });
          await expect(matrix).toBeVisible();
          await expect(matrix.getByRole('columnheader', { name: 'Status' })).toBeVisible();
          await expect(matrix.getByTestId('matrix-status').first()).toContainText('Granted');
          await expect(matrix.locator('input[type="checkbox"]')).toHaveCount(0);
        } finally {
          await page.close();
        }
      });

      test('a custom role offers "Edit permissions", saving is available', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRole(page, CUSTOM_ROLE);

          await expect(page.getByTestId('system-role-badge')).toHaveAttribute(
            'data-kind',
            'custom',
          );
          await expect(page.getByTestId('role-system-banner')).toHaveCount(0);
          const edit = page.getByTestId('role-edit').getByRole('button');
          await expect(edit).toHaveText(/Edit permissions/);
          // A strong ETag reached the browser, so saving is not switched off (design §7.2).
          await expect(edit).not.toHaveAttribute('aria-disabled', 'true');
          await expect(page.getByTestId('role-etag-banner')).toHaveCount(0);
          await expect(page.getByTestId('role-detail-counts')).toHaveText(
            /^\d+ permissions? · \d+ members?$/,
          );
          await expect(page.getByTestId('role-detail-updated')).toContainText('Updated');
        } finally {
          await page.close();
        }
      });

      test('Refresh re-reads the role and its permission set, and nothing else', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRole(page, CUSTOM_ROLE);
          const apiPaths: string[] = [];
          page.on('request', (request) => {
            const path = new URL(request.url()).pathname;
            if (path.startsWith('/api/')) apiPaths.push(`${request.method()} ${path}`);
          });

          const role = page.waitForResponse((response) => isGet(response, ROLE_PATH));
          const set = page.waitForResponse((response) => isGet(response, SET_PATH));
          await page.getByTestId('role-detail-refresh').getByRole('button').click();
          await Promise.all([role, set]);
          await expect(page.getByRole('heading', { level: 1, name: CUSTOM_ROLE })).toBeVisible();

          expect(apiPaths).toHaveLength(2);
          expect(
            apiPaths.filter((entry) => /^GET \/api\/v1\/roles\/[^/]+$/.test(entry)),
          ).toHaveLength(1);
          expect(
            apiPaths.filter((entry) => /^GET \/api\/v1\/roles\/[^/]+\/permissions$/.test(entry)),
          ).toHaveLength(1);
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
            await openRole(page, CUSTOM_ROLE);
            await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
            await expectNoSeriousA11yViolations(page);
          } finally {
            await page.close();
          }
        });
      }
    });
  }

  test('at 320 px the matrix becomes one section per resource, with no sideways scroll', async ({
    personaContext,
  }) => {
    const page = await (await personaContext('admin')).newPage();
    try {
      await page.setViewportSize({ width: 320, height: 800 });
      await openRole(page, SYSTEM_ROLE);

      await expect(page.getByRole('table')).toBeHidden();
      await expect(
        page.getByRole('heading', { level: 2, name: `Permissions granted by ${SYSTEM_ROLE}` }),
      ).toBeVisible();
      await expect(page.getByRole('heading', { level: 3, name: 'Roles' })).toBeVisible();
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(overflow).toBeLessThanOrEqual(0);
      await expectNoSeriousA11yViolations(page);
    } finally {
      await page.close();
    }
  });
});
