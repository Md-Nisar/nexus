import { Page, Response } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { PERSONAS } from '../fixtures/personas';
import { enterAddress } from '../fixtures/secret-input';
import { expect, test } from '../fixtures/test';

// The users list renders directory addresses; no trace is recorded, so nothing personal reaches
// the uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-015: the users list and the exact-email lookup, as the role-reader user manager
 * (`user:directory:read`, not an administrator). Reads only: nothing here changes a user or an
 * assignment.
 *
 * PII (design §19.3): rows are asserted by test id and count, never by address text; every
 * address is typed with `enterAddress`, so none reaches a step title; no assertion compares a
 * request body or a cell with an address, so none can appear in a failure message.
 */
const PERSONA = 'roleReaderUserManager';

function rows(page: Page) {
  return page.getByTestId('user-row-email');
}

function isListResponse(response: Response): boolean {
  return (
    response.request().method() === 'GET' && new URL(response.url()).pathname === '/api/v1/users'
  );
}

function isLookupResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/api/v1/users/lookup'
  );
}

/** Opens the list and waits for its one GET; returns that response. */
async function openUsers(page: Page, query = ''): Promise<Response> {
  const loaded = page.waitForResponse(isListResponse);
  await page.goto(`/admin/access/users${query}`);
  return loaded;
}

async function lookUp(page: Page, address: string): Promise<Response> {
  const field = page.getByRole('searchbox', { name: 'Find by email' });
  await enterAddress(field, address);
  const answered = page.waitForResponse(isLookupResponse);
  await field.press('Enter');
  return answered;
}

test.describe('users list', () => {
  test('lists users with status, verification and join date, counted by test id', async ({
    personaContext,
  }) => {
    const page = await (await personaContext(PERSONA)).newPage();
    try {
      const response = await openUsers(page);
      expect(response.ok()).toBe(true);

      await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
      await expect(rows(page).first()).toBeVisible();
      const count = await rows(page).count();
      expect(count).toBeGreaterThan(0);
      await expect(page.getByTestId('user-status-badge')).toHaveCount(count);
      await expect(page.getByTestId('user-verified')).toHaveCount(count);
      // Each address links to its user page by id (T-016).
      await expect(page.locator('tbody a').first()).toHaveAttribute(
        'href',
        /^\/admin\/access\/users\/[0-9a-f-]{36}$/,
      );
    } finally {
      await page.close();
    }
  });

  test('the status filter writes status to the URL, sends it, and every row matches', async ({
    personaContext,
  }) => {
    const page = await (await personaContext(PERSONA)).newPage();
    try {
      await openUsers(page);
      await expect(rows(page).first()).toBeVisible();

      const filtered = page.waitForResponse(isListResponse);
      await page.getByRole('combobox', { name: 'Status' }).click();
      await page.getByRole('option', { name: 'Active', exact: true }).click();
      const response = await filtered;

      expect(new URL(response.url()).searchParams.get('status')).toBe('ACTIVE');
      await expect(page).toHaveURL(/[?&]status=active(&|$)/);
      await expect(rows(page).first()).toBeVisible();
      const statuses = await page
        .getByTestId('user-status-badge')
        .evaluateAll((nodes) => nodes.map((node) => node.getAttribute('data-status')));
      expect(statuses.length).toBeGreaterThan(0);
      expect(new Set(statuses)).toEqual(new Set(['ACTIVE']));

      await page.goBack();
      await expect(page).not.toHaveURL(/status=/);
    } finally {
      await page.close();
    }
  });

  test('page in the URL is 1-based and requested 0-based, and survives a reload', async ({
    personaContext,
  }) => {
    const page = await (await personaContext(PERSONA)).newPage();
    try {
      const response = await openUsers(page, '?page=2&size=10');
      const sent = new URL(response.url()).searchParams;
      expect(sent.get('page')).toBe('1');
      expect(sent.get('size')).toBe('10');
      expect(response.ok()).toBe(true);

      const reloaded = page.waitForResponse(isListResponse);
      await page.reload();
      expect(new URL((await reloaded).url()).searchParams.get('page')).toBe('1');
      await expect(page).toHaveURL(/page=2&size=10/);
    } finally {
      await page.close();
    }
  });

  test('a page beyond the 10,000 offset shows the "past the end" copy and a way back', async ({
    personaContext,
  }) => {
    const page = await (await personaContext(PERSONA)).newPage();
    try {
      const response = await openUsers(page, '?page=502');
      expect(response.status()).toBe(400);

      await expect(page.getByTestId('users-offset')).toContainText(
        'This page is past the end of the list. Use the status filter to narrow it.',
      );
      const first = page.waitForResponse(isListResponse);
      await page.getByTestId('users-first-page').getByRole('button').click();
      expect((await first).ok()).toBe(true);
      await expect(page).not.toHaveURL(/page=/);
      await expect(rows(page).first()).toBeVisible();
    } finally {
      await page.close();
    }
  });

  test('lookup finds the assignment target as the one result; the address never enters the URL', async ({
    personaContext,
  }) => {
    const page = await (await personaContext(PERSONA)).newPage();
    try {
      await openUsers(page, '?status=active');
      await expect(rows(page).first()).toBeVisible();

      const response = await lookUp(page, PERSONAS.targetA.email);
      expect(response.ok()).toBe(true);
      expect(response.url()).not.toMatch(/@|%40/);

      const result = page.getByTestId('users-lookup-result');
      await expect(result.locator('caption')).toHaveText('Lookup result');
      await expect(result.getByTestId('user-row-email')).toHaveCount(1);
      await expect(result.getByTestId('user-status-badge')).toHaveAttribute(
        'data-status',
        'ACTIVE',
      );
      expect(page.url()).not.toMatch(/@|%40/);
      await expect(page).toHaveURL(/\/admin\/access\/users\?status=active$/);

      // Clear returns to the list.
      await page.getByTestId('nx-search-clear').click();
      await expect(page.getByTestId('users-lookup-result')).toHaveCount(0);
      await expect(page.getByTestId('users-list')).toBeVisible();
    } finally {
      await page.close();
    }
  });

  test('a lookup miss says no one has this address', async ({ personaContext }) => {
    const page = await (await personaContext(PERSONA)).newPage();
    try {
      await openUsers(page);
      // A reserved, never-delivered domain (RFC 2606): no real person has it.
      const response = await lookUp(page, `no-such-person-${Date.now()}@lookup-miss.invalid`);
      expect(response.ok()).toBe(true);

      await expect(page.getByTestId('users-lookup-miss')).toContainText(
        'No one in your organisation has this email address.',
      );
      await expect(rows(page)).toHaveCount(0);
      expect(page.url()).not.toMatch(/@|%40/);
    } finally {
      await page.close();
    }
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      const page = await (await personaContext(PERSONA)).newPage();
      try {
        await page.emulateMedia({ colorScheme: scheme });
        await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
        await openUsers(page);
        await expect(rows(page).first()).toBeVisible();
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await expectNoSeriousA11yViolations(page);
      } finally {
        await page.close();
      }
    });
  }
});
