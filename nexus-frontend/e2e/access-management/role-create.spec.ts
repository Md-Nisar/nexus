import { APIRequestContext, BrowserContext, Page, Request } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { apiBase } from '../fixtures/backend';
import { expect, test } from '../fixtures/test';

// The pages render tenant data; no trace is recorded, so nothing of it reaches the uploaded report
// (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-013: creating and cloning a role (design §6.6, §11.3, §12.5, §19.3), and scenario 24
 * (FR-G9): a description with markup, stored by the server, renders as text.
 *
 * Every role is per worker, `e2e-w{worker}-{random}` (a clone is "Copy of" one), and is deleted in
 * `afterAll`. API calls use a bearer token taken from the persona context's own refresh cookie while
 * no page of that context is open (one page at a time per persona context, see `fixtures/test.ts`).
 */

/** Labels of the permissions used here (`copy/permission-labels.ts`, provisional D3). */
const LABELS = {
  'tenant:read': 'Read tenant configuration and metadata',
  'audit:read': 'Read the authentication and audit event trail',
} as const;

type Code = keyof typeof LABELS;

const ROLE_PAGE = /^\/admin\/access\/roles\/([0-9a-f-]{36})\/permissions$/;
const MARKUP = '<img src=x onerror=alert(1)>';

/** Roles this worker created, deleted in `afterAll`. */
const created: string[] = [];

interface PermissionPage {
  readonly data: readonly { readonly id: string; readonly name: string }[];
}

interface RbacClient {
  createRole(codes: readonly Code[], description?: string): Promise<{ id: string; name: string }>;
  readCodes(roleId: string): Promise<string[]>;
  deleteRole(roleId: string): Promise<number>;
}

async function rbacClient(context: BrowserContext): Promise<RbacClient> {
  const request: APIRequestContext = context.request;
  const refreshed = await request.post(`${apiBase}/api/v1/auth/refresh`);
  expect(refreshed.ok()).toBe(true);
  const session = (await refreshed.json()) as { accessToken: string; tokenType: string };
  const headers = { Authorization: `${session.tokenType} ${session.accessToken}` };

  const catalogue = await request.get(`${apiBase}/api/v1/permissions?page=0&size=100`, {
    headers,
  });
  expect(catalogue.ok()).toBe(true);
  const byName = new Map(
    ((await catalogue.json()) as PermissionPage).data.map((entry) => [entry.name, entry.id]),
  );

  const readSet = async (roleId: string) => {
    const response = await request.get(`${apiBase}/api/v1/roles/${roleId}/permissions`, {
      headers,
    });
    expect(response.ok()).toBe(true);
    return {
      codes: ((await response.json()) as PermissionPage).data.map((entry) => entry.name).sort(),
      etag: response.headers()['etag'] ?? '',
    };
  };

  return {
    async createRole(codes, description = 'Created by the role create end-to-end test') {
      const name = uniqueName();
      const response = await request.post(`${apiBase}/api/v1/roles`, {
        headers,
        data: { name, description },
      });
      expect(response.status()).toBe(201);
      const { id } = (await response.json()) as { id: string };
      created.push(id);
      if (codes.length > 0) {
        const { etag } = await readSet(id);
        const replaced = await request.put(`${apiBase}/api/v1/roles/${id}/permissions`, {
          headers: { ...headers, 'If-Match': etag },
          data: {
            permissionIds: codes.map((code) => {
              const permissionId = byName.get(code);
              if (permissionId === undefined) throw new Error(`${code} is not in the catalogue`);
              return permissionId;
            }),
          },
        });
        expect(replaced.status()).toBe(200);
      }
      return { id, name };
    },
    async readCodes(roleId) {
      return (await readSet(roleId)).codes;
    },
    async deleteRole(roleId) {
      return (await request.delete(`${apiBase}/api/v1/roles/${roleId}`, { headers })).status();
    },
  };
}

function uniqueName(): string {
  return `e2e-w${test.info().workerIndex}-${Math.random().toString(36).slice(2, 10)}`;
}

function checkbox(page: Page, code: Code) {
  return page.getByRole('checkbox', { name: `${LABELS[code]} (${code})`, exact: true });
}

function isRolesCall(request: Request, method: string, path: RegExp): boolean {
  return request.method() === method && path.test(new URL(request.url()).pathname);
}

async function openCreate(page: Page, query = ''): Promise<void> {
  await page.goto(`/admin/access/roles/new${query}`);
  await expect(page.getByTestId('role-create-submit')).toBeVisible();
}

/** Submits the form and returns the new role's id from the page it lands on. */
async function submitAndLand(page: Page): Promise<string> {
  await page.getByTestId('role-create-submit').getByRole('button').click();
  await page.waitForURL((url) => ROLE_PAGE.test(url.pathname));
  const id = ROLE_PAGE.exec(new URL(page.url()).pathname)?.[1] ?? '';
  created.push(id);
  await expect(page.getByTestId('role-detail-title')).toBeVisible();
  return id;
}

test.describe('role create and clone', () => {
  test.afterAll(async ({ personaContext }) => {
    if (created.length === 0) return;
    const admin = await rbacClient(await personaContext('admin'));
    for (const roleId of created.splice(0)) {
      expect([204, 404]).toContain(await admin.deleteRole(roleId));
    }
  });

  test('create without permissions sends one POST and lands on the new role', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const page = await context.newPage();
    const name = uniqueName();
    let id = '';
    try {
      const calls: string[] = [];
      page.on('request', (request) => {
        if (isRolesCall(request, 'POST', /^\/api\/v1\/roles$/)) calls.push('POST');
        if (isRolesCall(request, 'PUT', /^\/api\/v1\/roles\/[^/]+\/permissions$/))
          calls.push('PUT');
      });
      await openCreate(page);
      await page.getByLabel('Name', { exact: true }).fill(name);
      await page.getByLabel('Description', { exact: true }).fill('No permissions yet');
      id = await submitAndLand(page);

      await expect(page.getByTestId('role-detail-title')).toHaveText(name);
      expect(calls).toEqual(['POST']);
    } finally {
      await page.close();
    }
    expect(await (await rbacClient(context)).readCodes(id)).toEqual([]);
  });

  test('create with permissions sends POST, GET and one PUT with a strong If-Match', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const page = await context.newPage();
    let id = '';
    try {
      const puts: Request[] = [];
      page.on('request', (request) => {
        if (isRolesCall(request, 'PUT', /^\/api\/v1\/roles\/[^/]+\/permissions$/)) {
          puts.push(request);
        }
      });
      await openCreate(page);
      await page.getByLabel('Name', { exact: true }).fill(uniqueName());
      await checkbox(page, 'tenant:read').check();
      await checkbox(page, 'audit:read').check();
      await expect(page.getByTestId('role-create-propagation')).toBeVisible();
      id = await submitAndLand(page);

      expect(puts).toHaveLength(1);
      expect(puts[0].headers()['if-match']).toMatch(/^"[^"]+"$/);
    } finally {
      await page.close();
    }
    expect(await (await rbacClient(context)).readCodes(id)).toEqual(['audit:read', 'tenant:read']);
  });

  test('clone prefills "Copy of" the source and its permissions, and creates the copy', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const source = await (await rbacClient(context)).createRole(['tenant:read', 'audit:read']);
    const page = await context.newPage();
    let id = '';
    try {
      await page.goto(`/admin/access/roles/${source.id}/permissions`);
      await page.getByTestId('role-clone').getByRole('button').click();
      await page.waitForURL(`**/admin/access/roles/new?from=${source.id}`);

      await expect(page.getByLabel('Name', { exact: true })).toHaveValue(`Copy of ${source.name}`);
      await expect(checkbox(page, 'tenant:read')).toBeChecked();
      await expect(checkbox(page, 'audit:read')).toBeChecked();
      // An administrator can grant everything: nothing is left out.
      await expect(page.getByTestId('role-create-not-copied')).toHaveCount(0);
      id = await submitAndLand(page);

      await expect(page.getByTestId('role-detail-title')).toHaveText(`Copy of ${source.name}`);
    } finally {
      await page.close();
    }
    expect(await (await rbacClient(context)).readCodes(id)).toEqual(['audit:read', 'tenant:read']);
  });

  test('scenario 24: a description with markup renders as text on the list and the detail page', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const role = await (await rbacClient(context)).createRole([], MARKUP);
    const page = await context.newPage();
    try {
      let dialogs = 0;
      page.on('dialog', (dialog) => {
        dialogs += 1;
        void dialog.dismiss();
      });

      await page.goto(`/admin/access/roles?q=${encodeURIComponent(role.name)}`);
      const row = page.locator('tbody tr').filter({ hasText: role.name });
      await expect(row.getByTestId('role-description')).toContainText(MARKUP);
      await expect(page.locator('main img')).toHaveCount(0);

      await page.goto(`/admin/access/roles/${role.id}/permissions`);
      await expect(page.getByTestId('role-detail-description')).toHaveText(MARKUP);
      await expect(page.locator('main img')).toHaveCount(0);
      expect(dialogs).toBe(0);
    } finally {
      await page.close();
    }
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`the create page has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      const page = await (await personaContext('admin')).newPage();
      try {
        await page.emulateMedia({ colorScheme: scheme });
        await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
        await openCreate(page);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await expectNoSeriousA11yViolations(page);

        // With the error summary and field errors shown.
        await page.getByTestId('role-create-submit').getByRole('button').click();
        await expect(page.getByTestId('role-create-summary')).toBeVisible();
        await expectNoSeriousA11yViolations(page);
      } finally {
        await page.close();
      }
    });
  }
});
