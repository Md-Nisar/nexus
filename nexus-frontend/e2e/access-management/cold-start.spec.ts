import { Page, Request } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { requireBackend } from '../fixtures/backend';
import { expect, test } from '../fixtures/test';

// These specs render the dashboard, whose header shows the signed-in persona's address; a retry
// trace would carry it into the uploaded report and fail the PII scan. No trace is recorded
// (file-level: Playwright does not allow a trace override inside a describe group).
test.use({ trace: 'off' });

const REFRESH_PATH = '/api/v1/auth/refresh';

function isRefresh(request: Request): boolean {
  return request.method() === 'POST' && new URL(request.url()).pathname === REFRESH_PATH;
}

function isApiCall(request: Request): boolean {
  return new URL(request.url()).pathname.startsWith('/api/');
}

/** Every request the page issues, routed or not, including ones a route aborts. */
function recordRequests(page: Page): Request[] {
  const requests: Request[] = [];
  page.on('request', (request) => requests.push(request));
  return requests;
}

function retryButton(page: Page) {
  return page.getByTestId('unavailable-retry');
}

function unavailableHeading(page: Page) {
  return page.getByRole('heading', { level: 1, name: 'Nexus is temporarily unavailable' });
}

test.describe('cold-start deep link', () => {
  test('a signed-in user reloading a protected route stays on it', async ({ personaContext }) => {
    const page = await (await personaContext('member')).newPage();
    try {
      await page.goto('/dashboard');
      await expect(page.getByTestId('dashboard-root')).toBeVisible();
      await page.reload();
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.getByTestId('dashboard-root')).toBeVisible();
      await expect(page).toHaveTitle('Dashboard · Nexus');
    } finally {
      await page.close();
    }
  });

  test('the home URL reaches the dashboard for a signed-in user', async ({ personaContext }) => {
    const page = await (await personaContext('admin')).newPage();
    try {
      await page.goto('/');
      await expect(page).toHaveURL(/\/dashboard$/);
    } finally {
      await page.close();
    }
  });

  test('a signed-out visitor is sent to login, not to access denied', async ({ page }) => {
    // Only a real 401 from the refresh call redirects to login; a network error does not.
    await requireBackend();
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/auth\/login\?returnUrl=%2Fdashboard$/);
    await expect(page.getByTestId('login-submit')).toBeVisible();
  });
});

/**
 * US-020 T-002: when nobody authoritative answers the cold-start refresh, the user lands on the
 * static unavailable view; Retry, after the cool-down, re-enters through the shell with exactly
 * one more refresh.
 */
test.describe('unavailable view', () => {
  test('a refresh that never reaches Nexus shows the view; Retry after the countdown lands on the return URL', async ({
    personaContext,
  }) => {
    // The cool-down without Retry-After is 10 s plus up to 5 s of jitter.
    test.setTimeout(60_000);
    const page = await (await personaContext('admin')).newPage();
    const requests = recordRequests(page);
    let aborted = false;
    await page.route(`**${REFRESH_PATH}`, async (route) => {
      if (aborted) return route.continue();
      aborted = true;
      return route.abort('connectionrefused');
    });
    try {
      await page.goto('/dashboard');

      await expect(page).toHaveURL(/\/unavailable\?returnUrl=%2Fdashboard$/);
      await expect(unavailableHeading(page)).toBeFocused();
      await expect(retryButton(page)).toHaveAttribute('aria-disabled', 'true');
      await expect(page.getByTestId('unavailable-countdown')).toHaveText(/^\s*Retry in \d+ s\s*$/);
      expect(requests.filter(isRefresh)).toHaveLength(1);
      const apiCallsOnArrival = requests.filter(isApiCall).length;

      await expect(page.getByTestId('unavailable-countdown')).toHaveText('You can retry now.', {
        timeout: 20_000,
      });
      await expect(retryButton(page)).not.toHaveAttribute('aria-disabled');
      // The view itself made no request during the whole countdown.
      expect(requests.filter(isApiCall)).toHaveLength(apiCallsOnArrival);

      await retryButton(page).click();

      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.getByTestId('dashboard-root')).toBeVisible();
      expect(requests.filter(isRefresh)).toHaveLength(2);
    } finally {
      await page.close();
    }
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`a direct visit makes no API call and has no serious accessibility violations in ${scheme} mode`, async ({
      browser,
    }) => {
      test.setTimeout(60_000);
      const context = await browser.newContext({ colorScheme: scheme });
      await context.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
      const page = await context.newPage();
      const requests = recordRequests(page);
      try {
        await page.goto('/unavailable?returnUrl=%2Fdashboard');
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await expect(unavailableHeading(page)).toBeFocused();

        // During the countdown (exactly 10 s with no recorded state, RC-75) ...
        await expect(retryButton(page)).toHaveAttribute('aria-disabled', 'true');
        await expectNoSeriousA11yViolations(page);

        // ... and once Retry is available.
        await expect(page.getByTestId('unavailable-countdown')).toHaveText('You can retry now.', {
          timeout: 15_000,
        });
        await expectNoSeriousA11yViolations(page);
        expect(requests.filter(isApiCall)).toEqual([]);
      } finally {
        await context.close();
      }
    });
  }
});
