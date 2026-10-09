import { randomBytes } from 'k6/crypto';
import { fail } from 'k6';
import { config } from '../config/environment.js';

/**
 * Guards for scenarios that register accounts (pre-PR security review L-4). The API has no user
 * delete, so a run leaves verified accounts behind: it must not start against a shared
 * environment by accident, and those accounts must not share a committed password.
 */

/** Hosts that are a local app or a compose service name (no dot): a disposable stack. */
function isDisposableHost(baseUrl) {
  const authority = baseUrl.replace(/^https?:\/\//, '').split('/')[0];
  if (authority.startsWith('[::1]')) {
    return true;
  }
  const host = authority.split(':')[0];
  return host === 'localhost' || /^127\./.test(host) || !host.includes('.');
}

/** Refuses to continue against anything but a local or compose host, unless explicitly allowed. */
export function requireWritableTarget(scenario) {
  if (__ENV.ALLOW_WRITE_SCENARIO === 'true' || isDisposableHost(config.baseUrl)) {
    return;
  }
  fail(
    `${scenario} registers accounts that cannot be deleted. Run it against a disposable ` +
      `stack (localhost or a compose host), or set ALLOW_WRITE_SCENARIO=true to accept that.`,
  );
}

/** A password for this run only: never committed, never reused between runs. */
export function runPassword() {
  const hex = Array.from(new Uint8Array(randomBytes(16)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `Pf-${hex}-9aA!`;
}
