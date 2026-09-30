import { check } from 'k6';

/**
 * Checks the status code plus any number of named predicates on the parsed JSON body.
 *
 * A body that is not JSON fails its body checks instead of throwing, so one bad response is
 * recorded against the `checks` threshold rather than aborting the iteration.
 *
 * @example checkResponse(res, 200, { 'status is UP': (body) => body.status === 'UP' });
 */
export function checkResponse(res, expectedStatus, bodyChecks = {}) {
  const body = parseJson(res);
  const checks = { [`status is ${expectedStatus}`]: (r) => r.status === expectedStatus };
  for (const [name, predicate] of Object.entries(bodyChecks)) {
    checks[name] = () => body !== undefined && predicate(body);
  }
  return check(res, checks);
}

function parseJson(res) {
  try {
    return res.json();
  } catch {
    return undefined;
  }
}
