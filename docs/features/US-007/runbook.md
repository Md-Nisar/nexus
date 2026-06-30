# Runbook — US-007: Self-Service Password Reset

---

## Scenario 1: User says "I never received the reset email"

**Likely causes:** email in spam, SMTP delivery failure, wrong email address, or account does not exist.

**Diagnostic steps:**

1. Check SMTP delivery logs on the mail relay for the user's address within the last hour.
2. Query `auth_events`:
   ```sql
   SELECT event_type, outcome, created_at, ip_address
   FROM auth_events
   WHERE event_type IN ('PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_THROTTLED')
     AND created_at > NOW() - INTERVAL 2 HOUR
   ORDER BY created_at DESC;
   ```
   - If `PASSWORD_RESET_REQUESTED` exists → reset token was generated; check SMTP relay.
   - If no row → either account does not exist for that email, or the request was not received (frontend issue).
   - If `PASSWORD_RESET_THROTTLED` → user hit 3/hour limit; advise waiting or check for abuse.

3. Check `MailEventListener` logs for `ERROR` or `WARN` from SMTP send:
   ```
   ERROR ... SmtpMailSenderAdapter : Failed to send password reset email ...
   ```
4. Verify `NEXUS_FRONTEND_BASE_URL` is set correctly — malformed URL would produce a working email with a broken link.

**Resolution:** If SMTP is healthy and the account exists, advise user to check spam folder or wait a few minutes. If `PASSWORD_RESET_THROTTLED`, advise waiting 1 hour.

---

## Scenario 2: User says "The reset link says it's expired or already used"

**HTTP 410, code `AUTH_RST_002`.**

**Likely causes:**
- Token expired (> 1 hour since email sent).
- Token already consumed (user clicked the link twice, or used an older email when a newer one was requested).
- Token URL was corrupted (copy-paste truncation, email client link-wrapping).
- Concurrent duplicate submission (browser double-click or page refresh during submit).

**Diagnostic steps:**

1. Check `auth_events` for `PASSWORD_RESET_FAILED` near the time of the complaint:
   ```sql
   SELECT created_at, ip_address, metadata
   FROM auth_events
   WHERE event_type = 'PASSWORD_RESET_FAILED'
     AND created_at > NOW() - INTERVAL 1 HOUR
   ORDER BY created_at DESC
   LIMIT 20;
   ```
2. Check `auth_tokens` for tokens of type RESET for the user:
   ```sql
   SELECT id, created_at, expires_at, consumed_at
   FROM auth_tokens
   WHERE user_id = '<uuid>'
     AND type = 'RESET'
   ORDER BY created_at DESC
   LIMIT 5;
   ```
   - `consumed_at IS NOT NULL` → already used; user must request a new one.
   - `expires_at < NOW()` → expired; user must request a new one.

**Resolution:** Advise user to request a new reset link. If `consumed_at` is null and not expired, suspect URL corruption; ask user to copy-paste the full URL from the email.

---

## Scenario 3: Alert: high rate of `PASSWORD_RESET_FAILED` events

**Possible token-guessing attack or rate-limit misconfiguration.**

**Diagnostic steps:**

1. Check originating IPs:
   ```sql
   SELECT ip_address, COUNT(*) as n
   FROM auth_events
   WHERE event_type = 'PASSWORD_RESET_FAILED'
     AND created_at > NOW() - INTERVAL 1 HOUR
   GROUP BY ip_address
   ORDER BY n DESC
   LIMIT 10;
   ```
2. Cross-reference with 429 responses on `POST /reset` in the access log. If 429s are being served → rate limiter is working; the failures hitting the application are within the allowed window.
3. If no 429s and high failure volume from few IPs → rate limiter key may not be routing correctly (check `getRemoteAddr()` vs. proxy topology).

**Mitigations:**
- Block offending IPs at the load balancer / WAF layer.
- Lower `nexus.security.rate-limit.reset-ip-max-attempts` temporarily.
- Verify 256-bit entropy in `TokenGenerator` output (check logs for unusual token lengths).

---

## Scenario 4: Alert: `SESSION_REVOCATION_PARTIAL` WARN log

**Meaning:** `revokeAllUserSessions()` threw a `RuntimeException` during a password reset. The password change committed, but one or more refresh-token families may not have been revoked.

**Diagnostic steps:**

1. Read the WARN log for `reason=` — determine the root cause (DB connection failure, `@Version` conflict, etc.).
2. Identify the affected `userId` from the log.
3. Manually revoke sessions:
   ```sql
   UPDATE auth_tokens
   SET revoked_at = NOW()
   WHERE user_id = '<uuid>'
     AND type = 'REFRESH'
     AND revoked_at IS NULL;
   ```
4. Verify the fix:
   ```sql
   SELECT COUNT(*) FROM auth_tokens
   WHERE user_id = '<uuid>' AND type = 'REFRESH' AND revoked_at IS NULL;
   -- Expected: 0
   ```

**Resolution:** Notify the user that they should re-authenticate. Investigate the root cause of the revocation failure (usually a transient DB issue).

---

## Scenario 5: User reports being rate-limited (429) on `/forgot`

**Two possible causes:** per-IP limit (`forgot-ip-max-attempts`) or per-email limit (`user-max-attempts`).

**Diagnostic steps:**

1. `Retry-After` header in the 429 response tells the user how long to wait.
2. Check `FORGOT_IP:<ip>` and `FORGOT_USER:<hmac>` keys in the rate-limit store (Redis):
   ```bash
   redis-cli get "FORGOT_IP:1.2.3.4"
   ```
3. If legitimate user hitting per-email limit: check `PASSWORD_RESET_THROTTLED` events; they may have requested several resets and the filter-level limit fired before the DB throttle.

**Resolution:** Either wait for the window to expire, or manually delete the rate-limit key in Redis:
```bash
redis-cli del "FORGOT_IP:1.2.3.4"
```
For the in-memory store, restart the service (clears all buckets).

---

## Scenario 6: `POST /forgot` returns 500

**Unexpected application error during reset request.**

**Diagnostic steps:**

1. Check application logs around the time of the 500 for stack traces.
2. Common causes:
   - `EmailBlindIndexService` misconfigured (HMAC key missing or changed) → check `NEXUS_EMAIL_BLIND_INDEX_SECRET`.
   - Mail infrastructure down (`SmtpMailSenderAdapter` can throw from async context — check MailEventListener thread).
   - `SecureEventService.recordEvent()` failing (DB connectivity, `auth_events` schema issue).

3. Verify DB connectivity:
   ```bash
   curl -s https://<host>/actuator/health | python3 -m json.tool | grep -A3 db
   ```

**Resolution:** Address root cause. The `/forgot` use case is designed to not leak error details; a 500 means an internal bug or infra failure, not bad input.
