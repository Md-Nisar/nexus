# US-006 Operational Runbook

## Scenario 1 — A legitimate user is locked out

**Symptoms:** User reports they cannot log in; they receive "Account locked" or HTTP 423.

**Diagnosis:**
```sql
SELECT id, status, failed_attempt_count, locked_until
FROM users
WHERE email_hmac = '<hmac of user email>';
-- email_hmac = SHA256-HMAC(lower(trim(email)), NEXUS_IDENTITY_HMAC_KEY)
```

If `status = 'LOCKED'` and `locked_until > NOW()`: account is legitimately locked (5+ failures).

**Resolution options:**

Option A — Wait for auto-expiry (15 minutes from lockout time):
- The lock expires automatically when `locked_until` passes.
- The user must then provide correct credentials.
- No action needed if lockout was recent and the user understands the wait.

Option B — Immediately unlock via SQL (use sparingly; requires DB access):
```sql
UPDATE users
SET status = 'ACTIVE', failed_attempt_count = 0, locked_until = NULL
WHERE id = UNHEX(REPLACE('<userId-uuid>', '-', ''));
```

Option C — Direct the user to US-007 password reset:
- `POST /api/v1/auth/password/reset-request` (US-007, when available).
- This resets the account AND revokes all refresh families.

---

## Scenario 2 — Many users are being locked out simultaneously (suspected attack)

**Symptoms:** Alert fires on `ACCOUNT_LOCKED` > 10 in 15 minutes, or support tickets spike.

**Diagnosis:**
```sql
-- Which accounts locked in last 15 minutes?
SELECT u.id, ae.metadata
FROM auth_events ae
JOIN users u ON u.id = ae.user_id
WHERE ae.event_type = 'ACCOUNT_LOCKED'
  AND ae.recorded_at > NOW() - INTERVAL 15 MINUTE
ORDER BY ae.recorded_at DESC;

-- Are they all from the same IP? (metadata JSON contains ipAddress)
SELECT JSON_EXTRACT(metadata, '$.ipAddress') as ip, COUNT(*) as cnt
FROM auth_events
WHERE event_type = 'LOGIN_FAILURE'
  AND recorded_at > NOW() - INTERVAL 15 MINUTE
GROUP BY ip
ORDER BY cnt DESC
LIMIT 20;
```

**Response options:**
1. Block the attacking IP at the load balancer / WAF (outside Nexus).
2. If distributed (many IPs), engage the IP-rate-limit tuning (lower `ip-max-attempts`, shorten `ip-window-seconds`) via config update and redeploy.
3. Mass-unlock legitimate users:
   ```sql
   -- Carefully review before running — only unlock accounts locked after the attack started
   UPDATE users SET status = 'ACTIVE', failed_attempt_count = 0, locked_until = NULL
   WHERE status = 'LOCKED' AND locked_until > NOW();
   ```
4. If attack is ongoing and cannot be blocked: disable the login feature flag temporarily (see [rollback.md](rollback.md)).

---

## Scenario 3 — `ACCOUNT_LOCKED_WRITE_FAILED` alert fires

**Symptoms:** Alert on `ACCOUNT_LOCKED_WRITE_FAILED` events in `auth_events`, or WARN logs with `msg="ACCOUNT_LOCKED_WRITE_FAILED"`.

**What this means:** The inner `REQUIRES_NEW` transaction in `SecureEventService.persistFailedAttempt` threw a non-optimistic exception. The failure counter was NOT persisted. If sustained, the lockout mechanism is disabled.

**Diagnosis:**
```bash
# Check application logs for the exception detail
grep "ACCOUNT_LOCKED_WRITE_FAILED" /var/log/nexus-backend.log | tail -20

# Check HikariCP pool exhaustion
curl http://localhost:1000/actuator/metrics/hikaricp.connections.pending

# Check MySQL deadlocks
mysql -e "SHOW ENGINE INNODB STATUS\G" | grep -A 30 "DEADLOCK"
```

**Root causes:**
- **Connection pool exhaustion**: Increase `spring.datasource.hikari.maximum-pool-size`. For virtual threads, a pool of 10 is typically sufficient; if `persistFailedAttempt` sees pool exhaustion, the outer login request pool size may need adjustment.
- **Deadlock**: Two concurrent REQUIRES_NEW TXs on the same `userId` may deadlock on the `version` column. The optimistic-lock path normally handles this — if deadlocks occur, confirm the `@Version` column has an index.
- **MySQL connectivity**: Check network / DB health separately.

**Immediate mitigation:** If the lockout mechanism is disabled by sustained write failures, users remain at risk of brute-force. Consider lowering `ip-max-attempts` to 3 (as an emergency compensating control) until the root cause is fixed.

---

## Scenario 4 — Smoke test after deployment

Run these in order after deploying US-006:

1. **Health check:**
   ```bash
   curl http://localhost:1000/actuator/health
   # expect: {"status":"UP"}
   ```

2. **Login with wrong password — should return 401:**
   ```bash
   curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:1000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"nonexistent@example.com","password":"Wrong1234!"}'
   # expect: 401
   ```

3. **Verify `Retry-After` header on 423:**
   After 5 failed attempts on a test account (see test setup in `LoginLockoutIT`), the 6th attempt should return HTTP 423 with `Retry-After` header present and `code: AUTH_LCK_001` in body.

4. **Verify rate-limit 429:**
   ```bash
   for i in {1..12}; do
     curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:1000/api/v1/auth/login \
       -H "Content-Type: application/json" \
       -d '{"email":"test@example.com","password":"pass"}';
   done
   # expect: 401 401 401 401 401 401 401 401 401 401 429 429
   ```

5. **Config validation:**
   ```bash
   curl http://localhost:1000/actuator/env | grep -A1 "ip-max-attempts"
   # expect: {"value":"10"}
   ```

---

## Scenario 5 — `Thread.sleep` flaky test in CI (`RateLimitIT`)

**Symptoms:** `RateLimitIT.rate_limit_resets_after_window` fails intermittently in CI with a timeout or assertion failure.

**Context:** This test uses `Thread.sleep(11_000L)` to wait for the 10-second window to expire (pre-existing, not introduced by US-006).

**Short-term workaround:** Re-run the CI job. The test is non-deterministic under load.

**Long-term fix:** Inject a `FakeClock` (or `java.time.Clock`) into `InMemoryRateLimitStore` and advance it programmatically in the test — no real-time sleep needed. See `08-test-audit.md` for details.
