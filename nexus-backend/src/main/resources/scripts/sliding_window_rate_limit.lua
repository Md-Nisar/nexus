-- Atomic sliding-window-log rate limit check (ADR 0016 / docs/redis-integration-plan.md §5.1).
-- Preserves InMemoryRateLimitStore's exact semantics: Retry-After is the time until the
-- OLDEST tracked request's window expires, not the full window duration.
--
-- KEYS[1] = redis key (sorted set)
-- ARGV[1] = now (epoch millis), ARGV[2] = window size (millis), ARGV[3] = max attempts
-- Returns: {1, 0} if permitted; {0, retryAfterSeconds} if rejected.
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local maxAttempts = tonumber(ARGV[3])
local windowStart = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)
local count = redis.call('ZCARD', key)

if count >= maxAttempts then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retryAfterMs = window - (now - tonumber(oldest[2]))
  return {0, math.max(1, math.ceil(retryAfterMs / 1000))}
else
  redis.call('ZADD', key, now, now .. '-' .. math.random(100000))
  redis.call('PEXPIRE', key, window)
  return {1, 0}
end
