package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.rbac.application.port.out.EpochUnparseableException;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis store of the per-user permission epoch (US-018 A9, design §9.2). Key {@code
 * {keyPrefix}:rbac:epoch:{tenantId}:{userId}}, holding a millisecond value.
 *
 * <p>Reads use the dedicated 50 ms template and fail open: a failed or slow read returns empty,
 * which the caller counts. A value outside {@code 0..MAX_EPOCH} (digits only) throws {@link
 * EpochUnparseableException}, which the caller must not count (L-1). Bumps use the dedicated bump
 * template and throw on failure. Until a template's connection has been opened off-thread at startup, the read returns
 * empty and the bump throws immediately, without touching Redis: the first connection is never
 * made on a request thread (design §9.5).
 *
 * <p>The bump is one Lua script per call: for each key, {@code new = max(old + 1, Redis TIME in
 * ms)}, then {@code SET key new EX ttl}, then {@code DEL} of the user's cached roleset and permset
 * under {@code old} ({@code 0} when there was no key), the A10 holder eviction (design §9.2,
 * §9.4), and returns each user's new value so that no caller derives it from its own clock (H-2).
 * The Redis server's clock is the same for every instance, and the {@code max} keeps the
 * value monotonic even after the key is lost. Multi-key scripts, and building the cache keys inside
 * the script from the epoch it read, are legal only because Redis Cluster is rejected at startup
 * (ADR-0016 D1, {@link EpochRedisConfig}); {@link RbacRedisKeys} owns every key shape.
 */
@Component
public class RedisPermissionEpochAdapter implements PermissionEpochPort {

  private static final Logger log = LoggerFactory.getLogger(RedisPermissionEpochAdapter.class);

  /**
   * The largest valid epoch, {@code 2^53 - 2}. The bump script computes in Lua doubles, which hold
   * integers exactly only up to {@code 2^53}; the largest value it can write is {@code MAX_EPOCH}
   * itself, so every value the script writes is a value {@link #parse} accepts, and no valid value
   * is lowered by a bump. The millisecond clock reaches it in about 285,000 years.
   */
  static final long MAX_EPOCH = (1L << 53) - 2;

  /** The longest valid stored value: the digits of {@link #MAX_EPOCH}. */
  private static final int MAX_EPOCH_DIGITS = Long.toString(MAX_EPOCH).length();

  // KEYS[i] = epoch key of user i; ARGV[1] = key TTL; ARGV[2i] / ARGV[2i+1] = that user's roleset
  // / permset stem. The old epoch is formatted as Long.toString renders it, so the DEL hits the
  // entry a mint cached under it. Returns the new epoch of each user, in KEYS order, as strings.
  //
  // A stored value is valid only if it is 1 to 16 plain digits and at most MAX_EPOCH, the same
  // rule as parse() (L-1). tonumber() alone would also accept "nan", "inf", "0x10" and "1e3", and
  // Lua doubles lose integers above 2^53. Anything else counts as 0, so the bump writes Redis TIME.
  // The "v ~= v" test is a second guard against NaN. The new value is capped at MAX_EPOCH, so the
  // script never writes a value parse() rejects.
  @SuppressWarnings("rawtypes")
  private static final RedisScript<List> BUMP_SCRIPT = RedisScript.of("""
      local ttl = tonumber(ARGV[1])
      local maxEpoch = %d
      local time = redis.call('TIME')
      local nowMs = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
      local result = {}
      for i, key in ipairs(KEYS) do
        local old = 0
        local raw = redis.call('GET', key)
        if raw and string.len(raw) <= %d and string.find(raw, '^%%d+$') then
          local v = tonumber(raw)
          if v == v and v >= 0 and v <= maxEpoch then
            old = v
          end
        end
        local new = math.min(math.max(old + 1, nowMs), maxEpoch)
        redis.call('SET', key, string.format('%%.0f', new), 'EX', ttl)
        local oldEpoch = string.format('%%.0f', old)
        redis.call('DEL', ARGV[2 * i] .. oldEpoch, ARGV[2 * i + 1] .. oldEpoch)
        result[i] = string.format('%%.0f', new)
      end
      return result
      """.formatted(MAX_EPOCH, MAX_EPOCH_DIGITS), List.class);

  private final EpochTemplates templates;
  private final RbacRedisKeys keys;
  private final String keyTtlSeconds;

  public RedisPermissionEpochAdapter(
      EpochTemplates templates,
      @Value("${nexus.redis.key-prefix:nexus}") String keyPrefix,
      @Value("${nexus.rbac.epoch.key-ttl-seconds}") long keyTtlSeconds) {
    this.templates = templates;
    this.keys = new RbacRedisKeys(keyPrefix);
    this.keyTtlSeconds = Long.toString(keyTtlSeconds);
  }

  @Override
  public OptionalLong current(UUID tenantId, UUID userId) {
    if (!templates.readReady()) {
      return OptionalLong.empty();
    }
    String value;
    try {
      value = templates.read().opsForValue().get(keys.epoch(tenantId, userId));
    } catch (DataAccessException e) {
      // One line per failed request at DEBUG only; nexus.rbac.epoch.check{outcome=skipped_error}
      // is the signal.
      log.debug("permission epoch read failed exception={}", e.getClass().getSimpleName());
      return OptionalLong.empty();
    }
    return OptionalLong.of(value == null ? 0L : parse(value));
  }

  /**
   * A value that is not 1 to 16 plain digits within {@link
   * #MAX_EPOCH} is the key's problem, not the store's (L-1); the bump script applies the same rule.
   */
  private static long parse(String value) {
    if (!isValidEpoch(value)) {
      throw new EpochUnparseableException();
    }
    long epoch = Long.parseLong(value);
    if (epoch > MAX_EPOCH) {
      throw new EpochUnparseableException();
    }
    return epoch;
  }

  private static boolean isValidEpoch(String value) {
    if (value.isEmpty() || value.length() > MAX_EPOCH_DIGITS) {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c < '0' || c > '9') {
        return false;
      }
    }
    return true;
  }

  @Override
  public boolean probe() {
    if (!templates.readReady()) {
      return false;
    }
    try {
      return templates.read().execute((RedisCallback<String>) RedisConnection::ping) != null;
    } catch (RuntimeException e) {
      // Any failure, not only DataAccessException: the scheduler tick must account for it as an
      // unanswered probe rather than die with it (N-3).
      log.debug("permission epoch probe failed exception={}", e.getClass().getSimpleName());
      return false;
    }
  }

  @Override
  public Map<UUID, Long> bump(UUID tenantId, Collection<UUID> userIds) {
    if (!templates.bumpReady()) {
      throw new RedisConnectionFailureException("permission epoch store is not connected yet");
    }
    List<UUID> users = List.copyOf(userIds);
    List<String> epochKeys = new ArrayList<>(users.size());
    List<Object> args = new ArrayList<>(1 + users.size() * 2);
    args.add(keyTtlSeconds);
    for (UUID userId : users) {
      epochKeys.add(keys.epoch(tenantId, userId));
      args.add(keys.rolesetStem(tenantId, userId));
      args.add(keys.permsetStem(tenantId, userId));
    }
    List<?> written = templates.bump().execute(BUMP_SCRIPT, epochKeys, args.toArray());
    if (written == null || written.size() != users.size()) {
      throw new InvalidDataAccessResourceUsageException(
          "permission epoch bump script returned an unexpected result");
    }
    // The script has applied the whole batch by now, so a value that does not parse must not fail
    // it: the caller would replay the batch and bump every user again. The user is left out of the
    // map instead, which the caller records as a lower bound (L-1).
    Map<UUID, Long> epochs = HashMap.newHashMap(users.size());
    for (int i = 0; i < users.size(); i++) {
      String value = String.valueOf(written.get(i));
      if (isValidEpoch(value)) {
        long epoch = Long.parseLong(value);
        if (epoch <= MAX_EPOCH) {
          epochs.put(users.get(i), epoch);
        }
      }
    }
    return epochs;
  }
}
