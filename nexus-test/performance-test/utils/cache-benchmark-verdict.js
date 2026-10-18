/**
 * The B6 keep/remove rule (US-018 design 10.6, Decision 23), as a pure function so it is the same
 * rule in the k6 summary and in its unit test (utils/cache-benchmark-verdict.test.mjs). No k6
 * imports: node can load it.
 *
 * KEEP the permission cache only if it lowers refresh p95 by at least 5 ms OR lowers the
 * mint-attributable MySQL QPS by at least 30%. Otherwise REMOVE. An inconclusive result, where the
 * run-to-run variance within an arm is as large as the effect, defaults to REMOVE.
 *
 * Inputs are arrays with one value per repeated run of each arm (at least 3 runs per arm are
 * recommended): refresh p95 in ms, and optionally MySQL queries per second attributable to minting.
 */

export const P95_IMPROVEMENT_MS = 5;
export const QPS_DROP_FRACTION = 0.3;

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function spread(values) {
  return Math.max(...values) - Math.min(...values);
}

/**
 * @param {{p95OnMs: number[], p95OffMs: number[], qpsOn?: number[], qpsOff?: number[]}} input
 * @returns {{decision: 'keep'|'remove', reasons: string[]}}
 */
export function decide({ p95OnMs, p95OffMs, qpsOn = [], qpsOff = [] }) {
  if (!p95OnMs?.length || !p95OffMs?.length) {
    throw new Error('Both arms need at least one p95 value');
  }
  const reasons = [];

  // Latency: the cache helps by (off - on). The effect must reach 5 ms AND exceed the larger
  // within-arm spread, otherwise the difference could be noise.
  const p95Gain = median(p95OffMs) - median(p95OnMs);
  const p95Noise = Math.max(spread(p95OnMs), spread(p95OffMs));
  const latencyKeeps = p95Gain >= P95_IMPROVEMENT_MS && p95Gain > p95Noise;
  reasons.push(
    `refresh p95 gain from the cache ${p95Gain.toFixed(2)} ms (needs >= ${P95_IMPROVEMENT_MS} ms ` +
      `and > run-to-run spread ${p95Noise.toFixed(2)} ms): ${latencyKeeps ? 'met' : 'not met'}`,
  );

  // Database load: the cache helps by the fraction of QPS it removes. Optional, because it is read
  // from MySQL and not from k6.
  let qpsKeeps = false;
  if (qpsOn.length && qpsOff.length) {
    const drop = 1 - median(qpsOn) / median(qpsOff);
    const noise = Math.max(spread(qpsOn) / median(qpsOff), spread(qpsOff) / median(qpsOff));
    qpsKeeps = drop >= QPS_DROP_FRACTION && drop > noise;
    reasons.push(
      `mint-attributable MySQL QPS drop ${(drop * 100).toFixed(1)}% (needs >= ` +
        `${QPS_DROP_FRACTION * 100}% and > spread ${(noise * 100).toFixed(1)}%): ` +
        `${qpsKeeps ? 'met' : 'not met'}`,
    );
  } else {
    reasons.push('MySQL QPS not supplied: only the latency criterion was evaluated');
  }

  const keep = latencyKeeps || qpsKeeps;
  reasons.push(keep ? 'KEEP the cache' : 'REMOVE the cache (a criterion not met, or inconclusive)');
  return { decision: keep ? 'keep' : 'remove', reasons };
}
