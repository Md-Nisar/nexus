import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide } from './cache-benchmark-verdict.js';

test('keeps the cache when p95 improves by at least 5 ms beyond the noise', () => {
  const { decision } = decide({ p95OnMs: [10, 10.5, 10.2], p95OffMs: [17, 16.5, 17.4] });
  assert.equal(decision, 'keep');
});

test('keeps the cache when MySQL QPS drops by at least 30% although latency is equal', () => {
  const { decision } = decide({
    p95OnMs: [10, 10.1, 10],
    p95OffMs: [10.2, 10, 10.1],
    qpsOn: [100, 102, 101],
    qpsOff: [160, 158, 162],
  });
  assert.equal(decision, 'keep');
});

test('removes the cache when neither criterion is met', () => {
  const { decision } = decide({
    p95OnMs: [10, 10.1, 10],
    p95OffMs: [12, 12.1, 12.2],
    qpsOn: [100, 101, 100],
    qpsOff: [120, 121, 119],
  });
  assert.equal(decision, 'remove');
});

test('removes the cache at exactly 4.99 ms of gain', () => {
  const { decision } = decide({ p95OnMs: [10], p95OffMs: [14.99] });
  assert.equal(decision, 'remove');
});

test('keeps the cache at exactly 5 ms of gain with no spread', () => {
  const { decision } = decide({ p95OnMs: [10, 10], p95OffMs: [15, 15] });
  assert.equal(decision, 'keep');
});

test('removes the cache when the variance is larger than the effect (inconclusive)', () => {
  const { decision } = decide({ p95OnMs: [8, 16, 12], p95OffMs: [14, 22, 18] });
  assert.equal(decision, 'remove');
});

test('rejects an empty arm', () => {
  assert.throws(() => decide({ p95OnMs: [], p95OffMs: [10] }));
});
