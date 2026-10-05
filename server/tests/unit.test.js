import './setup.js';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyze, deterministicInsight, extractJson } from '../src/services/aiService.js';
import { statusFor } from '../src/services/hostStatus.js';
import { detect, robustZ } from '../src/services/mlService.js';
import { computeHealth, computePosture, computeRisk, riskLevel } from '../src/services/riskEngine.js';
import { findingQuery } from '../src/modules/findings/query.js';
import { config } from '../src/config/index.js';

const F = (severity, category = 'ssh', confidence = 0.9, extra = {}) => ({ severity, category, confidence, title: `${severity} ${category}`, type: 't', ...extra });

test('risk: no findings is excellent, weighting is not a simple count', () => {
  assert.equal(computeRisk([]).score, 0);
  assert.equal(computeRisk([]).level, 'EXCELLENT');
  const manyLow = computeRisk(Array.from({ length: 10 }, () => F('LOW')));
  const oneCrit = computeRisk([F('CRITICAL', 'rootkit')]);
  assert.ok(oneCrit.score > manyLow.score, 'one strong critical outweighs ten lows');
  assert.ok(oneCrit.score >= 81);
});

test('risk: health findings do not affect security risk; weak HIGH has no floor', () => {
  assert.equal(computeRisk([F('CRITICAL', 'health')]).score, 0);
  assert.ok(computeRisk([F('HIGH', 'ssh', 0.9)]).score >= 41);
  assert.ok(computeRisk([F('HIGH', 'ssh', 0.3)]).score < 41);
  assert.equal(riskLevel(65), 'HIGH_RISK');
});

test('health score penalizes pressure and stays separate', () => {
  assert.equal(computeHealth(null).score, null);
  const ok = computeHealth({ cpu: { usage: 10, logical: 4 }, memory: { percent: 30 }, disk: [{ percent: 40 }], load: { load5: 1 } });
  assert.equal(ok.score, 100);
  const bad = computeHealth({ cpu: { usage: 100, logical: 1 }, memory: { percent: 98 }, disk: [{ percent: 97 }], load: { load5: 5 } });
  assert.ok(bad.score < 40);
  assert.equal(computePosture(20, 80), 80);
});

test('ml: learning below minimum, flags real spikes only', () => {
  assert.equal(detect([{ cpu: { usage: 1 } }], { minSamples: 10 }).status, 'LEARNING');
  const base = Array.from({ length: 200 }, (_, i) => ({ cpu: { usage: 10 + (i % 5) }, memory: { percent: 40 }, processCount: 200, network: { rxRate: 1000, txRate: 1000 } }));
  assert.equal(detect(base, { minSamples: 50, threshold: 4 }).anomalies.length, 0);
  const spike = [...base, ...Array.from({ length: 12 }, () => ({ cpu: { usage: 99 }, memory: { percent: 40 }, processCount: 200, network: { rxRate: 1000, txRate: 1000 } }))];
  const r = detect(spike, { minSamples: 50, threshold: 4 });
  assert.deepEqual(r.anomalies.map((a) => a.feature), ['cpu']);
  assert.equal(robustZ([1, 2], 5), null);
});

test('ai: deterministic insight is honest when nothing found', () => {
  const d = deterministicInsight({ risk: { score: 0, level: 'EXCELLENT', factors: [] }, health: { score: 90 } }, [], { status: 'LEARNING', samples: 3, required: 50 });
  assert.match(d.summary, /not that the system is guaranteed secure/);
  assert.ok(d.uncertainties.some((u) => /learning/i.test(u)));
});

const scores = { risk: { score: 90, level: 'CRITICAL', factors: [] }, health: { score: 80 } };
const host = { hostname: 'h', os: {}, kernel: 'k' };

test('ai: invalid model output falls back to deterministic engine', async () => {
  const out = await analyze(host, scores, [F('CRITICAL', 'rootkit')], null, { caller: async () => 'I think it is fine' });
  // AI not configured in tests -> deterministic regardless; ensure fallback shape is complete.
  assert.equal(out.engine, 'deterministic');
  assert.ok(out.topPriorities.length === 1 && out.topPriorities[0].recommendation);
});

test('ai: with a provider, valid JSON is used but cannot downgrade CRITICAL evidence; garbage falls back', async () => {
  Object.assign(config, { aiEnabled: true, AI_MODEL: 'test-model' });
  try {
    const good = JSON.stringify({ summary: 's', riskLevel: 'LOW', topPriorities: [], observations: [], uncertainties: [] });
    const llm = await analyze(host, scores, [F('CRITICAL', 'rootkit')], null, { caller: async () => `ok ${good}` });
    assert.equal(llm.engine, 'llm');
    assert.equal(llm.riskLevel, 'CRITICAL', 'evidence wins over the model');
    const bad = await analyze(host, scores, [F('CRITICAL', 'rootkit')], null, { caller: async () => '{"summary": 5}' });
    assert.equal(bad.engine, 'deterministic');
    assert.match(bad.fallbackReason, /AI unavailable/);
    const down = await analyze(host, scores, [], null, { caller: async () => { throw new Error('ECONNREFUSED'); } });
    assert.equal(down.engine, 'deterministic');
  } finally {
    Object.assign(config, { aiEnabled: false, AI_MODEL: '' });
  }
});

test('ai: JSON extraction tolerates prose around the object', () => {
  assert.deepEqual(extractJson('Here:\n{"a":1}\nthanks'), { a: 1 });
  assert.throws(() => extractJson('none'));
});

test('host status thresholds', () => {
  const now = Date.now();
  assert.equal(statusFor(new Date(now - 10000), now), 'ONLINE');
  assert.equal(statusFor(new Date(now - 90000), now), 'DEGRADED');
  assert.equal(statusFor(new Date(now - 200000), now), 'OFFLINE');
  assert.equal(statusFor(null, now), 'OFFLINE');
});

test('finding query whitelists values (no operator injection)', () => {
  const q = findingQuery({ severity: 'HIGH,{"$ne":1},bogus', category: '{"$gt":""}', q: '.*(a+)+$' });
  assert.deepEqual(q.severity, { $in: ['HIGH'] });
  assert.equal(q.category, undefined);
  assert.equal(q.title.$regex, '\\.\\*\\(a\\+\\)\\+\\$');
});

test('agent keys with dots/dollars are neutralised before storage', async () => {
  const { sanitizeKeys } = await import('../src/utils/sanitize.js');
  assert.deepEqual(sanitizeKeys({ 'a.b': 1, $where: { 'x.y': [{ $gt: 2 }] } }), { a_b: 1, _where: { x_y: [{ _gt: 2 }] } });
});

test('risk: critical band requires a critical finding', () => {
  const many = computeRisk(Array.from({ length: 30 }, () => F('HIGH', 'network', 0.9)));
  assert.equal(many.score, 80);
  assert.equal(many.level, 'HIGH_RISK');
});
