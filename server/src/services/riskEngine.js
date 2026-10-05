// Deterministic risk & health scoring (spec §27, §58). Layer 1 - works with no LLM configured.
import { config } from '../config/index.js';

const { severityWeight, categoryMultiplier, saturation, bands } = config.risk;

export function riskLevel(score) {
  return bands.find(([max]) => score <= max)[1];
}

/** Weighted, saturating risk score: 0 (no exposure) .. 100 (critical). Not a finding count. */
export function computeRisk(findings) {
  const sec = findings.filter((f) => (categoryMultiplier[f.category] ?? 1) > 0);
  let total = 0;
  const contributions = {};
  for (const f of sec) {
    const w = (severityWeight[f.severity] || 0) * (f.confidence ?? 0.7) * (categoryMultiplier[f.category] ?? 1);
    total += w;
    contributions[f.category] = (contributions[f.category] || 0) + w;
  }
  let score = Math.round(100 * (1 - Math.exp(-total / saturation)));
  // Floors: strong evidence of a critical/high issue cannot be averaged away.
  const strong = (sev) => sec.some((f) => f.severity === sev && (f.confidence ?? 0) >= 0.7);
  if (strong('CRITICAL')) score = Math.max(score, 81);
  else if (strong('HIGH')) score = Math.max(score, 41);
  // The Critical band is reserved for critical evidence; many lesser issues top out at High risk.
  if (!sec.some((f) => f.severity === 'CRITICAL')) score = Math.min(score, 80);
  const factors = Object.entries(contributions).sort((a, b) => b[1] - a[1])
    .map(([category, weight]) => ({ category, weight: Math.round(weight * 10) / 10 }));
  return { score, level: riskLevel(score), factors };
}

/** Health 0..100 (higher is better) from the latest metric sample + failed services. */
export function computeHealth(metric, { failedServices = 0 } = {}) {
  if (!metric) return { score: null, factors: [], note: 'No metrics received yet' };
  const factors = [];
  const penalize = (name, pts, detail) => { if (pts > 0) factors.push({ name, penalty: Math.round(pts), detail }); };
  const cpu = metric.cpu?.usage ?? 0;
  penalize('cpu', Math.max(0, cpu - 70) * 0.8, `${cpu}% CPU`);
  const mem = metric.memory?.percent ?? 0;
  penalize('memory', Math.max(0, mem - 75) * 1.0, `${mem}% memory`);
  const worst = Math.max(0, ...(metric.disk || []).map((d) => d.percent || 0));
  penalize('disk', worst >= 95 ? 30 : worst >= 90 ? 20 : worst >= 80 ? 10 : 0, `fullest filesystem ${worst}%`);
  const perCpu = (metric.load?.load5 ?? 0) / (metric.cpu?.logical || 1);
  penalize('load', perCpu > 2 ? 15 : perCpu > 1.5 ? 8 : 0, `load5/cpu ${perCpu.toFixed(2)}`);
  penalize('swap', (metric.memory?.swapPercent ?? 0) > 80 ? 5 : 0, `swap ${metric.memory?.swapPercent}%`);
  penalize('services', Math.min(15, failedServices * 3), `${failedServices} failed services`);
  const score = Math.max(0, Math.min(100, 100 - factors.reduce((a, f) => a + f.penalty, 0)));
  return { score: Math.round(score), factors };
}

/** Overall posture: average of security (100-risk) and health. Kept separate in the UI (spec §58). */
export function computePosture(risk, health) {
  if (health == null) return 100 - risk;
  return Math.round(((100 - risk) + health) / 2);
}
