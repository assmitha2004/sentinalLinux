// Recomputes and stores a host's scores after any change in findings/metrics.
import { Host } from '../models/index.js';
import { activeFindings } from './findingService.js';
import { computeHealth, computePosture, computeRisk } from './riskEngine.js';

export async function hostScores(host) {
  const findings = await activeFindings(host._id);
  const risk = computeRisk(findings);
  const failedServices = host.snapshot?.services?.failed ?? 0;
  const health = computeHealth(host.latestMetric, { failedServices });
  return { risk, health, posture: computePosture(risk.score, health.score), findings };
}

export async function refreshScores(hostId) {
  const host = await Host.findById(hostId);
  if (!host) return null;
  const s = await hostScores(host);
  host.scores = { risk: s.risk.score, riskLevel: s.risk.level, health: s.health.score, posture: s.posture, updatedAt: new Date() };
  await host.save();
  return s;
}
