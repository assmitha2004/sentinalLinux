import { Router } from 'express';
import { config } from '../../config/index.js';
import { requireUser } from '../../middleware/auth.js';
import { Alert, Finding, Host } from '../../models/index.js';
import { statusFor } from '../../services/hostStatus.js';
import { asyncHandler, ok } from '../../utils/http.js';

const r = Router();

// Fleet summary (spec §36, §76).
r.get('/dashboard/summary', requireUser, asyncHandler(async (_req, res) => {
  const hosts = await Host.find().select('hostname status lastSeen scores latestMetric os').lean();
  const statuses = hosts.map((h) => statusFor(h.lastSeen));
  const scored = hosts.filter((h) => h.scores?.risk != null);
  const healthy = hosts.filter((h) => h.scores?.health != null);
  const avg = (arr, f) => (arr.length ? Math.round(arr.reduce((a, h) => a + f(h), 0) / arr.length) : null);
  const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const counts = await Promise.all(sev.map((s) => Finding.countDocuments({ severity: s, status: { $in: ['OPEN', 'ACKNOWLEDGED'] } })));
  const [activeAlerts, topFindings] = await Promise.all([
    Alert.countDocuments({ acknowledged: false }),
    Finding.find({ status: 'OPEN', severity: { $in: ['CRITICAL', 'HIGH', 'MEDIUM'] } }).sort({ lastSeen: -1 }).limit(200)
      .select('title severity confidence category firstSeen recommendation evidence hostId').populate('hostId', 'hostname').lean(),
  ]);
  const rank = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
  topFindings.sort((a, b) => rank[b.severity] - rank[a.severity] || (b.confidence || 0) - (a.confidence || 0));
  ok(res, {
    hosts: {
      total: hosts.length,
      online: statuses.filter((s) => s === 'ONLINE').length,
      degraded: statuses.filter((s) => s === 'DEGRADED').length,
      offline: statuses.filter((s) => s === 'OFFLINE').length,
      critical: scored.filter((h) => h.scores.risk > 80).length,
      highRisk: scored.filter((h) => h.scores.risk > 60 && h.scores.risk <= 80).length,
    },
    averageRisk: avg(scored, (h) => h.scores.risk),
    averageHealth: avg(healthy, (h) => h.scores.health),
    findingsBySeverity: Object.fromEntries(sev.map((s, i) => [s, counts[i]])),
    activeAlerts,
    topFindings: topFindings.slice(0, 10),
    aiConfigured: config.aiEnabled,
  });
}));

// Non-secret runtime settings for the Settings page.
r.get('/settings', requireUser, (_req, res) => ok(res, {
  heartbeatIntervalSec: config.HEARTBEAT_INTERVAL_SEC,
  degradedMultiplier: config.DEGRADED_MULTIPLIER,
  offlineMultiplier: config.OFFLINE_MULTIPLIER,
  alertCooldownMin: config.ALERT_COOLDOWN_MIN,
  retentionDays: { metrics: config.RETENTION_METRICS_DAYS, findings: config.RETENTION_FINDINGS_DAYS,
    alerts: config.RETENTION_ALERTS_DAYS, audit: config.RETENTION_AUDIT_DAYS, scans: config.RETENTION_SCANS_DAYS },
  ai: { configured: config.aiEnabled, provider: config.AI_PROVIDER || 'none', model: config.aiEnabled ? config.AI_MODEL : null },
  ml: { minSamples: config.ML_MIN_SAMPLES, zThreshold: config.ML_Z_THRESHOLD },
  risk: config.risk,
  registrationOpen: config.ALLOW_REGISTRATION,
  staticEnrollmentSecret: !!config.AGENT_ENROLLMENT_SECRET,
}));

export default r;
