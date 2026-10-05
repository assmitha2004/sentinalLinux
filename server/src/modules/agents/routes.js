// Agent-facing endpoints + enrollment-token management (spec §33 agent, §34).
import { Router } from 'express';
import { z } from 'zod';
import { requireAgent } from '../../middleware/agentAuth.js';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId, validate } from '../../middleware/validate.js';
import { SCAN_TYPES } from '../../models/constants.js';
import { EnrollmentToken, Host, SecurityScan } from '../../models/index.js';
import { raiseAlert } from '../../services/alertService.js';
import { audit } from '../../services/audit.js';
import { ingestFindings } from '../../services/findingService.js';
import { statusFor } from '../../services/hostStatus.js';
import { refreshScores } from '../../services/scoring.js';
import { emit } from '../../sockets/index.js';
import { randomToken, sha256 } from '../../utils/crypto.js';
import { asyncHandler, notFound, ok } from '../../utils/http.js';
import { sanitizeKeys } from '../../utils/sanitize.js';

const r = Router();

// ---------- enrollment tokens (dashboard, ADMIN) ----------
r.post('/agent/enrollment-tokens', requireUser, requireRole('ADMIN'),
  validate(z.object({ label: z.string().max(100).optional(), ttlHours: z.number().int().min(1).max(720).default(24), maxUses: z.number().int().min(1).max(1000).default(1) })),
  asyncHandler(async (req, res) => {
    const token = `sat_${randomToken(24)}`;
    const doc = await EnrollmentToken.create({ tokenHash: sha256(token), label: req.body.label, createdBy: req.user._id,
      expiresAt: new Date(Date.now() + req.body.ttlHours * 3600000), maxUses: req.body.maxUses });
    await audit(req, 'enrollment_token.create', 'enrollment_token', doc._id, { label: doc.label, maxUses: doc.maxUses });
    // Plaintext token is returned exactly once.
    ok(res, { id: doc._id, token, expiresAt: doc.expiresAt, maxUses: doc.maxUses, label: doc.label }, 201);
  }));

r.get('/agent/enrollment-tokens', requireUser, requireRole('ADMIN'), asyncHandler(async (_req, res) => {
  ok(res, await EnrollmentToken.find().sort({ createdAt: -1 }).limit(100).select('-tokenHash').lean());
}));

r.delete('/agent/enrollment-tokens/:id', requireUser, requireRole('ADMIN'), objectId, asyncHandler(async (req, res) => {
  const t = await EnrollmentToken.findByIdAndUpdate(req.params.id, { revoked: true }, { new: true });
  if (!t) throw notFound('Token');
  await audit(req, 'enrollment_token.revoke', 'enrollment_token', t._id);
  ok(res, { revoked: true });
}));

// ---------- agent runtime ----------
const heartbeatSchema = z.object({
  agentVersion: z.string().max(32).optional(),
  host: z.object({ hostname: z.string().max(255), os: z.record(z.any()).optional(), kernel: z.string().max(200).optional(),
    architecture: z.string().max(50).optional() }).passthrough().optional(),
  capabilities: z.record(z.any()).optional(),
  outbox: z.number().int().min(0).optional(),
  currentScan: z.string().max(32).nullable().optional(),
});

r.post('/agent/heartbeat', requireAgent, validate(heartbeatSchema), asyncHandler(async (req, res) => {
  const host = req.agentHost;
  const prev = statusFor(host.lastSeen);
  host.lastSeen = new Date();
  host.status = 'ONLINE';
  if (req.body.agentVersion) host.agentVersion = req.body.agentVersion;
  if (req.body.capabilities) host.capabilities = sanitizeKeys(req.body.capabilities);
  if (req.body.host?.kernel) host.kernel = req.body.host.kernel;
  if (req.body.host?.os) host.os = sanitizeKeys(req.body.host.os);
  host.outbox = req.body.outbox ?? 0;
  host.currentScan = req.body.currentScan || undefined;
  await host.save();
  if (prev !== 'ONLINE') emit('host:online', { hostname: host.hostname }, host._id);
  // Deliver queued manual scans (dashboard -> agent command channel).
  const queued = await SecurityScan.find({ hostId: host._id, status: 'QUEUED' }).sort({ createdAt: 1 }).limit(5);
  const commands = [];
  for (const s of queued) {
    s.status = 'DISPATCHED';
    await s.save();
    commands.push({ type: 'scan', scanId: s.scanId, scanType: s.scanType });
  }
  ok(res, { serverTime: new Date().toISOString(), commands });
}));

const eventSchema = z.object({ type: z.enum(['snapshot', 'scan_progress', 'scan_failed']), data: z.record(z.any()) });

r.post('/agent/events', requireAgent, validate(eventSchema), asyncHandler(async (req, res) => {
  const host = req.agentHost;
  const { type } = req.body;
  const data = sanitizeKeys(req.body.data);
  if (type === 'snapshot') {
    host.snapshot = data;
    host.snapshotAt = new Date();
    host.lastSeen = new Date();
    await host.save();
    emit('host:snapshot', { snapshotAt: host.snapshotAt }, host._id);
  } else if (type === 'scan_progress') {
    const scanId = String(data.scanId || '');
    const total = Number(data.checksTotal) || 0;
    const done = Number(data.checksCompleted) || 0;
    const update = { status: 'RUNNING', checksTotal: total, checksCompleted: done, currentCheck: String(data.check || ''),
      progress: total ? Math.round((100 * done) / total) : 0 };
    let scan = await SecurityScan.findOneAndUpdate({ scanId, hostId: host._id }, { $set: update }, { new: true });
    if (!scan && SCAN_TYPES.includes(data.type)) {
      scan = await SecurityScan.create({ hostId: host._id, scanId, scanType: data.type, startedAt: new Date(), ...update });
      emit('scan:started', { scanId, scanType: data.type }, host._id);
    } else if (scan && done === 1) {
      scan.startedAt = scan.startedAt || new Date();
      await scan.save();
      emit('scan:started', { scanId, scanType: scan.scanType }, host._id);
    }
    if (scan) emit('scan:progress', { scanId, progress: scan.progress, currentCheck: scan.currentCheck }, host._id);
  } else if (type === 'scan_failed') {
    const scan = await SecurityScan.findOneAndUpdate({ scanId: String(data.scanId), hostId: host._id },
      { $set: { status: 'FAILED', error: String(data.error || '').slice(0, 500), completedAt: new Date() } }, { new: true });
    await raiseAlert({ hostId: host._id, severity: 'MEDIUM', kind: 'scan_failure', key: scan?.scanType || 'scan',
      title: `Scan failed on ${host.hostname}`, message: String(data.error || '').slice(0, 300) });
    emit('scan:completed', { scanId: data.scanId, status: 'FAILED' }, host._id);
  }
  ok(res, { accepted: true });
}));

const findingSchema = z.object({
  id: z.string().min(1).max(64), type: z.string().max(100), category: z.string().max(50),
  severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), title: z.string().max(500),
  description: z.string().max(5000).optional(), whyItMatters: z.string().max(5000).optional(),
  evidence: z.any(), resource: z.string().max(1000).optional(), confidence: z.number().min(0).max(1),
  recommendation: z.string().max(5000).optional(),
  verification: z.object({ mode: z.string().max(20), command: z.string().max(2000) }).optional(),
  requiresAdminApproval: z.boolean().optional(), source: z.string().max(50).optional(), timestamp: z.string().optional(),
});
const checkSchema = z.object({
  check: z.string().max(64), status: z.enum(['PASS', 'WARN', 'FAIL', 'ERROR', 'NOT_SUPPORTED', 'NOT_APPLICABLE']),
  severity: z.string().optional(), category: z.string().max(50).optional(), data: z.any(), reason: z.string().max(500).optional(),
  findings: z.array(findingSchema).max(2000), errors: z.array(z.string().max(2000)).max(50),
  capability: z.any(), durationMs: z.number().optional(), timestamp: z.string().optional(),
});
const scanResultSchema = z.object({
  scanId: z.string().min(1).max(64), type: z.enum(SCAN_TYPES), status: z.string().max(32),
  startedAt: z.string(), completedAt: z.string(), checksTotal: z.number().int(), checksCompleted: z.number().int(),
  checks: z.array(checkSchema).max(64), summary: z.any(), capabilities: z.any().optional(), findings: z.any().optional(),
});

r.post('/agent/scan-results', requireAgent, validate(scanResultSchema), asyncHandler(async (req, res) => {
  const host = req.agentHost;
  const b = sanitizeKeys(req.body);
  const ing = await ingestFindings(host._id, b.checks);
  const scores = await refreshScores(host._id);
  // Store per-check status/data, not duplicated findings (they live in the Finding collection).
  const checks = b.checks.map(({ findings, ...rest }) => ({ ...rest, findingCount: findings.length }));
  const status = b.status === 'COMPLETED_WITH_ERRORS' ? 'COMPLETED_WITH_ERRORS' : 'COMPLETED';
  const update = { hostId: host._id, scanId: b.scanId, scanType: b.type, status, progress: 100, checksTotal: b.checksTotal,
    checksCompleted: b.checksCompleted, startedAt: new Date(b.startedAt), completedAt: new Date(b.completedAt),
    summary: { ...b.summary, newFindings: ing.created, autoResolved: ing.resolved }, checks, findingIds: ing.fingerprints,
    scores: { risk: scores.risk.score, riskLevel: scores.risk.level, health: scores.health.score } };
  const scan = await SecurityScan.findOneAndUpdate({ scanId: b.scanId, hostId: host._id }, { $set: update }, { upsert: true, new: true });
  if (b.capabilities) { host.capabilities = b.capabilities; await host.save(); }
  emit('scan:completed', { scanId: b.scanId, scanType: b.type, status, summary: scan.summary, scores: scan.scores }, host._id);
  ok(res, { scanId: b.scanId, newFindings: ing.created, resolved: ing.resolved, riskScore: scores.risk.score }, 201);
}));

export default r;
