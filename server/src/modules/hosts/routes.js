import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { config } from '../../config/index.js';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId, validate } from '../../middleware/validate.js';
import { AIInsight, Alert, EnrollmentToken, Finding, Host, SecurityScan, SystemMetric } from '../../models/index.js';
import { audit } from '../../services/audit.js';
import { statusFor } from '../../services/hostStatus.js';
import { randomToken, safeEqualHex, sha256 } from '../../utils/crypto.js';
import { AppError, asyncHandler, notFound, ok, paginate } from '../../utils/http.js';
import { sanitizeKeys } from '../../utils/sanitize.js';

const r = Router();
const enrollLimiter = rateLimit({ windowMs: 15 * 60000, limit: 30, standardHeaders: true, legacyHeaders: false });

const registerSchema = z.object({
  enrollmentToken: z.string().min(8).max(200),
  hostname: z.string().min(1).max(255),
  machineId: z.string().max(64).nullable().optional(),
  os: z.record(z.any()).default({}),
  kernel: z.string().max(200).optional(),
  architecture: z.string().max(50).optional(),
  capabilities: z.record(z.any()).default({}),
});

async function consumeToken(token) {
  if (config.AGENT_ENROLLMENT_SECRET && safeEqualHex(sha256(token), sha256(config.AGENT_ENROLLMENT_SECRET))) return 'static';
  // Compare-and-swap on `uses` so concurrent enrollments cannot exceed maxUses.
  const t2 = await EnrollmentToken.findOne({ tokenHash: sha256(token), revoked: false, expiresAt: { $gt: new Date() } });
  if (!t2 || t2.uses >= t2.maxUses) return null;
  const upd = await EnrollmentToken.updateOne({ _id: t2._id, uses: t2.uses }, { $inc: { uses: 1 } });
  return upd.modifiedCount ? `token:${t2._id}` : null;
}

// Agent enrollment: exchanges an enrollment token for a per-host credential (returned once).
r.post('/hosts/register', enrollLimiter, validate(registerSchema), asyncHandler(async (req, res) => {
  const via = await consumeToken(req.body.enrollmentToken);
  if (!via) throw new AppError(401, 'INVALID_ENROLLMENT_TOKEN', 'Enrollment token is invalid, expired or used up');
  const agentSecret = randomToken(32);
  const fields = { hostname: req.body.hostname, os: sanitizeKeys(req.body.os), kernel: req.body.kernel, architecture: req.body.architecture,
    capabilities: sanitizeKeys(req.body.capabilities), agentSecretHash: sha256(agentSecret), lastSeen: new Date(), status: 'ONLINE' };
  // Re-enrolling the same machine rotates its credential instead of duplicating the host.
  let host = req.body.machineId ? await Host.findOne({ machineId: req.body.machineId }) : null;
  if (host) {
    Object.assign(host, fields);
    host.agentId = randomUUID();
    await host.save();
  } else {
    host = await Host.create({ ...fields, machineId: req.body.machineId, agentId: randomUUID() });
  }
  await audit(req, 'agent.register', 'host', host._id, { hostname: host.hostname, via, actor: `agent:${host.agentId}` });
  ok(res, { hostId: host._id, agentId: host.agentId, agentSecret }, 201);
}));

const hostView = (h) => ({ id: h._id, hostname: h.hostname, os: h.os, kernel: h.kernel, architecture: h.architecture,
  status: statusFor(h.lastSeen), lastSeen: h.lastSeen, agentVersion: h.agentVersion, capabilities: h.capabilities,
  scores: h.scores, latestMetric: h.latestMetric, currentScan: h.currentScan, outbox: h.outbox, createdAt: h.createdAt });

r.get('/hosts', requireUser, asyncHandler(async (req, res) => {
  const { limit, skip, page } = paginate(req.query, { maxLimit: 500, defLimit: 100 });
  const [hosts, total] = await Promise.all([
    Host.find().sort({ hostname: 1 }).skip(skip).limit(limit).select('-snapshot').lean(), Host.countDocuments()]);
  const alertCounts = await Promise.all(hosts.map((h) => Alert.countDocuments({ hostId: h._id, acknowledged: false })));
  ok(res, hosts.map((h, i) => ({ ...hostView(h), activeAlerts: alertCounts[i] })), 200, { page, limit, total });
}));

r.get('/hosts/:id', requireUser, objectId, asyncHandler(async (req, res) => {
  const h = await Host.findById(req.params.id).select('-snapshot').lean();
  if (!h) throw notFound('Host');
  ok(res, hostView(h));
}));

r.get('/hosts/:id/snapshot', requireUser, objectId, asyncHandler(async (req, res) => {
  const h = await Host.findById(req.params.id).select('snapshot snapshotAt').lean();
  if (!h) throw notFound('Host');
  ok(res, { snapshotAt: h.snapshotAt, ...(h.snapshot || {}) });
}));

r.delete('/hosts/:id', requireUser, requireRole('ADMIN'), objectId, asyncHandler(async (req, res) => {
  const h = await Host.findByIdAndDelete(req.params.id);
  if (!h) throw notFound('Host');
  await Promise.all([SystemMetric.deleteMany({ hostId: h._id }), Finding.deleteMany({ hostId: h._id }),
    SecurityScan.deleteMany({ hostId: h._id }), Alert.deleteMany({ hostId: h._id }), AIInsight.deleteMany({ hostId: h._id })]);
  await audit(req, 'host.delete', 'host', h._id, { hostname: h.hostname });
  ok(res, { deleted: true });
}));

export default r;
