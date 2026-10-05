import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId, validate } from '../../middleware/validate.js';
import { SCAN_TYPES } from '../../models/constants.js';
import { Finding, Host, SecurityScan } from '../../models/index.js';
import { audit } from '../../services/audit.js';
import { hostScores } from '../../services/scoring.js';
import { emit } from '../../sockets/index.js';
import { AppError, asyncHandler, notFound, ok, paginate } from '../../utils/http.js';
import { findingQuery } from '../findings/query.js';

const r = Router();
r.use('/hosts/:id', requireUser);

r.post('/hosts/:id/scan', objectId, requireRole('ANALYST'), validate(z.object({ type: z.enum(SCAN_TYPES).default('QUICK') })),
  asyncHandler(async (req, res) => {
    const host = await Host.findById(req.params.id);
    if (!host) throw notFound('Host');
    const pending = await SecurityScan.countDocuments({ hostId: host._id, status: { $in: ['QUEUED', 'DISPATCHED'] } });
    if (pending >= 3) throw new AppError(429, 'SCAN_QUEUE_FULL', 'Too many pending scans for this host');
    const scan = await SecurityScan.create({ hostId: host._id, scanId: randomUUID(), scanType: req.body.type, trigger: 'MANUAL',
      requestedBy: req.user._id, status: 'QUEUED' });
    await audit(req, 'scan.request', 'host', host._id, { scanType: scan.scanType, scanId: scan.scanId });
    emit('scan:queued', { scanId: scan.scanId, scanType: scan.scanType }, host._id);
    ok(res, { scanId: scan.scanId, status: scan.status, note: 'The agent picks up queued scans on its next heartbeat.' }, 202);
  }));

r.get('/hosts/:id/scans', objectId, asyncHandler(async (req, res) => {
  const { limit, skip, page } = paginate(req.query, { defLimit: 25 });
  const q = { hostId: req.params.id };
  const [items, total] = await Promise.all([
    SecurityScan.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).select('-checks -findingIds').lean(),
    SecurityScan.countDocuments(q)]);
  ok(res, items, 200, { page, limit, total });
}));

r.get('/hosts/:id/scans/:scanId', objectId, asyncHandler(async (req, res) => {
  const scan = await SecurityScan.findOne({ hostId: req.params.id, scanId: req.params.scanId }).lean();
  if (!scan) throw notFound('Scan');
  const findings = await Finding.find({ hostId: req.params.id, fingerprint: { $in: scan.findingIds || [] } })
    .select('-evidence').sort({ severity: -1 }).limit(1000).lean();
  ok(res, { ...scan, findings });
}));

r.get('/hosts/:id/findings', objectId, asyncHandler(async (req, res) => {
  const { limit, skip, page } = paginate(req.query);
  const q = findingQuery({ ...req.query, hostId: req.params.id });
  const [items, total] = await Promise.all([Finding.find(q).sort({ lastSeen: -1 }).skip(skip).limit(limit).lean(), Finding.countDocuments(q)]);
  ok(res, items, 200, { page, limit, total });
}));

// Security posture: scores + per-area status cards (spec §38) + score history.
const AREAS = { ssh: ['ssh'], firewall: ['firewall'], files: ['permissions', 'filesystem'], network: ['network'],
  processes: ['process'], users: ['users', 'auth', 'authentication'], rootkit: ['rootkit'], kernel: ['kernel'],
  logging: ['logging'], benchmark: ['benchmark'], vulnerabilities: ['vulnerability'] };

r.get('/hosts/:id/security-score', objectId, asyncHandler(async (req, res) => {
  const host = await Host.findById(req.params.id);
  if (!host) throw notFound('Host');
  const s = await hostScores(host);
  const last = await SecurityScan.find({ hostId: host._id, status: { $in: ['COMPLETED', 'COMPLETED_WITH_ERRORS'] } })
    .sort({ completedAt: -1 }).limit(200).select('checks.check checks.status checks.data.verdict checks.data.compliancePercent checks.data.state checks.reason scanType completedAt scores').lean();
  const latestCheck = {};
  for (const scan of last) for (const c of scan.checks || []) if (!latestCheck[c.check]) latestCheck[c.check] = { ...c, at: scan.completedAt };
  const sevOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const areas = Object.entries(AREAS).map(([area, cats]) => {
    const fs = s.findings.filter((f) => cats.includes(f.category));
    const worst = fs.reduce((w, f) => (sevOrder.indexOf(f.severity) > sevOrder.indexOf(w) ? f.severity : w), 'INFO');
    const check = { ssh: 'ssh', firewall: 'firewall', rootkit: 'rootkit', benchmark: 'benchmark', logging: 'audit_logging',
      kernel: 'kernel_params', vulnerabilities: 'vulnerabilities', files: 'permissions', network: 'c2_heuristics',
      processes: 'processes', users: 'authentication' }[area];
    const lc = latestCheck[check];
    let status = fs.length === 0 ? 'GOOD' : ['HIGH', 'CRITICAL'].includes(worst) ? 'INSECURE' : ['MEDIUM'].includes(worst) ? 'WARNING' : 'GOOD';
    if (!lc && fs.length === 0) status = 'UNKNOWN';
    if (lc?.status === 'NOT_SUPPORTED' && fs.length === 0) status = 'NOT_SUPPORTED';
    return { area, status, worstSeverity: fs.length ? worst : null, openFindings: fs.length, lastChecked: lc?.at,
      detail: area === 'benchmark' ? (lc?.data?.compliancePercent != null ? `${lc.data.compliancePercent}% compliant` : lc?.reason)
        : area === 'rootkit' ? lc?.data?.verdict : area === 'firewall' ? lc?.data?.state : undefined };
  });
  const bySeverity = Object.fromEntries(sevOrder.map((k) => [k, s.findings.filter((f) => f.severity === k).length]));
  const history = last.filter((x) => x.scores?.risk != null).slice(0, 100).reverse()
    .map((x) => ({ at: x.completedAt, risk: x.scores.risk, health: x.scores.health, scanType: x.scanType }));
  ok(res, { risk: s.risk, health: s.health, posture: s.posture, bySeverity, areas, history });
}));

export default r;
