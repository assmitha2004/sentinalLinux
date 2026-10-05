import { Router } from 'express';
import { z } from 'zod';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId, validate } from '../../middleware/validate.js';
import { Finding } from '../../models/index.js';
import { audit } from '../../services/audit.js';
import { recommendationFor } from '../../services/recommendations.js';
import { refreshScores } from '../../services/scoring.js';
import { asyncHandler, notFound, ok, paginate } from '../../utils/http.js';
import { findingQuery } from './query.js';

const r = Router();
r.use('/findings', requireUser);

r.get('/findings', asyncHandler(async (req, res) => {
  const { limit, skip, page } = paginate(req.query);
  const q = findingQuery(req.query);
  const [items, total] = await Promise.all([
    Finding.find(q).sort({ lastSeen: -1 }).skip(skip).limit(limit).populate('hostId', 'hostname').lean(), Finding.countDocuments(q)]);
  ok(res, items, 200, { page, limit, total });
}));

r.get('/findings/:id', objectId, asyncHandler(async (req, res) => {
  const f = await Finding.findById(req.params.id).populate('hostId', 'hostname').lean();
  if (!f) throw notFound('Finding');
  ok(res, { ...f, remediation: recommendationFor(f) });
}));

// Spec §78: acknowledging/closing findings is an ADMIN action.
r.patch('/findings/:id', objectId, requireRole('ADMIN'),
  validate(z.object({ status: z.enum(['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE']) })), asyncHandler(async (req, res) => {
    const f = await Finding.findByIdAndUpdate(req.params.id, { status: req.body.status, statusChangedBy: req.user._id,
      resolvedAt: req.body.status === 'RESOLVED' ? new Date() : undefined }, { new: true });
    if (!f) throw notFound('Finding');
    await refreshScores(f.hostId);
    await audit(req, 'finding.status', 'finding', f._id, { status: f.status, title: f.title });
    ok(res, f);
  }));

export default r;
