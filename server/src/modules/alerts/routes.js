import { Router } from 'express';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId } from '../../middleware/validate.js';
import { SEVERITIES } from '../../models/constants.js';
import { Alert } from '../../models/index.js';
import { audit } from '../../services/audit.js';
import { asyncHandler, notFound, ok, paginate } from '../../utils/http.js';

const r = Router();
r.use('/alerts', requireUser);

r.get('/alerts', asyncHandler(async (req, res) => {
  const { limit, skip, page } = paginate(req.query);
  const q = {};
  if (req.query.acknowledged === 'true' || req.query.acknowledged === 'false') q.acknowledged = req.query.acknowledged === 'true';
  if (req.query.hostId && /^[a-f0-9]{24}$/i.test(req.query.hostId)) q.hostId = req.query.hostId;
  if (SEVERITIES.includes(req.query.severity)) q.severity = req.query.severity;
  const [items, total] = await Promise.all([
    Alert.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).populate('hostId', 'hostname').lean(), Alert.countDocuments(q)]);
  ok(res, items, 200, { page, limit, total });
}));

r.patch('/alerts/:id/acknowledge', objectId, requireRole('ANALYST'), asyncHandler(async (req, res) => {
  const a = await Alert.findByIdAndUpdate(req.params.id, { acknowledged: true, acknowledgedBy: req.user._id, acknowledgedAt: new Date() }, { new: true });
  if (!a) throw notFound('Alert');
  await audit(req, 'alert.acknowledge', 'alert', a._id, { title: a.title });
  ok(res, a);
}));

export default r;
