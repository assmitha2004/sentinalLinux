import bcrypt from 'bcryptjs';
import { Router } from 'express';
import { z } from 'zod';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId, validate } from '../../middleware/validate.js';
import { ROLES } from '../../models/constants.js';
import { AuditLog, User } from '../../models/index.js';
import { audit } from '../../services/audit.js';
import { AppError, asyncHandler, notFound, ok, paginate } from '../../utils/http.js';

const r = Router();
r.use(requireUser, requireRole('ADMIN'));

r.get('/users', asyncHandler(async (_req, res) => {
  const users = await User.find().sort({ createdAt: 1 }).limit(500);
  ok(res, users.map((u) => u.toPublic()));
}));

r.post('/users', validate(z.object({ name: z.string().min(1).max(100), email: z.string().email(),
  password: z.string().min(10).max(128), role: z.enum(ROLES) })), asyncHandler(async (req, res) => {
  const u = await User.create({ ...req.body, passwordHash: await bcrypt.hash(req.body.password, 12) });
  await audit(req, 'user.create', 'user', u._id, { role: u.role });
  ok(res, u.toPublic(), 201);
}));

r.patch('/users/:id', objectId, validate(z.object({ role: z.enum(ROLES) })), asyncHandler(async (req, res) => {
  if (String(req.user._id) === req.params.id && req.body.role !== 'ADMIN') throw new AppError(400, 'SELF_DEMOTION', 'You cannot remove your own admin role');
  const u = await User.findByIdAndUpdate(req.params.id, { role: req.body.role, $inc: { tokenVersion: 1 } }, { new: true });
  if (!u) throw notFound('User');
  await audit(req, 'user.role_change', 'user', u._id, { role: u.role });
  ok(res, u.toPublic());
}));

r.delete('/users/:id', objectId, asyncHandler(async (req, res) => {
  if (String(req.user._id) === req.params.id) throw new AppError(400, 'SELF_DELETE', 'You cannot delete yourself');
  const u = await User.findByIdAndDelete(req.params.id);
  if (!u) throw notFound('User');
  await audit(req, 'user.delete', 'user', u._id, { actor: req.user.email });
  ok(res, { deleted: true });
}));

r.get('/audit-logs', asyncHandler(async (req, res) => {
  const { limit, skip, page } = paginate(req.query);
  const q = req.query.action ? { action: String(req.query.action) } : {};
  const [items, total] = await Promise.all([AuditLog.find(q).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(), AuditLog.countDocuments(q)]);
  ok(res, items, 200, { page, limit, total });
}));

export default r;
