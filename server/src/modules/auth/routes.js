import bcrypt from 'bcryptjs';
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { config } from '../../config/index.js';
import { requireUser, signToken } from '../../middleware/auth.js';
import { validate } from '../../middleware/validate.js';
import { User } from '../../models/index.js';
import { audit } from '../../services/audit.js';
import { AppError, asyncHandler, ok } from '../../utils/http.js';

const r = Router();
const authLimiter = rateLimit({ windowMs: 15 * 60000, limit: 20, standardHeaders: true, legacyHeaders: false,
  handler: (_q, res) => res.status(429).json({ success: false, error: { code: 'RATE_LIMITED', message: 'Too many attempts, try later' } }) });

const password = z.string().min(10, 'Password must be at least 10 characters').max(128)
  .regex(/[A-Za-z]/, 'Password needs a letter').regex(/[0-9]/, 'Password needs a digit');
const registerSchema = z.object({ name: z.string().trim().min(1).max(100), email: z.string().email().max(200), password });
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1).max(128) });

const MAX_FAILS = 5;
const LOCK_MIN = 15;

r.post('/register', authLimiter, validate(registerSchema), asyncHandler(async (req, res) => {
  const count = await User.estimatedDocumentCount();
  if (count > 0 && !config.ALLOW_REGISTRATION) throw new AppError(403, 'REGISTRATION_DISABLED', 'Self-registration is disabled; ask an administrator');
  // The very first account becomes ADMIN (bootstrap); later self-registrations are read-only VIEWERs.
  const role = count === 0 ? 'ADMIN' : 'VIEWER';
  const user = await User.create({ name: req.body.name, email: req.body.email, role, passwordHash: await bcrypt.hash(req.body.password, 12) });
  req.user = user;
  await audit(req, 'user.register', 'user', user._id, { role });
  ok(res, { user: user.toPublic(), token: signToken(user) }, 201);
}));

r.post('/login', authLimiter, validate(loginSchema), asyncHandler(async (req, res) => {
  const user = await User.findOne({ email: req.body.email.toLowerCase() }).select('+passwordHash +failedLogins +lockedUntil');
  const invalid = () => new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
  if (!user) { await bcrypt.hash('timing-equalizer', 12); throw invalid(); }
  if (user.lockedUntil && user.lockedUntil > new Date()) throw new AppError(423, 'ACCOUNT_LOCKED', 'Account temporarily locked after repeated failures');
  if (!(await bcrypt.compare(req.body.password, user.passwordHash))) {
    user.failedLogins = (user.failedLogins || 0) + 1;
    if (user.failedLogins >= MAX_FAILS) { user.lockedUntil = new Date(Date.now() + LOCK_MIN * 60000); user.failedLogins = 0; }
    await user.save();
    await audit(req, 'user.login_failed', 'user', user._id, { actor: user.email });
    throw invalid();
  }
  user.failedLogins = 0; user.lockedUntil = undefined;
  await user.save();
  req.user = user;
  await audit(req, 'user.login', 'user', user._id);
  ok(res, { user: user.toPublic(), token: signToken(user) });
}));

r.get('/me', requireUser, (req, res) => ok(res, { user: req.user.toPublic() }));

// Logout invalidates every outstanding JWT for this user.
r.post('/logout', requireUser, asyncHandler(async (req, res) => {
  await User.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 } });
  await audit(req, 'user.logout', 'user', req.user._id);
  ok(res, { loggedOut: true });
}));

export default r;
