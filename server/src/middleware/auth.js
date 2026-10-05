import jwt from 'jsonwebtoken';
import { config } from '../config/index.js';
import { User } from '../models/index.js';
import { AppError, asyncHandler } from '../utils/http.js';

export const signToken = (user) => jwt.sign({ sub: String(user._id), role: user.role, v: user.tokenVersion },
  config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN, algorithm: 'HS256' });

export async function userFromToken(token) {
  let payload;
  try {
    payload = jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
  const user = await User.findById(payload.sub);
  if (!user || user.tokenVersion !== payload.v) return null;
  return user;
}

export const requireUser = asyncHandler(async (req, _res, next) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) throw new AppError(401, 'UNAUTHENTICATED', 'Authentication required');
  const user = await userFromToken(token);
  if (!user) throw new AppError(401, 'UNAUTHENTICATED', 'Invalid or expired session');
  req.user = user;
  next();
});

// Role hierarchy per spec §78: ADMIN > ANALYST > VIEWER.
const LEVEL = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };
export const requireRole = (min) => (req, _res, next) => {
  if (!req.user || LEVEL[req.user.role] < LEVEL[min]) {
    return next(new AppError(403, 'FORBIDDEN', `Requires ${min} role`));
  }
  return next();
};
