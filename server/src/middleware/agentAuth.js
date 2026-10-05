// Agents authenticate with the per-host secret issued at enrollment (stored only as SHA-256).
import { Host } from '../models/index.js';
import { safeEqualHex, sha256 } from '../utils/crypto.js';
import { AppError, asyncHandler } from '../utils/http.js';

export const requireAgent = asyncHandler(async (req, _res, next) => {
  const agentId = req.headers['x-agent-id'];
  const h = req.headers.authorization || '';
  const secret = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!agentId || !secret || typeof agentId !== 'string') throw new AppError(401, 'AGENT_UNAUTHENTICATED', 'Agent credentials required');
  const host = await Host.findOne({ agentId }).select('+agentSecretHash');
  if (!host || !safeEqualHex(host.agentSecretHash, sha256(secret))) {
    throw new AppError(401, 'AGENT_UNAUTHENTICATED', 'Invalid agent credentials');
  }
  req.agentHost = host;
  next();
});

// For agent routes carrying :id, the agent may only write its own host.
export const agentOwnsHost = (req, _res, next) => {
  if (String(req.agentHost._id) !== req.params.id) return next(new AppError(403, 'FORBIDDEN', 'Agent may only report for its own host'));
  return next();
};
