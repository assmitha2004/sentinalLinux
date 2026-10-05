import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../../config/index.js';
import { requireRole, requireUser } from '../../middleware/auth.js';
import { objectId } from '../../middleware/validate.js';
import { AIInsight, Host } from '../../models/index.js';
import { analyze } from '../../services/aiService.js';
import { audit } from '../../services/audit.js';
import { analyzeHost } from '../../services/mlService.js';
import { hostScores } from '../../services/scoring.js';
import { asyncHandler, notFound, ok } from '../../utils/http.js';

const r = Router();
const aiLimiter = rateLimit({ windowMs: 60000, limit: 6, standardHeaders: true, legacyHeaders: false });

r.post('/hosts/:id/ai/analyze', requireUser, objectId, requireRole('ANALYST'), aiLimiter, asyncHandler(async (req, res) => {
  const host = await Host.findById(req.params.id);
  if (!host) throw notFound('Host');
  const scores = await hostScores(host);
  const ml = await analyzeHost(host._id);
  const out = await analyze(host, scores, scores.findings, ml);
  const insight = await AIInsight.create({
    hostId: host._id, riskScore: scores.risk.score, riskLevel: scores.risk.level, healthScore: scores.health.score,
    summary: out.summary, priorities: out.topPriorities, recommendations: out.deterministic?.topPriorities || out.topPriorities,
    observations: out.observations, uncertainties: out.uncertainties, ml, engine: out.engine, model: out.model,
    fallbackReason: out.fallbackReason, requestedBy: req.user._id,
  });
  await audit(req, 'ai.analyze', 'host', host._id, { engine: out.engine });
  ok(res, insight, 201);
}));

r.get('/hosts/:id/ai/insights', requireUser, objectId, asyncHandler(async (req, res) => {
  const items = await AIInsight.find({ hostId: req.params.id }).sort({ createdAt: -1 }).limit(Math.min(parseInt(req.query.limit, 10) || 10, 50)).lean();
  ok(res, items, 200, { aiConfigured: config.aiEnabled, provider: config.AI_PROVIDER || 'none' });
}));

r.get('/hosts/:id/ai/anomalies', requireUser, objectId, asyncHandler(async (req, res) => {
  ok(res, await analyzeHost(req.params.id));
}));

export default r;
