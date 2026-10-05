import { Router } from 'express';
import { z } from 'zod';
import { agentOwnsHost, requireAgent } from '../../middleware/agentAuth.js';
import { requireUser } from '../../middleware/auth.js';
import { objectId, validate } from '../../middleware/validate.js';
import { Host, SystemMetric } from '../../models/index.js';
import { raiseAlert } from '../../services/alertService.js';
import { computeHealth } from '../../services/riskEngine.js';
import { emit } from '../../sockets/index.js';
import { asyncHandler, ok } from '../../utils/http.js';

const r = Router();
const n = z.number().finite().nullable().optional();
const metricSchema = z.object({
  cpu: z.object({ usage: z.number().min(0).max(100), logical: z.number().int().min(1).optional() }),
  memory: z.object({ total: z.number(), used: z.number(), percent: z.number().min(0).max(100), swapPercent: n }),
  disk: z.array(z.object({ mount: z.string().max(512), total: z.number(), used: z.number(), percent: z.number() })).max(64),
  load: z.object({ load1: z.number(), load5: z.number(), load15: z.number() }),
  network: z.object({ rxBytes: z.number(), txBytes: z.number(), rxRate: n, txRate: n }),
  processCount: z.number().int().min(0),
  uptimeSeconds: z.number().int().min(0).optional(),
});

const SPIKE = { cpu: 95, memory: 95 };

r.post('/hosts/:id/metrics', requireAgent, objectId, agentOwnsHost, validate(metricSchema), asyncHandler(async (req, res) => {
  const host = req.agentHost;
  const m = await SystemMetric.create({ hostId: host._id, timestamp: new Date(), ...req.body });
  const health = computeHealth(req.body, { failedServices: host.snapshot?.services?.failed ?? 0 });
  await Host.updateOne({ _id: host._id }, { $set: { latestMetric: { ...req.body, timestamp: m.timestamp }, lastSeen: new Date(),
    'scores.health': health.score } });
  emit('metric:update', { metric: { ...req.body, timestamp: m.timestamp }, health: health.score }, host._id);
  if (req.body.cpu.usage >= SPIKE.cpu || req.body.memory.percent >= SPIKE.memory) {
    const what = req.body.cpu.usage >= SPIKE.cpu ? `CPU ${req.body.cpu.usage}%` : `memory ${req.body.memory.percent}%`;
    await raiseAlert({ hostId: host._id, severity: 'MEDIUM', kind: 'resource_spike', key: what.split(' ')[0],
      title: `Resource spike on ${host.hostname}: ${what}`, message: 'Resource usage crossed the spike threshold.' });
  }
  ok(res, { stored: true }, 201);
}));

const RANGES = { '15m': 15, '1h': 60, '6h': 360, '24h': 1440, '7d': 10080 };

r.get('/hosts/:id/metrics', requireUser, objectId, asyncHandler(async (req, res) => {
  const minutes = RANGES[req.query.range] || 60;
  const since = new Date(Date.now() - minutes * 60000);
  const limit = Math.min(parseInt(req.query.limit, 10) || 720, 2000);
  let rows = await SystemMetric.find({ hostId: req.params.id, timestamp: { $gte: since } }).sort({ timestamp: 1 }).limit(20000).lean();
  // Downsample to `limit` points so long ranges stay cheap to render.
  if (rows.length > limit) { const step = Math.ceil(rows.length / limit); rows = rows.filter((_, i) => i % step === 0); }
  ok(res, rows.map(({ _id, hostId, ...rest }) => rest), 200, { range: Object.keys(RANGES).find((k) => RANGES[k] === minutes), points: rows.length });
}));

export default r;
