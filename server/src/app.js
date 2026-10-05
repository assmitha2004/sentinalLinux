import cors from 'cors';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { config } from './config/index.js';
import { errorHandler, notFoundHandler } from './middleware/error.js';
import agentRoutes from './modules/agents/routes.js';
import aiRoutes from './modules/ai/routes.js';
import alertRoutes from './modules/alerts/routes.js';
import authRoutes from './modules/auth/routes.js';
import dashboardRoutes from './modules/dashboard/routes.js';
import findingRoutes from './modules/findings/routes.js';
import hostRoutes from './modules/hosts/routes.js';
import metricRoutes from './modules/metrics/routes.js';
import securityRoutes from './modules/security/routes.js';
import userRoutes from './modules/users/routes.js';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  if (config.TRUST_PROXY) app.set('trust proxy', 1);
  app.use(helmet());
  app.use(cors({ origin: config.corsOrigins, credentials: true }));

  // Agent uploads (scan results, snapshots) can be large; everything else is capped small.
  app.use('/api/v1/agent', express.json({ limit: '16mb' }));
  app.use(express.json({ limit: '200kb' }));

  app.get('/health', (_req, res) => res.json({ success: true, data: { status: 'ok', time: new Date().toISOString() } }));

  const api = express.Router();
  api.use(rateLimit({ windowMs: 60000, limit: 1200, standardHeaders: true, legacyHeaders: false }));
  api.use('/auth', authRoutes);
  for (const routes of [hostRoutes, metricRoutes, securityRoutes, findingRoutes, alertRoutes, aiRoutes, agentRoutes, dashboardRoutes, userRoutes]) {
    api.use(routes);
  }
  app.use('/api/v1', api);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
