// Central configuration: validated once at startup (fail fast on missing secrets).
import 'dotenv/config';
import { z } from 'zod';

const num = (d) => z.coerce.number().default(d);
const bool = (d) => z.enum(['true', 'false']).default(d ? 'true' : 'false').transform((v) => v === 'true');

const schema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: num(5000),
  MONGODB_URI: z.string().min(1, 'MONGODB_URI is required'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_EXPIRES_IN: z.string().default('8h'),
  AGENT_ENROLLMENT_SECRET: z.string().optional().default(''),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  ALLOW_REGISTRATION: bool(true),
  TRUST_PROXY: bool(false),
  AI_PROVIDER: z.enum(['', 'none', 'anthropic', 'openai']).default(''),
  AI_API_KEY: z.string().optional().default(''),
  AI_MODEL: z.string().optional().default(''),
  AI_BASE_URL: z.string().optional().default(''),
  AI_TIMEOUT_MS: num(60000),
  HEARTBEAT_INTERVAL_SEC: num(30),
  DEGRADED_MULTIPLIER: num(2),
  OFFLINE_MULTIPLIER: num(4),
  ALERT_COOLDOWN_MIN: num(30),
  RETENTION_METRICS_DAYS: num(7),
  RETENTION_FINDINGS_DAYS: num(90),
  RETENTION_ALERTS_DAYS: num(90),
  RETENTION_AUDIT_DAYS: num(180),
  RETENTION_SCANS_DAYS: num(90),
  ML_MIN_SAMPLES: num(500),
  ML_Z_THRESHOLD: num(4),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('Invalid configuration:\n' + parsed.error.issues.map((i) => ` - ${i.path.join('.')}: ${i.message}`).join('\n'));
  process.exit(1);
}
const env = parsed.data;

export const config = {
  ...env,
  isProd: env.NODE_ENV === 'production',
  corsOrigins: env.CORS_ORIGIN.split(',').map((s) => s.trim()).filter(Boolean),
  aiEnabled: ['anthropic', 'openai'].includes(env.AI_PROVIDER) && !!env.AI_MODEL &&
    (env.AI_PROVIDER === 'openai' ? !!(env.AI_API_KEY || env.AI_BASE_URL) : !!env.AI_API_KEY),
  // Weighted risk model (spec §27). Tune here; documented in README.
  risk: {
    severityWeight: { CRITICAL: 25, HIGH: 10, MEDIUM: 4, LOW: 1, INFO: 0 },
    categoryMultiplier: { rootkit: 1.5, network: 1.2, process: 1.2, users: 1.2, ssh: 1.1, health: 0 },
    saturation: 40,
    bands: [[20, 'EXCELLENT'], [40, 'GOOD'], [60, 'MODERATE'], [80, 'HIGH_RISK'], [100, 'CRITICAL']],
  },
};
