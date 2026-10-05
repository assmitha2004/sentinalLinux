// Configurable retention (spec §70). Open/acknowledged findings are never auto-deleted.
import { config } from '../config/index.js';
import { Alert, AuditLog, Finding, SecurityScan, SystemMetric } from '../models/index.js';
import { logger } from '../utils/logger.js';

const log = logger('retention');
const ago = (days) => new Date(Date.now() - days * 86400000);

export async function applyRetention() {
  const r = await Promise.all([
    SystemMetric.deleteMany({ timestamp: { $lt: ago(config.RETENTION_METRICS_DAYS) } }),
    Finding.deleteMany({ status: { $in: ['RESOLVED', 'FALSE_POSITIVE'] }, lastSeen: { $lt: ago(config.RETENTION_FINDINGS_DAYS) } }),
    Alert.deleteMany({ acknowledged: true, createdAt: { $lt: ago(config.RETENTION_ALERTS_DAYS) } }),
    AuditLog.deleteMany({ timestamp: { $lt: ago(config.RETENTION_AUDIT_DAYS) } }),
    SecurityScan.deleteMany({ createdAt: { $lt: ago(config.RETENTION_SCANS_DAYS) } }),
  ]);
  const [metrics, findings, alerts, audit, scans] = r.map((x) => x.deletedCount || 0);
  log.info('retention applied', { metrics, findings, alerts, audit, scans });
  return { metrics, findings, alerts, audit, scans };
}
