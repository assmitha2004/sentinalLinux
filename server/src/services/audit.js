import { AuditLog } from '../models/index.js';
import { logger } from '../utils/logger.js';

const log = logger('audit');
const SENSITIVE = /pass|secret|token|key/i;

// Never store secrets in metadata (spec §61).
function scrub(meta = {}) {
  return Object.fromEntries(Object.entries(meta).filter(([k]) => !SENSITIVE.test(k)));
}

export async function audit(req, action, resource, resourceId, metadata) {
  try {
    await AuditLog.create({
      userId: req.user?._id, actor: req.user?.email || req.agentHost?.agentId || metadata?.actor,
      action, resource, resourceId: resourceId ? String(resourceId) : undefined,
      metadata: scrub(metadata), ip: req.ip,
    });
  } catch (e) {
    log.error(`audit write failed: ${e.message}`);
  }
}
