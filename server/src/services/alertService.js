// Alert generation with dedup + cooldown (spec §59): a repeat of the same unacknowledged alert
// within the cooldown increments its counter instead of creating a new alert.
import { config } from '../config/index.js';
import { Alert } from '../models/index.js';
import { emit } from '../sockets/index.js';

export async function raiseAlert({ hostId, severity, kind, key, title, message, findingId }) {
  const dedupKey = `${hostId || 'global'}:${kind}:${key}`;
  const since = new Date(Date.now() - config.ALERT_COOLDOWN_MIN * 60000);
  const existing = await Alert.findOne({ dedupKey, acknowledged: false, lastOccurrence: { $gte: since } });
  if (existing) {
    existing.count += 1;
    existing.lastOccurrence = new Date();
    await existing.save();
    return { alert: existing, created: false };
  }
  const alert = await Alert.create({ hostId, severity, kind, dedupKey, title, message, findingId });
  emit('security:alert', { alert }, hostId);
  return { alert, created: true };
}

const ALERT_ON = new Set(['CRITICAL', 'HIGH']);
const ALWAYS = new Set(['suspicious_connection', 'process_from_temp', 'suspicious_cmdline', 'temp_deleted_exe_running', 'hidden_process']);

export function shouldAlertForFinding(f) {
  return ALERT_ON.has(f.severity) || (ALWAYS.has(f.type) && f.severity !== 'INFO');
}

export async function alertsForNewFindings(hostId, findings) {
  for (const f of findings.filter(shouldAlertForFinding)) {
    await raiseAlert({ hostId, severity: f.severity, kind: 'finding', key: f.fingerprint, title: f.title,
      message: f.description, findingId: f._id });
  }
}
