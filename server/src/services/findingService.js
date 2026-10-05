// Upserts agent findings, keeps first/last seen, and auto-resolves findings whose check ran
// successfully in this scan but no longer reports them.
import { Finding } from '../models/index.js';
import { emit } from '../sockets/index.js';
import { alertsForNewFindings } from './alertService.js';

const ACTIVE = ['OPEN', 'ACKNOWLEDGED'];
const CONCLUSIVE = new Set(['PASS', 'WARN', 'FAIL']); // NOT_SUPPORTED/ERROR prove nothing

export async function ingestFindings(hostId, checks) {
  const now = new Date();
  const created = [];
  const seen = [];
  for (const check of checks) {
    for (const f of check.findings || []) {
      const fp = f.id;
      seen.push(fp);
      const fields = {
        type: f.type, category: f.category, check: check.check, severity: f.severity, confidence: f.confidence,
        title: f.title, description: f.description, whyItMatters: f.whyItMatters, evidence: f.evidence,
        resource: f.resource, recommendation: f.recommendation, verification: f.verification,
        requiresAdminApproval: !!f.requiresAdminApproval, source: f.source || 'sentinel-agent', lastSeen: now,
      };
      const existing = await Finding.findOne({ hostId, fingerprint: fp });
      if (!existing) {
        created.push(await Finding.create({ hostId, fingerprint: fp, ...fields, firstSeen: now }));
      } else {
        Object.assign(existing, fields);
        existing.occurrences += 1;
        // A resolved issue that reappears is reopened; acknowledged/false-positive keep the analyst's decision.
        if (existing.status === 'RESOLVED') { existing.status = 'OPEN'; existing.resolvedAt = undefined; created.push(existing); }
        await existing.save();
      }
    }
  }
  // Auto-resolve: same check ran conclusively and did not report the fingerprint.
  const ranChecks = checks.filter((c) => CONCLUSIVE.has(c.status)).map((c) => c.check);
  let resolved = 0;
  if (ranChecks.length) {
    const r = await Finding.updateMany(
      { hostId, check: { $in: ranChecks }, status: { $in: ACTIVE }, fingerprint: { $nin: seen } },
      { $set: { status: 'RESOLVED', resolvedAt: now } },
    );
    resolved = r.modifiedCount || 0;
  }
  for (const f of created) emit('finding:new', { finding: { _id: f._id, title: f.title, severity: f.severity, category: f.category } }, hostId);
  await alertsForNewFindings(hostId, created);
  return { created: created.length, seen: seen.length, resolved, fingerprints: seen };
}

export const activeFindings = (hostId) => Finding.find({ hostId, status: { $in: ['OPEN', 'ACKNOWLEDGED'] } }).lean();
