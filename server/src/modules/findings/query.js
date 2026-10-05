import { FINDING_STATUS, SEVERITIES } from '../../models/constants.js';

const list = (v, allowed) => String(v).split(',').map((x) => x.trim().toUpperCase()).filter((x) => allowed.includes(x));
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Builds a safe Mongo filter from query params (whitelisted, no operator injection). */
export function findingQuery(qs) {
  const q = {};
  if (qs.hostId && /^[a-f0-9]{24}$/i.test(qs.hostId)) q.hostId = qs.hostId;
  if (qs.severity) q.severity = { $in: list(qs.severity, SEVERITIES) };
  if (qs.status) q.status = { $in: list(qs.status, FINDING_STATUS) };
  else q.status = { $in: ['OPEN', 'ACKNOWLEDGED'] };
  if (qs.status === 'ALL') delete q.status;
  if (qs.category && /^[a-z_]{1,40}(,[a-z_]{1,40}){0,9}$/.test(qs.category)) q.category = { $in: qs.category.split(',') };
  if (qs.from || qs.to) {
    q.lastSeen = {};
    if (qs.from && !Number.isNaN(Date.parse(qs.from))) q.lastSeen.$gte = new Date(qs.from);
    if (qs.to && !Number.isNaN(Date.parse(qs.to))) q.lastSeen.$lte = new Date(qs.to);
  }
  if (qs.q && typeof qs.q === 'string') q.title = { $regex: escape(qs.q.slice(0, 100)), $options: 'i' };
  return q;
}
