import mongoose from 'mongoose';
import { FINDING_STATUS, SEVERITIES } from './constants.js';

const schema = new mongoose.Schema({
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Host', required: true },
  fingerprint: { type: String, required: true }, // agent's stable id (type|resource hash)
  type: { type: String, required: true },
  category: { type: String, required: true },
  check: String,
  severity: { type: String, enum: SEVERITIES, required: true },
  confidence: { type: Number, min: 0, max: 1 },
  title: { type: String, required: true },
  description: String,
  whyItMatters: String,
  evidence: mongoose.Schema.Types.Mixed,
  resource: String,
  recommendation: String,
  verification: { mode: String, command: String },
  requiresAdminApproval: Boolean,
  source: { type: String, default: 'sentinel-agent' },
  status: { type: String, enum: FINDING_STATUS, default: 'OPEN' },
  statusChangedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  resolvedAt: Date,
  occurrences: { type: Number, default: 1 },
}, { timestamps: true });
schema.index({ hostId: 1, fingerprint: 1 }, { unique: true });
schema.index({ hostId: 1, status: 1, severity: 1 });
schema.index({ severity: 1 });
schema.index({ lastSeen: -1 });
export const Finding = mongoose.model('Finding', schema);
