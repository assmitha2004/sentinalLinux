import mongoose from 'mongoose';
import { SCAN_TYPES } from './constants.js';

const schema = new mongoose.Schema({
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Host', required: true },
  scanId: { type: String, required: true, unique: true },
  scanType: { type: String, enum: SCAN_TYPES, required: true },
  trigger: { type: String, enum: ['SCHEDULED', 'MANUAL'], default: 'SCHEDULED' },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['QUEUED', 'DISPATCHED', 'RUNNING', 'COMPLETED', 'COMPLETED_WITH_ERRORS', 'FAILED'], default: 'QUEUED' },
  progress: { type: Number, default: 0 },
  checksCompleted: { type: Number, default: 0 },
  checksTotal: { type: Number, default: 0 },
  currentCheck: String,
  startedAt: Date,
  completedAt: Date,
  summary: mongoose.Schema.Types.Mixed,
  checks: { type: [mongoose.Schema.Types.Mixed], default: [] }, // per-check status + data (no findings duplicated)
  findingIds: [String],
  scores: { risk: Number, riskLevel: String, health: Number },
  error: String,
}, { timestamps: true });
schema.index({ hostId: 1, createdAt: -1 });
schema.index({ status: 1 });
export const SecurityScan = mongoose.model('SecurityScan', schema);
