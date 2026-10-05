import mongoose from 'mongoose';
import { SEVERITIES } from './constants.js';

const schema = new mongoose.Schema({
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Host' },
  severity: { type: String, enum: SEVERITIES, required: true },
  kind: { type: String, required: true }, // finding | resource_spike | host_offline | scan_failure | anomaly
  dedupKey: { type: String, required: true },
  title: { type: String, required: true },
  message: String,
  findingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Finding' },
  acknowledged: { type: Boolean, default: false },
  acknowledgedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  acknowledgedAt: Date,
  count: { type: Number, default: 1 },
  lastOccurrence: { type: Date, default: Date.now },
}, { timestamps: true });
schema.index({ dedupKey: 1, acknowledged: 1, createdAt: -1 });
schema.index({ hostId: 1, createdAt: -1 });
schema.index({ acknowledged: 1, severity: 1 });
export const Alert = mongoose.model('Alert', schema);
