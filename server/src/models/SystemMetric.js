import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Host', required: true },
  timestamp: { type: Date, default: Date.now },
  cpu: mongoose.Schema.Types.Mixed,
  memory: mongoose.Schema.Types.Mixed,
  disk: mongoose.Schema.Types.Mixed,
  load: mongoose.Schema.Types.Mixed,
  network: mongoose.Schema.Types.Mixed,
  processCount: Number,
  uptimeSeconds: Number,
}, { versionKey: false });
schema.index({ hostId: 1, timestamp: -1 });
schema.index({ timestamp: 1 });
export const SystemMetric = mongoose.model('SystemMetric', schema);
