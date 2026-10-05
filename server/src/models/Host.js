import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  hostname: { type: String, required: true },
  machineId: { type: String, index: true },
  agentId: { type: String, required: true, unique: true },
  agentSecretHash: { type: String, required: true, select: false },
  agentVersion: String,
  os: { type: mongoose.Schema.Types.Mixed, default: {} },
  kernel: String,
  architecture: String,
  status: { type: String, enum: ['ONLINE', 'DEGRADED', 'OFFLINE'], default: 'ONLINE', index: true },
  lastSeen: { type: Date, index: true },
  capabilities: { type: mongoose.Schema.Types.Mixed, default: {} },
  snapshot: { type: mongoose.Schema.Types.Mixed, default: {} }, // latest processes/network/services
  snapshotAt: Date,
  latestMetric: { type: mongoose.Schema.Types.Mixed },
  scores: {
    risk: Number, riskLevel: String, health: Number, posture: Number, updatedAt: Date,
  },
  currentScan: String,
  outbox: Number,
}, { timestamps: true });

export const Host = mongoose.model('Host', schema);
