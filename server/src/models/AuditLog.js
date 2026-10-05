import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  actor: String, // email or agent id
  action: { type: String, required: true },
  resource: String,
  resourceId: String,
  metadata: mongoose.Schema.Types.Mixed,
  ip: String,
  timestamp: { type: Date, default: Date.now },
}, { versionKey: false });
schema.index({ timestamp: -1 });
schema.index({ userId: 1, timestamp: -1 });
export const AuditLog = mongoose.model('AuditLog', schema);
