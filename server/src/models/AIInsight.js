import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Host', required: true },
  riskScore: Number,
  riskLevel: String,
  healthScore: Number,
  summary: String,
  priorities: [mongoose.Schema.Types.Mixed],
  recommendations: [mongoose.Schema.Types.Mixed],
  observations: [String],
  uncertainties: [String],
  ml: mongoose.Schema.Types.Mixed,
  engine: { type: String, enum: ['llm', 'deterministic'], required: true },
  model: String,
  fallbackReason: String,
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });
schema.index({ hostId: 1, createdAt: -1 });
export const AIInsight = mongoose.model('AIInsight', schema);
