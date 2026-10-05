import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  label: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  expiresAt: { type: Date, required: true },
  maxUses: { type: Number, default: 1 },
  uses: { type: Number, default: 0 },
  revoked: { type: Boolean, default: false },
}, { timestamps: true });
export const EnrollmentToken = mongoose.model('EnrollmentToken', schema);
