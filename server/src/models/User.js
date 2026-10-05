import mongoose from 'mongoose';
import { ROLES } from './constants.js';

const schema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, enum: ROLES, default: 'VIEWER' },
  failedLogins: { type: Number, default: 0, select: false },
  lockedUntil: { type: Date, select: false },
  tokenVersion: { type: Number, default: 0 }, // bump to invalidate all JWTs (logout everywhere)
}, { timestamps: true });

schema.methods.toPublic = function toPublic() {
  return { id: this._id, name: this.name, email: this.email, role: this.role, createdAt: this.createdAt };
};
export const User = mongoose.model('User', schema);
