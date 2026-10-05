import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';

const log = logger('db');
mongoose.set('strictQuery', true);

export async function connectDb(uri) {
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000, maxPoolSize: 20 });
  log.info('connected to MongoDB');
  // Explicit index build so a fresh database is query-ready (spec §79).
  await Promise.all(Object.values(mongoose.models).map((m) => m.createIndexes().catch((e) => log.warn(`index ${m.modelName}: ${e.message}`))));
}

export const disconnectDb = () => mongoose.disconnect();
