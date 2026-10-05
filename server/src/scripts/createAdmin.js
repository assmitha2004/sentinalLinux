// Usage: npm run create-admin -- admin@example.com "Admin Name"   (password read from ADMIN_PASSWORD env)
import bcrypt from 'bcryptjs';
import { config } from '../config/index.js';
import { connectDb, disconnectDb } from '../config/db.js';
import { User } from '../models/index.js';

const [email, name = 'Administrator'] = process.argv.slice(2);
const password = process.env.ADMIN_PASSWORD;
if (!email || !password || password.length < 10) {
  console.error('Usage: ADMIN_PASSWORD=<min 10 chars> npm run create-admin -- <email> [name]');
  process.exit(1);
}
await connectDb(config.MONGODB_URI);
const user = await User.findOneAndUpdate({ email: email.toLowerCase() },
  { name, email: email.toLowerCase(), role: 'ADMIN', passwordHash: await bcrypt.hash(password, 12), $inc: { tokenVersion: 1 } },
  { upsert: true, new: true });
console.log(`Admin ready: ${user.email}`);
await disconnectDb();
