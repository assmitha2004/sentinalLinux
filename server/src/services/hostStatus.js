// Heartbeat-based ONLINE / DEGRADED / OFFLINE sweeper (spec §60).
import { config } from '../config/index.js';
import { Host } from '../models/index.js';
import { emit } from '../sockets/index.js';
import { raiseAlert } from './alertService.js';

export function statusFor(lastSeen, now = Date.now()) {
  if (!lastSeen) return 'OFFLINE';
  const age = (now - new Date(lastSeen).getTime()) / 1000;
  const hb = config.HEARTBEAT_INTERVAL_SEC;
  if (age > hb * config.OFFLINE_MULTIPLIER) return 'OFFLINE';
  if (age > hb * config.DEGRADED_MULTIPLIER) return 'DEGRADED';
  return 'ONLINE';
}

export async function sweepHostStatus() {
  const hosts = await Host.find({}).select('hostname status lastSeen').lean();
  for (const h of hosts) {
    const next = statusFor(h.lastSeen);
    if (next === h.status) continue;
    await Host.updateOne({ _id: h._id }, { $set: { status: next } });
    emit(next === 'OFFLINE' ? 'host:offline' : 'host:status', { status: next, hostname: h.hostname }, h._id);
    if (next === 'OFFLINE') {
      await raiseAlert({ hostId: h._id, severity: 'HIGH', kind: 'host_offline', key: 'offline',
        title: `Host ${h.hostname} is offline`, message: `No heartbeat since ${h.lastSeen?.toISOString?.() || h.lastSeen}.` });
    }
  }
}
