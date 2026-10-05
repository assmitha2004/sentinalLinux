// Background jobs: host status sweep, anomaly alerts, retention.
import { Host } from '../models/index.js';
import { logger } from '../utils/logger.js';
import { raiseAlert } from './alertService.js';
import { sweepHostStatus } from './hostStatus.js';
import { analyzeHost } from './mlService.js';
import { applyRetention } from './retention.js';

const log = logger('jobs');
const timers = [];

function every(ms, name, fn) {
  const run = () => fn().catch((e) => log.error(`${name} failed: ${e.message}`));
  timers.push(setInterval(run, ms));
  return run;
}

async function anomalySweep() {
  const hosts = await Host.find({ status: 'ONLINE' }).select('hostname').lean();
  for (const h of hosts) {
    const ml = await analyzeHost(h._id);
    for (const a of ml.anomalies || []) {
      await raiseAlert({ hostId: h._id, severity: 'MEDIUM', kind: 'anomaly', key: a.feature,
        title: `Unusual ${a.feature} on ${h.hostname}`,
        message: `Current ${a.value} vs baseline median ${a.baselineMedian} (robust z=${a.zScore}). Statistical signal, not proof of compromise.` });
    }
  }
}

export function startJobs() {
  every(30000, 'host-status', sweepHostStatus)();
  every(5 * 60000, 'anomaly', anomalySweep);
  every(60 * 60000, 'retention', applyRetention)();
}

export const stopJobs = () => timers.splice(0).forEach(clearInterval);
