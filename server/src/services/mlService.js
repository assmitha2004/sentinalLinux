// Local anomaly detection (spec §30). Robust z-score (median/MAD) of the latest window against
// the host's own history. Honest about data sufficiency: below ML_MIN_SAMPLES it reports LEARNING
// and makes no predictions. Isolation Forest etc. can replace `robustZ` behind the same interface.
import { config } from '../config/index.js';
import { SystemMetric } from '../models/index.js';

const FEATURES = {
  cpu: (m) => m.cpu?.usage,
  memory: (m) => m.memory?.percent,
  processCount: (m) => m.processCount,
  netRx: (m) => m.network?.rxRate,
  netTx: (m) => m.network?.txRate,
};

const median = (a) => { const s = [...a].sort((x, y) => x - y); const n = s.length; return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2; };

export function robustZ(history, value) {
  const vals = history.filter((v) => typeof v === 'number' && Number.isFinite(v));
  if (vals.length < 10 || typeof value !== 'number') return null;
  const med = median(vals);
  const mad = median(vals.map((v) => Math.abs(v - med))) || 1e-9;
  return 0.6745 * (value - med) / mad;
}

export function detect(samples, { minSamples = config.ML_MIN_SAMPLES, threshold = config.ML_Z_THRESHOLD, window = 12 } = {}) {
  if (samples.length < minSamples) {
    return { status: 'LEARNING', message: 'Learning / Insufficient historical data', samples: samples.length, required: minSamples, anomalies: [] };
  }
  const recent = samples.slice(-window);
  const baseline = samples.slice(0, -window);
  const anomalies = [];
  for (const [name, get] of Object.entries(FEATURES)) {
    const hist = baseline.map(get);
    const cur = median(recent.map(get).filter((v) => typeof v === 'number'));
    const z = robustZ(hist, cur);
    // Only flag sustained (window-median) deviations, and only upward spikes for resource features.
    if (z !== null && z > threshold) {
      anomalies.push({ feature: name, value: Math.round(cur * 100) / 100, baselineMedian: Math.round(median(hist.filter(Number.isFinite)) * 100) / 100, zScore: Math.round(z * 10) / 10 });
    }
  }
  return { status: 'ACTIVE', model: 'robust-zscore (median/MAD)', samples: samples.length, threshold, anomalies };
}

export async function analyzeHost(hostId) {
  const since = new Date(Date.now() - 7 * 86400000);
  const samples = await SystemMetric.find({ hostId, timestamp: { $gte: since } }).sort({ timestamp: 1 })
    .select('cpu memory processCount network timestamp').limit(20000).lean();
  return detect(samples);
}
