// DEMO_MODE fixtures for frontend development only. Every screen shows a "Demo data" banner
// when this is active; these values are illustrative and never mixed with real hosts.
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString();
const HOST = '000000000000000000000d01';

const host = {
  id: HOST, hostname: 'boss-demo-ws01', status: 'ONLINE', lastSeen: iso(4000), agentVersion: '1.0.0',
  os: { distribution: 'BOSS', version: '10', codename: 'unnati', prettyName: 'BOSS GNU/Linux 10 (demo)', isBoss10: true, initSystem: 'systemd' },
  kernel: '6.1.0-boss-amd64', architecture: 'x86_64', activeAlerts: 2,
  capabilities: { systemd: true, ss: true, ip: true, journalctl: true, auditd: false, openscap: false, rkhunter: false, chkrootkit: false, nftables: true, iptables: true, sshd: true, packageManager: 'dpkg', isRoot: true },
  scores: { risk: 64, riskLevel: 'HIGH_RISK', health: 86, posture: 61 },
  latestMetric: { cpu: { usage: 23, logical: 8 }, memory: { percent: 41, total: 16e9, used: 6.5e9 }, disk: [{ mount: '/', percent: 69, total: 2.5e11, used: 1.7e11 }], load: { load1: 0.8, load5: 0.7, load15: 0.6 }, processCount: 241, uptimeSeconds: 302400 },
};

const F = (i, severity, category, title, extra = {}) => ({
  _id: `00000000000000000000f${String(i).padStart(3, '0')}`, hostId: { _id: HOST, hostname: host.hostname }, fingerprint: `demo${i}`,
  severity, category, title, confidence: 0.9, status: 'OPEN', firstSeen: iso(86400000 * i), lastSeen: iso(60000),
  description: title, whyItMatters: 'Demo explanation.', evidence: { demo: true }, recommendation: 'Demo recommendation.',
  verification: { mode: 'READ-ONLY', command: 'sshd -T' }, requiresAdminApproval: true, type: 'demo', ...extra,
});
const findings = [
  F(1, 'HIGH', 'ssh', 'SSH permits direct root login', { type: 'ssh_root_login', description: 'PermitRootLogin is yes. SSH is listening on all interfaces.', evidence: { PermitRootLogin: 'yes', source: 'sshd -T' } }),
  F(2, 'HIGH', 'permissions', 'World-writable executable: /usr/local/bin/backup.sh', { evidence: { path: '/usr/local/bin/backup.sh', mode: '0o777' } }),
  F(3, 'MEDIUM', 'firewall', 'No active host firewall rules', { verification: { mode: 'READ-ONLY', command: 'nft list ruleset' } }),
  F(4, 'MEDIUM', 'ssh', 'SSH allows password authentication'),
  F(5, 'LOW', 'kernel', 'Kernel parameter kernel.kptr_restrict = 0'),
  F(6, 'LOW', 'network', 'Service listening on all interfaces: tcp/8080'),
];
const metrics = Array.from({ length: 90 }, (_, i) => ({
  timestamp: iso((90 - i) * 40000), cpu: { usage: 18 + 10 * Math.sin(i / 6) + (i % 7) }, memory: { percent: 40 + (i % 5) },
  disk: [{ mount: '/', percent: 69 }], load: { load1: 0.7, load5: 0.6, load15: 0.5 }, network: { rxRate: 40000 + 20000 * Math.sin(i / 4), txRate: 12000 + 6000 * Math.cos(i / 5) }, processCount: 240 + (i % 4),
}));
const areas = [['ssh', 'INSECURE', 'HIGH'], ['firewall', 'WARNING', 'MEDIUM', 'DISABLED'], ['files', 'INSECURE', 'HIGH'], ['network', 'GOOD'], ['processes', 'GOOD'],
  ['users', 'GOOD'], ['rootkit', 'GOOD', null, 'No strong rootkit indicators detected'], ['kernel', 'GOOD'], ['logging', 'WARNING', 'LOW'],
  ['benchmark', 'NOT_SUPPORTED', null, 'Required benchmark tooling not available (oscap not installed)'], ['vulnerabilities', 'GOOD']]
  .map(([area, status, worstSeverity, detail]) => ({ area, status, worstSeverity, detail, openFindings: worstSeverity ? 1 : 0, lastChecked: iso(120000) }));
const scans = [{ scanId: 'demo-scan-1', scanType: 'STANDARD', trigger: 'SCHEDULED', status: 'COMPLETED', progress: 100, checksTotal: 16, checksCompleted: 16, startedAt: iso(130000), completedAt: iso(120000), summary: { findings: 6, newFindings: 0, autoResolved: 1 }, scores: { risk: 64, health: 86 } }];
const snapshot = {
  snapshotAt: iso(5000),
  processes: { count: 241, rootCount: 88, top: [{ pid: 1201, user: 'root', name: 'Xorg', cpu: 4.1, mem: 1.2, exe: '/usr/lib/xorg/Xorg', cmdline: '/usr/lib/xorg/Xorg :0' }, { pid: 2210, user: 'boss', name: 'firefox-esr', cpu: 3.2, mem: 6.8, exe: '/usr/lib/firefox-esr/firefox-esr', cmdline: 'firefox-esr' }] },
  network: { interfaces: [{ name: 'enp3s0', up: true, ipv4: ['10.20.1.15'], ipv6: [], mac: '52:54:00:12:34:56', rxBytes: 9.1e9, txBytes: 1.2e9 }], listening: [{ proto: 'tcp', localAddress: '0.0.0.0', localPort: 22, process: 'sshd', pid: 812 }, { proto: 'tcp', localAddress: '0.0.0.0', localPort: 8080, process: 'python3', pid: 4021 }], established: [], counts: { listening: 2, established: 14, external: 3, total: 20 } },
  services: { init: 'systemd', total: 182, running: 41, failed: 1, services: [{ name: 'ssh.service', load: 'loaded', active: 'active', sub: 'running', description: 'OpenBSD Secure Shell server' }, { name: 'cups-browsed.service', load: 'loaded', active: 'failed', sub: 'failed', description: 'Make remote CUPS printers available locally' }] },
  system: { hostname: host.hostname, prettyName: host.os.prettyName, kernel: host.kernel, uptimeSeconds: 302400, bootTime: Math.floor((now - 302400000) / 1000) },
};
const insight = { _id: 'demo-ai-1', engine: 'deterministic', fallbackReason: 'AI provider not configured', riskScore: 64, riskLevel: 'HIGH_RISK', healthScore: 86, createdAt: iso(300000),
  summary: 'This host currently has a HIGH RISK security risk score (64/100). 6 open finding(s); the highest-priority issue is "SSH permits direct root login".',
  priorities: findings.slice(0, 3).map((f) => ({ title: f.title, reason: f.whyItMatters, severity: f.severity, recommendation: 'REQUIRES ADMIN APPROVAL: Create/verify a non-root administrative account with sudo.', verification: f.verification.command })),
  observations: ['Category "ssh" contributes 16.2 risk weight.'], uncertainties: ['Anomaly detection is still learning (120/500 samples).'], ml: { status: 'LEARNING', samples: 120, required: 500, anomalies: [] } };
const alerts = [{ _id: 'a1', hostId: { _id: HOST, hostname: host.hostname }, severity: 'HIGH', kind: 'finding', title: 'SSH permits direct root login', message: 'PermitRootLogin is yes.', acknowledged: false, count: 1, createdAt: iso(3600000) },
  { _id: 'a2', hostId: { _id: HOST, hostname: host.hostname }, severity: 'HIGH', kind: 'finding', title: 'World-writable executable: /usr/local/bin/backup.sh', acknowledged: false, count: 1, createdAt: iso(7200000) }];

const routes = [
  [/^\/auth\/(login|register)$/, () => ({ user: { id: 'u', name: 'Demo admin', email: 'demo@sentinel.local', role: 'ADMIN' }, token: 'demo' })],
  [/^\/auth\/me$/, () => ({ user: { id: 'u', name: 'Demo admin', email: 'demo@sentinel.local', role: 'ADMIN' } })],
  [/^\/dashboard\/summary$/, () => ({ hosts: { total: 1, online: 1, degraded: 0, offline: 0, critical: 0, highRisk: 1 }, averageRisk: 64, averageHealth: 86, activeAlerts: 2, aiConfigured: false,
    findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 2, LOW: 2, INFO: 0 }, topFindings: findings.slice(0, 4) })],
  [/^\/hosts$/, () => [host]],
  [/^\/hosts\/[^/]+$/, () => host],
  [/^\/hosts\/[^/]+\/metrics$/, () => metrics],
  [/^\/hosts\/[^/]+\/snapshot$/, () => snapshot],
  [/^\/hosts\/[^/]+\/security-score$/, () => ({ risk: { score: 64, level: 'HIGH_RISK', factors: [{ category: 'ssh', weight: 16.2 }] }, health: { score: 86, factors: [] }, posture: 61,
    bySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 2, LOW: 2, INFO: 0 }, areas, history: Array.from({ length: 12 }, (_, i) => ({ at: iso((12 - i) * 3600000), risk: 50 + i, health: 88 - (i % 3) })) })],
  [/^\/hosts\/[^/]+\/findings$/, () => findings],
  [/^\/findings$/, () => findings],
  [/^\/findings\/[^/]+$/, (url) => ({ ...findings.find((f) => url.endsWith(f._id)) || findings[0], remediation: { steps: ['Demo step one.', 'Demo step two.'], verification: { mode: 'READ-ONLY', command: 'sshd -T | grep permitrootlogin' }, modifying: 'Edit /etc/ssh/sshd_config', requiresAdminApproval: true } })],
  [/^\/hosts\/[^/]+\/scans$/, () => scans],
  [/^\/hosts\/[^/]+\/ai\/insights$/, () => [insight]],
  [/^\/hosts\/[^/]+\/ai\/analyze$/, () => insight],
  [/^\/alerts$/, () => alerts],
  [/^\/settings$/, () => ({ heartbeatIntervalSec: 30, degradedMultiplier: 2, offlineMultiplier: 4, alertCooldownMin: 30, retentionDays: { metrics: 7, findings: 90, alerts: 90, audit: 180, scans: 90 }, ai: { configured: false, provider: 'none' }, ml: { minSamples: 500, zThreshold: 4 } })],
  [/^\/(users|audit-logs|agent\/enrollment-tokens)$/, () => []],
];

export async function demoAdapter(config) {
  const url = config.url.split('?')[0];
  const hit = routes.find(([re]) => re.test(url));
  await new Promise((r) => setTimeout(r, 150));
  const data = hit ? hit[1](url) : { ok: true };
  return { data: { success: true, data, meta: { total: Array.isArray(data) ? data.length : undefined, demo: true } }, status: 200, statusText: 'OK', headers: {}, config };
}
