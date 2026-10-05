import './setup.js';
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import mongoose from 'mongoose';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { connectDb } from '../src/config/db.js';
import { Alert, SystemMetric } from '../src/models/index.js';

let app; let skip = false;
before(async () => {
  try {
    await connectDb(process.env.MONGODB_URI);
    await mongoose.connection.db.dropDatabase();
    await connectDb(process.env.MONGODB_URI);
  } catch (e) {
    skip = `MongoDB not reachable at ${process.env.MONGODB_URI}: ${e.message}`;
  }
  app = createApp();
});
after(async () => { if (!skip) await mongoose.connection.db.dropDatabase(); await mongoose.disconnect(); });

const S = {};
const t = (name, fn) => test(name, async (ctx) => { if (skip) return ctx.skip(skip); await fn(); });
const auth = (tok) => ({ Authorization: `Bearer ${tok}` });

function finding(id, severity, extra = {}) {
  return { id, type: 'ssh_root_login', category: 'ssh', severity, title: `finding ${id}`, description: 'd', evidence: { a: 1 },
    resource: id, confidence: 0.9, recommendation: 'r', verification: { mode: 'READ-ONLY', command: 'sshd -T' }, requiresAdminApproval: true, ...extra };
}
function scanPayload(scanId, findings, type = 'QUICK') {
  return { scanId, type, status: 'COMPLETED', startedAt: new Date().toISOString(), completedAt: new Date().toISOString(),
    checksTotal: 2, checksCompleted: 2, summary: { findings: findings.length },
    checks: [{ check: 'ssh', status: findings.length ? 'FAIL' : 'PASS', category: 'ssh', data: {}, findings, errors: [], capability: {} },
      { check: 'benchmark', status: 'NOT_SUPPORTED', reason: 'oscap missing', data: {}, findings: [], errors: [], capability: {} }] };
}

t('health endpoint', async () => {
  const r = await request(app).get('/health');
  assert.equal(r.status, 200);
  assert.equal(r.body.success, true);
});

t('first user becomes ADMIN, next becomes VIEWER; weak passwords rejected', async () => {
  const weak = await request(app).post('/api/v1/auth/register').send({ name: 'x', email: 'w@x.io', password: 'short' });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error.code, 'VALIDATION_ERROR');
  const a = await request(app).post('/api/v1/auth/register').send({ name: 'Admin', email: 'admin@x.io', password: 'correct-horse-1' });
  assert.equal(a.status, 201);
  assert.equal(a.body.data.user.role, 'ADMIN');
  assert.equal(a.body.data.user.passwordHash, undefined);
  S.admin = a.body.data.token;
  const v = await request(app).post('/api/v1/auth/register').send({ name: 'View', email: 'viewer@x.io', password: 'correct-horse-2' });
  assert.equal(v.body.data.user.role, 'VIEWER');
  S.viewer = v.body.data.token;
});

t('login, me, and unauthenticated access', async () => {
  const bad = await request(app).post('/api/v1/auth/login').send({ email: 'admin@x.io', password: 'nope-nope-1' });
  assert.equal(bad.status, 401);
  const r = await request(app).post('/api/v1/auth/login').send({ email: 'admin@x.io', password: 'correct-horse-1' });
  assert.equal(r.status, 200);
  S.admin = r.body.data.token;
  const me = await request(app).get('/api/v1/auth/me').set(auth(S.admin));
  assert.equal(me.body.data.user.email, 'admin@x.io');
  assert.equal((await request(app).get('/api/v1/hosts')).status, 401);
  assert.equal((await request(app).get('/api/v1/hosts').set(auth('garbage'))).status, 401);
});

t('agent enrollment with one-time token', async () => {
  const forbidden = await request(app).post('/api/v1/agent/enrollment-tokens').set(auth(S.viewer)).send({});
  assert.equal(forbidden.status, 403);
  const tok = await request(app).post('/api/v1/agent/enrollment-tokens').set(auth(S.admin)).send({ label: 'test', maxUses: 1 });
  assert.equal(tok.status, 201);
  const body = { enrollmentToken: tok.body.data.token, hostname: 'boss-test', machineId: 'abc123',
    os: { distribution: 'BOSS', version: '10', isBoss10: true }, kernel: '6.1.0', architecture: 'x86_64', capabilities: { ss: true } };
  const reg = await request(app).post('/api/v1/hosts/register').send(body);
  assert.equal(reg.status, 201);
  S.hostId = reg.body.data.hostId;
  S.agent = { 'X-Agent-Id': reg.body.data.agentId, Authorization: `Bearer ${reg.body.data.agentSecret}` };
  const reuse = await request(app).post('/api/v1/hosts/register').send(body);
  assert.equal(reuse.status, 401, 'token is single use');
});

t('agent auth is enforced', async () => {
  const r = await request(app).post('/api/v1/agent/heartbeat').set({ 'X-Agent-Id': S.agent['X-Agent-Id'], Authorization: 'Bearer wrong' }).send({});
  assert.equal(r.status, 401);
  const other = await request(app).post('/api/v1/hosts/0123456789abcdef01234567/metrics').set(S.agent).send({});
  assert.equal(other.status, 403);
});

t('heartbeat + metrics ingestion', async () => {
  const hb = await request(app).post('/api/v1/agent/heartbeat').set(S.agent).send({ agentVersion: '1.0.0', outbox: 0 });
  assert.equal(hb.status, 200);
  assert.deepEqual(hb.body.data.commands, []);
  const metric = { cpu: { usage: 12.5, logical: 4 }, memory: { total: 8e9, used: 2e9, percent: 25, swapPercent: 0 },
    disk: [{ mount: '/', total: 1e11, used: 5e10, percent: 50 }], load: { load1: 0.5, load5: 0.4, load15: 0.3 },
    network: { rxBytes: 1, txBytes: 2, rxRate: null, txRate: null }, processCount: 150, uptimeSeconds: 1000 };
  const m = await request(app).post(`/api/v1/hosts/${S.hostId}/metrics`).set(S.agent).send(metric);
  assert.equal(m.status, 201);
  const bad = await request(app).post(`/api/v1/hosts/${S.hostId}/metrics`).set(S.agent).send({ ...metric, cpu: { usage: 500 } });
  assert.equal(bad.status, 400);
  const g = await request(app).get(`/api/v1/hosts/${S.hostId}/metrics?range=1h`).set(auth(S.viewer));
  assert.equal(g.body.data.length, 1);
  const host = await request(app).get(`/api/v1/hosts/${S.hostId}`).set(auth(S.viewer));
  assert.equal(host.body.data.status, 'ONLINE');
  assert.equal(host.body.data.scores.health, 100);
});

t('manual scan: RBAC, queue, dispatch on heartbeat', async () => {
  const v = await request(app).post(`/api/v1/hosts/${S.hostId}/scan`).set(auth(S.viewer)).send({ type: 'FULL' });
  assert.equal(v.status, 403);
  const r = await request(app).post(`/api/v1/hosts/${S.hostId}/scan`).set(auth(S.admin)).send({ type: 'QUICK' });
  assert.equal(r.status, 202);
  S.scanId = r.body.data.scanId;
  const hb = await request(app).post('/api/v1/agent/heartbeat').set(S.agent).send({});
  assert.deepEqual(hb.body.data.commands, [{ type: 'scan', scanId: S.scanId, scanType: 'QUICK' }]);
  const hb2 = await request(app).post('/api/v1/agent/heartbeat').set(S.agent).send({});
  assert.equal(hb2.body.data.commands.length, 0, 'dispatched only once');
});

t('scan results create findings, scores and deduplicated alerts', async () => {
  const p = await request(app).post('/api/v1/agent/events').set(S.agent).send({ type: 'scan_progress', data: { scanId: S.scanId, type: 'QUICK', check: 'ssh', checksCompleted: 1, checksTotal: 2 } });
  assert.equal(p.status, 200);
  const r = await request(app).post('/api/v1/agent/scan-results').set(S.agent).send(scanPayload(S.scanId, [finding('f1', 'HIGH'), finding('f2', 'LOW')]));
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.data.newFindings, 2);
  assert.ok(r.body.data.riskScore >= 41);
  const f = await request(app).get(`/api/v1/hosts/${S.hostId}/findings`).set(auth(S.viewer));
  assert.equal(f.body.meta.total, 2);
  // Same finding again (scheduled scan): no duplicates, no new alert.
  await request(app).post('/api/v1/agent/scan-results').set(S.agent).send(scanPayload('sched-1', [finding('f1', 'HIGH'), finding('f2', 'LOW')]));
  const again = await request(app).get(`/api/v1/hosts/${S.hostId}/findings`).set(auth(S.viewer));
  assert.equal(again.body.meta.total, 2);
  assert.equal(await Alert.countDocuments({ kind: 'finding' }), 1, 'only the HIGH finding alerts, once');
  const scan = await request(app).get(`/api/v1/hosts/${S.hostId}/scans/${S.scanId}`).set(auth(S.viewer));
  assert.equal(scan.body.data.status, 'COMPLETED');
  assert.equal(scan.body.data.findings.length, 2);
});

t('fixed finding auto-resolves; NOT_SUPPORTED never resolves anything', async () => {
  await request(app).post('/api/v1/agent/scan-results').set(S.agent).send(scanPayload('sched-2', [finding('f1', 'HIGH')]));
  const open = await request(app).get(`/api/v1/hosts/${S.hostId}/findings`).set(auth(S.viewer));
  assert.deepEqual(open.body.data.map((x) => x.fingerprint), ['f1']);
  const all = await request(app).get(`/api/v1/findings?status=RESOLVED`).set(auth(S.viewer));
  assert.equal(all.body.data[0].fingerprint, 'f2');
});

t('security score endpoint exposes areas and NOT_SUPPORTED benchmark', async () => {
  const r = await request(app).get(`/api/v1/hosts/${S.hostId}/security-score`).set(auth(S.viewer));
  assert.equal(r.status, 200);
  const area = Object.fromEntries(r.body.data.areas.map((a) => [a.area, a]));
  assert.equal(area.ssh.status, 'INSECURE');
  assert.equal(area.benchmark.status, 'NOT_SUPPORTED');
  assert.ok(r.body.data.history.length >= 1);
});

t('finding status change requires ADMIN and is audited', async () => {
  const f = (await request(app).get(`/api/v1/hosts/${S.hostId}/findings`).set(auth(S.admin))).body.data[0];
  assert.equal((await request(app).patch(`/api/v1/findings/${f._id}`).set(auth(S.viewer)).send({ status: 'ACKNOWLEDGED' })).status, 403);
  const r = await request(app).patch(`/api/v1/findings/${f._id}`).set(auth(S.admin)).send({ status: 'ACKNOWLEDGED' });
  assert.equal(r.body.data.status, 'ACKNOWLEDGED');
  const detail = await request(app).get(`/api/v1/findings/${f._id}`).set(auth(S.viewer));
  assert.equal(detail.body.data.remediation.requiresAdminApproval, true);
  const logs = await request(app).get('/api/v1/audit-logs').set(auth(S.admin));
  const actions = logs.body.data.map((l) => l.action);
  for (const a of ['user.register', 'user.login', 'agent.register', 'scan.request', 'finding.status']) assert.ok(actions.includes(a), a);
  assert.ok(!JSON.stringify(logs.body.data).includes('correct-horse'), 'no passwords in audit log');
});

t('alerts list + acknowledge', async () => {
  const a = await request(app).get('/api/v1/alerts?acknowledged=false').set(auth(S.viewer));
  assert.ok(a.body.data.length >= 1);
  assert.equal((await request(app).patch(`/api/v1/alerts/${a.body.data[0]._id}/acknowledge`).set(auth(S.viewer))).status, 403);
  const ack = await request(app).patch(`/api/v1/alerts/${a.body.data[0]._id}/acknowledge`).set(auth(S.admin));
  assert.equal(ack.body.data.acknowledged, true);
});

t('AI analyze falls back to deterministic engine without a provider', async () => {
  await SystemMetric.deleteMany({});
  const r = await request(app).post(`/api/v1/hosts/${S.hostId}/ai/analyze`).set(auth(S.admin));
  assert.equal(r.status, 201);
  assert.equal(r.body.data.engine, 'deterministic');
  assert.match(r.body.data.fallbackReason, /not configured/);
  assert.equal(r.body.data.ml.status, 'LEARNING');
  assert.ok(r.body.data.priorities[0].recommendation.startsWith('REQUIRES ADMIN APPROVAL'));
  const list = await request(app).get(`/api/v1/hosts/${S.hostId}/ai/insights`).set(auth(S.viewer));
  assert.equal(list.body.data.length, 1);
  assert.equal(list.body.meta.aiConfigured, false);
});

t('dashboard summary and consistent error envelope', async () => {
  const d = await request(app).get('/api/v1/dashboard/summary').set(auth(S.viewer));
  assert.equal(d.body.data.hosts.total, 1);
  assert.equal(d.body.data.hosts.online, 1);
  const nf = await request(app).get('/api/v1/nope').set(auth(S.viewer));
  assert.deepEqual(Object.keys(nf.body), ['success', 'error']);
  const badId = await request(app).get('/api/v1/hosts/xyz').set(auth(S.viewer));
  assert.equal(badId.status, 400);
});

t('logout invalidates the token', async () => {
  const r = await request(app).post('/api/v1/auth/logout').set(auth(S.viewer));
  assert.equal(r.status, 200);
  assert.equal((await request(app).get('/api/v1/auth/me').set(auth(S.viewer))).status, 401);
});
