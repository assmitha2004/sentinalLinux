// Layer 2 AI explanation engine (spec §28, §89-91). The LLM only ever sees normalized findings
// (no raw logs, no file contents), must return JSON that passes schema validation, and is never
// allowed to drive actions. Any failure falls back to the deterministic engine.
import { z } from 'zod';
import { config } from '../config/index.js';
import { SEVERITY_RANK } from '../models/constants.js';
import { logger } from '../utils/logger.js';
import { recommendationFor } from './recommendations.js';

const log = logger('ai');

export const SYSTEM_PROMPT = `You are SentinelAI Security Analyst.
Analyze ONLY the evidence supplied by SentinelAI in the user message. Do not invent facts.
Do not claim malware, compromise, or exploitation without evidence; when evidence is weak, say so in "uncertainties".
Separate observed facts ("observations") from inference ("reason") and recommendations.
Prioritize by risk (severity x confidence x exposure). At most 5 priorities.
You cannot and must not execute commands. Provide only safe, READ-ONLY verification commands.
When remediation can alter system security (SSH, firewall, users, services, file permissions), begin the recommendation with "REQUIRES ADMIN APPROVAL:".
Respond with a single JSON object and nothing else, matching exactly:
{"summary": string, "riskLevel": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "topPriorities": [{"title": string, "reason": string, "severity": "INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "recommendation": string, "verification": string}], "observations": [string], "uncertainties": [string]}`;

export const aiResponseSchema = z.object({
  summary: z.string().min(1).max(4000),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  topPriorities: z.array(z.object({
    title: z.string().max(300), reason: z.string().max(2000),
    severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    recommendation: z.string().max(3000), verification: z.string().max(1000),
  })).max(10),
  observations: z.array(z.string().max(1000)).max(30),
  uncertainties: z.array(z.string().max(1000)).max(30),
});

const truncate = (v, n = 400) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s && s.length > n ? `${s.slice(0, n)}…` : s; };

export function buildPayload(host, scores, findings, ml) {
  const top = [...findings].filter((f) => f.severity !== 'INFO')
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.confidence || 0) - (a.confidence || 0)).slice(0, 40);
  return {
    host: { hostname: host.hostname, os: `${host.os?.distribution || ''} ${host.os?.version || ''}`.trim(), kernel: host.kernel },
    riskScore: scores.risk.score, riskLevel: scores.risk.level, healthScore: scores.health.score,
    riskFactors: scores.risk.factors,
    findings: top.map((f) => ({ type: f.type, category: f.category, severity: f.severity, confidence: f.confidence,
      title: f.title, evidence: truncate(f.evidence), status: f.status })),
    anomalyDetection: ml ? { status: ml.status, anomalies: ml.anomalies } : undefined,
  };
}

/** Deterministic fallback (always available). */
export function deterministicInsight(scores, findings, ml) {
  // Security findings drive the security summary; health issues are reported as observations.
  const ranked = [...findings].filter((f) => f.severity !== 'INFO' && f.category !== 'health')
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.confidence || 0) - (a.confidence || 0));
  const healthIssues = findings.filter((f) => f.category === 'health' && f.severity !== 'INFO');
  const priorities = ranked.slice(0, 5).map((f) => {
    const rule = recommendationFor(f);
    return { title: f.title, reason: f.whyItMatters || f.description, severity: f.severity,
      recommendation: `${rule.requiresAdminApproval ? 'REQUIRES ADMIN APPROVAL: ' : ''}${rule.steps.join(' ')}`,
      verification: f.verification?.command || rule.verification.command || '', findingId: f._id };
  });
  const level = scores.risk.level.replace('_', ' ');
  const summary = ranked.length
    ? `This host currently has a ${level} security risk score (${scores.risk.score}/100). ${ranked.length} open finding(s); the highest-priority issue is "${ranked[0].title}".`
    : `No open security findings. Risk score ${scores.risk.score}/100 (${level}). This means no issues were detected by the checks that ran — not that the system is guaranteed secure.`;
  const uncertainties = [];
  const weak = ranked.filter((f) => (f.confidence ?? 1) < 0.6);
  if (weak.length) uncertainties.push(`${weak.length} finding(s) are weak indicators (confidence < 0.6) and need manual confirmation.`);
  if (ml?.status === 'LEARNING') uncertainties.push(`Anomaly detection is still learning (${ml.samples}/${ml.required} samples).`);
  return {
    summary, riskLevel: scores.risk.score > 80 ? 'CRITICAL' : scores.risk.score > 60 ? 'HIGH' : scores.risk.score > 40 ? 'MEDIUM' : 'LOW',
    topPriorities: priorities,
    observations: [
      ...scores.risk.factors.slice(0, 5).map((f) => `Category "${f.category}" contributes ${f.weight} risk weight.`),
      ...healthIssues.slice(0, 3).map((f) => `Health: ${f.title}.`),
      ...(ml?.anomalies || []).map((a) => `Unusual ${a.feature}: ${a.value} vs baseline median ${a.baselineMedian} (z=${a.zScore}).`),
    ],
    uncertainties,
  };
}

export function extractJson(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('no JSON object in model output');
  return JSON.parse(text.slice(start, end + 1));
}

async function callAnthropic(payload) {
  const res = await fetch(`${config.AI_BASE_URL || 'https://api.anthropic.com'}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': config.AI_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: config.AI_MODEL, max_tokens: 2000, system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: `SentinelAI evidence:\n${JSON.stringify(payload)}` }] }),
    signal: AbortSignal.timeout(config.AI_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`anthropic HTTP ${res.status}`);
  const data = await res.json();
  return data.content?.filter((c) => c.type === 'text').map((c) => c.text).join('') || '';
}

// OpenAI-compatible chat API: works with hosted providers and with local servers (Ollama, vLLM,
// llama.cpp) via AI_BASE_URL - useful for air-gapped BOSS deployments.
async function callOpenAI(payload) {
  const base = (config.AI_BASE_URL || 'https://api.openai.com').replace(/\/$/, '');
  const headers = { 'content-type': 'application/json' };
  if (config.AI_API_KEY) headers.authorization = `Bearer ${config.AI_API_KEY}`;
  const res = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST', headers,
    body: JSON.stringify({ model: config.AI_MODEL, temperature: 0.1,
      messages: [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: `SentinelAI evidence:\n${JSON.stringify(payload)}` }] }),
    signal: AbortSignal.timeout(config.AI_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`openai-compatible HTTP ${res.status}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content || '';
}

export async function analyze(host, scores, findings, ml, { caller } = {}) {
  const fallback = deterministicInsight(scores, findings, ml);
  if (!config.aiEnabled) return { ...fallback, engine: 'deterministic', fallbackReason: 'AI provider not configured' };
  try {
    const call = caller || (config.AI_PROVIDER === 'anthropic' ? callAnthropic : callOpenAI);
    const text = await call(buildPayload(host, scores, findings, ml));
    const parsed = aiResponseSchema.parse(extractJson(text));
    // Evidence wins over the model (spec §103): never let the LLM downgrade a deterministic CRITICAL.
    if (fallback.riskLevel === 'CRITICAL' && parsed.riskLevel !== 'CRITICAL') {
      parsed.uncertainties.push('Model risk level was raised to CRITICAL to match deterministic evidence.');
      parsed.riskLevel = 'CRITICAL';
    }
    return { ...parsed, engine: 'llm', model: config.AI_MODEL, deterministic: fallback };
  } catch (e) {
    log.warn(`AI unavailable, using deterministic engine: ${e.message}`);
    return { ...fallback, engine: 'deterministic', fallbackReason: `AI unavailable (${e.message.slice(0, 120)}). Showing deterministic security recommendations.` };
  }
}
