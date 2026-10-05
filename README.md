# SentinelAI

**Intelligent system health and security monitoring for BOSS 10 Linux.**

SentinelAI is a Linux agent plus a MERN web dashboard. The agent runs on each BOSS 10 machine, discovers what the host can actually do (commands, init system, package manager, firewall and security tooling), collects system health and runs read-only security checks. The backend stores results, scores risk and health, raises alerts and explains findings — with an optional LLM on top of a deterministic engine that always works offline.

It answers one question: *is this BOSS 10 machine healthy and secure right now, what is wrong, how severe is it, why does it matter, and what should I do next?*

Design rules the code follows throughout:

- **Detect, never assume.** Nothing about BOSS 10 is hard-coded. A missing tool makes a check report `NOT_SUPPORTED` — never `FAIL`, never a fabricated result.
- **Read-only.** The agent never kills processes, deletes files, edits SSH/firewall/user configuration or exploits anything. Remediation is shown as commands marked *read-only* or *modifying*, and changes that alter security are flagged *requires administrator approval*.
- **Evidence first.** Every finding carries evidence, a confidence (0–1, separate from severity), why it matters, a recommendation and a verification command.
- **Honest wording.** A clean rootkit check says "No strong rootkit indicators detected", never "clean". An external IP alone is never "malicious".

---

## Contents

1. [Architecture](#1-architecture)
2. [Requirements](#2-requirements)
3. [BOSS 10 compatibility](#3-boss-10-compatibility)
4. [Quick start (development)](#4-quick-start-development)
5. [MongoDB setup](#5-mongodb-setup)
6. [Running the backend](#6-running-the-backend)
7. [Running the frontend](#7-running-the-frontend)
8. [Installing and enrolling the agent](#8-installing-and-enrolling-the-agent)
9. [Configuration reference](#9-configuration-reference)
10. [Using the dashboard](#10-using-the-dashboard)
11. [Security checks](#11-security-checks)
12. [Scoring, alerts and anomaly detection](#12-scoring-alerts-and-anomaly-detection)
13. [AI setup](#13-ai-setup)
14. [API reference](#14-api-reference)
15. [Testing](#15-testing)
16. [BOSS 10 verification checklist](#16-boss-10-verification-checklist)
17. [Production deployment](#17-production-deployment)
18. [Troubleshooting](#18-troubleshooting)
19. [Uninstallation](#19-uninstallation)
20. [Security model and known limits](#20-security-model-and-known-limits)

---

## 1. Architecture

```text
 BOSS 10 host                                   SentinelAI server
┌────────────────────────────────┐            ┌────────────────────────────────────┐
│ sentinel-agent (Python)        │  HTTPS     │ Express API  /api/v1               │
│  bossplatform/  capability     │──────────▶ │  auth · RBAC · validation (zod)    │
│                 discovery      │  REST      │  agent enrollment + credentials    │
│  collectors/    cpu mem disk   │            │  ingestion: metrics, snapshots,    │
│                 net proc svc   │◀────────── │             scan results           │
│  security/      14 checks      │  commands  │  risk engine · alerts · retention  │
│  scanner.py     scan types     │  on        │  AI service (LLM optional)         │
│  scheduler.py   fast/slow jobs │  heartbeat │  anomaly detection (robust z)      │
│  client.py      bounded outbox │            │  Socket.IO ───────────┐            │
└────────────────────────────────┘            └────────┬──────────────┼────────────┘
                                                       │              │ live events
                                                  MongoDB      React dashboard (Vite)
```

| Part | Path | Stack |
|---|---|---|
| Agent | `agent/` | Python 3.9+, psutil, requests, PyYAML |
| Backend | `server/` | Node.js 18+, Express 4, Mongoose 8, Socket.IO, zod, JWT, bcrypt, helmet |
| Dashboard | `client/` | React 18, Vite 5, React Router, Axios, Recharts, socket.io-client |
| Deployment | `deploy/`, `agent/deploy/` | systemd units, nginx TLS proxy |
| Design notes | `docs/ARCHITECTURE.md` | privileges, optional tools, assumptions, risks |

Data flow:

1. **Enrollment.** An admin creates a one-time enrollment token in *Settings*. The agent exchanges it at `POST /api/v1/hosts/register` for a per-host `agentId` + secret. The server stores only the SHA-256 of the secret; the agent stores it in `/var/lib/sentinelai/credentials.json` (mode 0600). Re-enrolling the same machine (same `/etc/machine-id`) rotates the credential instead of creating a duplicate host.
2. **Fast loop.** Every 5 s the agent posts a metric sample; every 10 s a process/network/service snapshot; every 30 s a heartbeat.
3. **Scans.** A STANDARD scan (without slow filesystem walks) runs every 5 minutes, a FULL scan daily, and any type on demand. Dashboard scan requests are queued on the server and delivered in the next heartbeat response — the server never connects to agents.
4. **Ingestion.** Findings are upserted by a stable fingerprint (type + resource), so repeat scans update `lastSeen` rather than duplicating. A finding that a *conclusive* re-run of the same check no longer reports is auto-resolved; checks that were `NOT_SUPPORTED` or `ERROR` resolve nothing.
5. **Scoring and alerts** are recomputed, and Socket.IO pushes `metric:update`, `finding:new`, `security:alert`, `scan:*` and `host:*` events to the dashboard.
6. **Offline tolerance.** If the server is unreachable, metrics and scan results go to a bounded SQLite outbox (default 5 000 items, oldest dropped first) and are replayed after the next successful heartbeat.

---

## 2. Requirements

| Component | Requirement |
|---|---|
| Agent host | BOSS 10 (other Debian-family hosts run in compatibility mode with a warning), Python ≥ 3.9 with `venv` (`python3-venv`), root for installation |
| Server | Node.js ≥ 18 (LTS recommended), npm, MongoDB ≥ 6 |
| Dashboard build | Node.js ≥ 18; any modern browser to use it |
| Optional on hosts | `openssh-server`, `nftables`/`iptables`, `auditd`, `rkhunter`, `chkrootkit`, `libopenscap8` + SCAP content, `debsums` |

The agent's core monitoring has **no Internet dependency**. Only an LLM provider (if you configure one) needs network access from the server.

---

## 3. BOSS 10 compatibility

At startup the agent builds a capability registry and reports it to the dashboard (*Host → Overview → Detected capabilities*). See it yourself without a server:

```bash
cd agent
python3 main.py --config /nonexistent detect
```

```json
{
  "os": { "distribution": "BOSS", "version": "10", "codename": "...", "kernel": "...", "architecture": "x86_64", "initSystem": "systemd", "isBoss10": true },
  "capabilities": { "systemd": true, "ss": true, "ip": true, "journalctl": true, "auditd": false, "openscap": false, "rkhunter": false, "nftables": true, "packageManager": "dpkg", "isRoot": false, "...": "..." },
  "commands": { "ip": true, "ss": true, "systemctl": true, "dpkg-query": true, "...": "..." }
}
```

How BOSS-specific behaviour is isolated (`agent/bossplatform/`, named so it does not shadow Python's `platform` module):

| Module | Decides at runtime |
|---|---|
| `os_detection.py` | Distribution from `/etc/os-release` (`ID`/`ID_LIKE`/`NAME` containing "boss"), version, codename, Debian base version, init system from `/run/systemd/system` or PID 1 |
| `capabilities.py` | Which of ~45 commands exist (also searches `/usr/sbin`, `/sbin` for non-root PATHs), SELinux/AppArmor presence, SCAP content |
| `package_manager.py` | `dpkg-query` or `rpm`; file ownership with merged-`/usr` path fallback (`/usr/bin/x` ↔ `/bin/x`) |
| `service_manager.py` | systemd units if systemd is PID 1, otherwise process-name matching |
| `network_tools.py` | psutil sockets (works without `ss`/`netstat`) |
| `security_tools.py` | nftables, iptables, firewalld, ufw — whichever exist; AppArmor/SELinux state |
| `benchmark_tools.py` | SCAP datastreams in known content dirs; prefers BOSS content, then Debian of the same major version |

Things that **must be verified on a real BOSS 10 install** (they were designed for but not tested on BOSS 10 in this build — see §16):
`/etc/os-release` field values, the default firewall stack, whether `auditd`/`rsyslog` are installed by default, the auth log location (journald vs `/var/log/auth.log`), whether SCAP content for BOSS/Debian 12 is packaged, and the APT origin labels used to tell security updates apart.

---

## 4. Quick start (development)

```bash
git clone <your-repo-url> sentinelai && cd sentinelai

# 1. MongoDB (see §5), then the API
cd server
cp .env.example .env
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -base64 48)|" .env
npm install
npm run dev                       # http://localhost:5000  (GET /health)

# 2. Dashboard (new terminal)
cd client
cp .env.example .env
npm install
npm run dev                       # http://localhost:5173

# 3. Open http://localhost:5173/register — the first account becomes ADMIN.
#    Settings → "Enroll a host" → Create token.

# 4. Agent on the same machine, without installing (new terminal)
cd agent
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cat > /tmp/agent.yaml <<'EOF'
server: {url: "http://localhost:5000"}
agent:  {state_dir: /tmp/sentinel-state}
EOF
python3 main.py --config /tmp/agent.yaml enroll --token sat_XXXXXXXX
sudo -E .venv/bin/python main.py --config /tmp/agent.yaml run     # sudo = full visibility; optional
```

Frontend-only work with no backend: set `VITE_DEMO_MODE=true` in `client/.env`. Every screen then shows a striped "Demo data" banner; demo data is never mixed with real hosts.

---

## 5. MongoDB setup

Any MongoDB ≥ 6 works (local, replica set or Atlas).

```bash
# Debian-family (BOSS 10 base is Debian 12 "bookworm") — official MongoDB repo:
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-7.gpg
echo "deb [signed-by=/usr/share/keyrings/mongodb-7.gpg] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" \
  | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update && sudo apt install -y mongodb-org
sudo systemctl enable --now mongod

# or with Docker:
docker run -d --name sentinel-mongo -p 127.0.0.1:27017:27017 -v sentinel-mongo:/data/db mongo:7
```

Set `MONGODB_URI=mongodb://127.0.0.1:27017/sentinelai` in `server/.env`. Indexes (on `hostId`, `timestamp`, `severity`, `status`, `createdAt`, `agentId`, …) are created at startup. In production enable MongoDB authentication and use a URI with credentials.

---

## 6. Running the backend

```bash
cd server
npm install
npm run dev          # auto-reload
npm start            # production
npm test             # unit + API integration tests (needs MongoDB; see §15)

# Create or reset an admin from the CLI (password via env, not argv):
ADMIN_PASSWORD='a-long-passphrase-1' npm run create-admin -- admin@example.org "Admin Name"
```

Configuration is validated at startup; the server refuses to start with a missing `MONGODB_URI` or a `JWT_SECRET` shorter than 32 characters. Full list in §9.

---

## 7. Running the frontend

```bash
cd client
npm install
npm run dev          # Vite dev server on :5173
npm run build        # static files in client/dist
npm test             # component tests (vitest + jsdom)
```

`VITE_API_URL` and `VITE_SOCKET_URL` are baked in at build time. Fonts (Hind, JetBrains Mono) are bundled from npm, so the dashboard needs no external CDN — it works on air-gapped networks.

---

## 8. Installing and enrolling the agent

On each BOSS 10 host, copy the `agent/` directory (or the repository) and run:

```bash
cd agent
sudo SENTINEL_SERVER_URL=https://sentinel.example.org \
     SENTINEL_AGENT_TOKEN=sat_XXXXXXXXXXXXXXXX \
     ./install.sh
```

The dashboard shows this exact command after you create a token. The installer:

1. Prints the detected OS, version, kernel, architecture and init system. If the host is not BOSS 10 it asks `Continue anyway? [y/N]` (or warns and continues with `-y`).
2. Verifies Python ≥ 3.9 and `venv` (tells you to `apt install python3-venv` if missing).
3. Copies the agent to `/opt/sentinelai/agent` and creates a virtualenv there.
4. Installs dependencies from PyPI, or offline with `--wheelhouse DIR`.
5. Writes `/etc/sentinelai/agent.yaml` (kept if it exists) and `/etc/sentinelai/agent.env` (mode 0640, server URL only — the token is not persisted).
6. Creates the `sentinelai` system user and `/var/lib/sentinelai` (mode 0700).
7. Prints the capability report and enrolls the agent (token passed by environment, not argv).
8. If systemd is PID 1, installs and starts `sentinel-agent.service`; otherwise prints the manual start command.
9. Sends a test heartbeat and prints troubleshooting steps if it fails.

Options:

| Option | Effect |
|---|---|
| `--mode restricted` (default) | Runs as `sentinelai` with only `CAP_DAC_READ_SEARCH` (read any file), `CAP_SYS_PTRACE` (see other users' processes/sockets) and `CAP_NET_ADMIN` (read firewall rules). |
| `--mode root` | Runs as root. Needed only to let `rkhunter`/`chkrootkit` execute. |
| `--wheelhouse DIR` | Offline install. Prepare on a connected machine: `pip download -d wheels -r agent/requirements.txt` |
| `--no-service` | Install files and enroll only. |
| `-y` | Non-interactive. |

Useful agent commands (also work from a checkout, no install needed):

```bash
A="/opt/sentinelai/agent/venv/bin/python /opt/sentinelai/agent/main.py --config /etc/sentinelai/agent.yaml"
$A detect                              # capability discovery
$A scan --type QUICK --summary         # run a scan locally and print results (no server)
$A scan --type FULL > full-scan.json   # full JSON
$A ping                                # one heartbeat
systemctl status sentinel-agent
journalctl -u sentinel-agent -f        # structured JSON logs, secrets redacted
```

---

## 9. Configuration reference

### Backend — `server/.env`

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 5000 | API port |
| `MONGODB_URI` | — | required |
| `JWT_SECRET` | — | required, ≥ 32 chars (`openssl rand -base64 48`) |
| `JWT_EXPIRES_IN` | 8h | session length |
| `AGENT_ENROLLMENT_SECRET` | empty | optional shared, multi-use bootstrap token; prefer one-time tokens |
| `CORS_ORIGIN` | http://localhost:5173 | comma-separated dashboard origins |
| `ALLOW_REGISTRATION` | true | after the first (admin) account, self-registered users are VIEWERs; set `false` to disable |
| `TRUST_PROXY` | false | `true` behind nginx so rate limits see client IPs |
| `AI_PROVIDER` | empty | `anthropic`, `openai` (any OpenAI-compatible API) or empty |
| `AI_API_KEY`, `AI_MODEL`, `AI_BASE_URL`, `AI_TIMEOUT_MS` | | see §13 |
| `HEARTBEAT_INTERVAL_SEC` | 30 | must match the agent |
| `DEGRADED_MULTIPLIER` / `OFFLINE_MULTIPLIER` | 2 / 4 | host is DEGRADED after 2× and OFFLINE after 4× the heartbeat interval |
| `ALERT_COOLDOWN_MIN` | 30 | repeats of the same unacknowledged alert are counted, not re-raised |
| `RETENTION_*_DAYS` | metrics 7, findings 90, alerts 90, audit 180, scans 90 | applied hourly; open findings and unacknowledged alerts are never auto-deleted |
| `ML_MIN_SAMPLES` / `ML_Z_THRESHOLD` | 500 / 4 | anomaly baseline size and sensitivity |

Risk weights live in `server/src/config/index.js` (`config.risk`).

### Dashboard — `client/.env`

| Variable | Example |
|---|---|
| `VITE_API_URL` | `http://localhost:5000/api/v1` |
| `VITE_SOCKET_URL` | `http://localhost:5000` |
| `VITE_DEMO_MODE` | `false` |

### Agent — `/etc/sentinelai/agent.yaml` + `/etc/sentinelai/agent.env`

The annotated default is `agent/deploy/agent.yaml`. Key settings: server URL/TLS (`verify_tls`, `ca_bundle` for a private CA), intervals, disk/CPU/memory thresholds (disk WARN 80 / HIGH 90 / CRITICAL 95 by default), scan paths and exclusions, expected listening ports, suspicious ports, optional SCAP datastream/profile overrides.

Environment overrides: `SENTINEL_SERVER_URL`, `SENTINEL_AGENT_TOKEN` (enrollment only), `SENTINEL_VERIFY_TLS`, `SENTINEL_CA_BUNDLE`, `SENTINEL_STATE_DIR`, `SENTINEL_LOG_LEVEL`, `SENTINEL_CONFIG`.

Optional threat intelligence: put one IP per line in `/etc/sentinelai/ioc-blocklist.txt`. Only a match against this operator-supplied list can mark a connection *Confirmed malicious*.

---

## 10. Using the dashboard

| Page | What it shows |
|---|---|
| **Overview** | Security risk gauge on the 0–100 band scale, findings by severity, health with CPU/memory/disk meters, active alerts, hosts online, CPU/memory and network charts (live), what needs attention, and a host table when more than one host reports |
| **Hosts** | Every enrolled host: OS, status (online/degraded/offline), health, risk, last seen, open alerts |
| **Host → Overview** | Risk, health, uptime/load, *Run a scan*, detected capabilities |
| **Host → System** | OS details, filesystems, CPU/memory/load/process/disk history (15 m – 7 d) |
| **Host → Security** | Risk gauge, risk/health history, posture by area (SSH, firewall, file permissions, network exposure, processes, accounts, rootkit indicators, kernel hardening, audit and logging, CIS benchmark, pending updates). Select an area to list its findings |
| **Host → Network** | Interfaces, listening ports with exposure, connections to other hosts, suspicious-connection findings |
| **Host → Processes / Services** | Top processes (filterable) and systemd units (running / failed / all) |
| **Host → Findings / Findings** | Filter by severity, status, category, host, date and text. A finding opens a panel with what happened, why it matters, evidence, affected resource, what to do, read-only verification command, possible fix (marked *modifying*), and triage buttons (admins) |
| **Host → Scans** | Start a scan, live progress, history; expand a scan to see each check's result, duration and reason (e.g. *not supported: oscap not installed*) |
| **Host → AI analysis** | Summary, top priorities (why / what to do / verify), observations, uncertainties, anomaly-detection status |
| **Alerts** | Open or acknowledged alerts with repeat counts |
| **Settings** | Enrollment tokens (admin), server configuration, people and roles (admin), audit trail (admin) |

Roles: **ADMIN** manages hosts, users, tokens and finding status; **ANALYST** runs scans and AI analyses and acknowledges alerts; **VIEWER** is read-only.

---

## 11. Security checks

Scan types:

| Type | Contents |
|---|---|
| QUICK | system, CPU, memory, disk, network, firewall, kernel parameters, AppArmor/SELinux, connection heuristics |
| STANDARD | QUICK + processes, services, SSH, accounts/authentication, world-writable files, temp executables, audit/logging |
| FULL | STANDARD + packages, SUID/SGID, binary inventory, rootkit indicators, pending updates, SCAP benchmark |
| NETWORK / PROCESS / FILESYSTEM | focused subsets |
| BENCHMARK | OpenSCAP only |

| Check | What it looks at | Typical findings | Needs |
|---|---|---|---|
| `ssh` | `sshd -T` (or parsed `sshd_config` + `Include`s), listening sockets, `authorized_keys` *counts* | root login, password auth, empty passwords, MaxAuthTries, X11 forwarding, exposure on all interfaces (INFO, "review whether intentional") | openssh-server; root/CAP_DAC_READ_SEARCH for `sshd -T` |
| `authentication` | `/etc/passwd`, `/etc/shadow` (only to detect an *empty* field — hashes are never read out), `login.defs`, PAM | extra UID 0, empty passwords, system accounts with shells, world-writable homes, no expiry, no pwquality | root/CAP for shadow |
| `suid` | safe walk of configured roots (never `/proc /sys /dev /run`, no symlinks, no other mounts), package ownership, SHA-256 for unusual files | unexpected SUID/SGID — standard package-owned ones are inventoried, not flagged | dpkg |
| `permissions` | world-writable executables/configs/unit files/dirs (sticky dirs excluded, exclusions configurable), sensitive file modes | world-writable executable/service/config, weak `/etc/shadow` permissions | — |
| `temp_executables` | ELF binaries and shebang scripts in `/tmp`, `/var/tmp`, `/dev/shm`; running or deleted temp executables | executable in temp dir (severity by running / ELF / SUID) | — |
| `binaries` | inventory of `/usr/bin` etc.; hashes optional | non-root-owned or world-writable system binaries, world-writable bin dirs | — |
| `firewall` | nftables, iptables, firewalld, ufw — whichever exist | no active rules | CAP_NET_ADMIN/root to read rules |
| `audit_logging` | auditd state and rules, journald, rsyslog; last hour of auth events (counts only) | auditd off, no rules, no logging, SSH brute force, sudo failures | `adm`/`systemd-journal` group |
| `kernel_params` | 12 sysctl values read from `/proc/sys` | ASLR off, symlink protection off, redirects, etc. | — |
| `mac` | AppArmor/SELinux | no MAC active | — |
| `c2_heuristics` | established connections scored on evidence (temp/deleted executable, backdoor ports, shell holding a socket, repeats, hidden owner) | Observed / Suspicious / High risk / Confirmed malicious (IOC list only); services exposed on all interfaces | root/CAP_SYS_PTRACE for full PID visibility |
| `rootkit` | rkhunter/chkrootkit if installed (root only), `/proc` vs process table, `/etc/ld.so.preload`, known artefacts, suspicious module names, taint | verdict: *strong indicators* / *weak indicators only* / *no strong rootkit indicators detected* | optional scanners |
| `benchmark` | `oscap xccdf eval` (no `--remediate`) on detected datastream/profile | compliance %, failed rules | `oscap` + SCAP content, else NOT_SUPPORTED |
| `vulnerabilities` | `apt list --upgradable` from the **local** cache, reboot-required | pending security updates, reboot required | apt |

To enable the optional checks on a host: `sudo apt install auditd rkhunter chkrootkit` (then `--mode root` for the scanners) and, for benchmarks, install `libopenscap8` and an SCAP Security Guide datastream for Debian 12 into one of `/usr/share/xml/scap`, `/usr/share/scap-security-guide`, `/opt/scap` or set `benchmark.datastream` in `agent.yaml`.

---

## 12. Scoring, alerts and anomaly detection

**Security risk score (0–100, higher = more exposure).** Each open finding contributes `severity weight × confidence × category multiplier` (CRITICAL 25, HIGH 10, MEDIUM 4, LOW 1, INFO 0; rootkit ×1.5; network/process/users ×1.2; health ×0). The total saturates: `100 × (1 − e^(−total/40))`. A strong (confidence ≥ 0.7) HIGH finding sets a floor of 41, a strong CRITICAL a floor of 81, and without any CRITICAL finding the score is capped at 80. Bands: 0–20 Excellent, 21–40 Good, 41–60 Moderate, 61–80 High risk, 81–100 Critical.

**Health score (0–100, higher = better)** comes from the latest metrics: CPU above 70 %, memory above 75 %, fullest disk ≥ 80/90/95 %, load per CPU, swap, failed services. It is shown separately; *overall posture* is the average of (100 − risk) and health.

**Alerts** are raised for new HIGH/CRITICAL findings, suspicious processes/connections, CPU or memory ≥ 95 %, statistical anomalies, hosts going offline and failed scans. The same unacknowledged alert inside the cooldown increments a counter instead of creating a new alert.

**Anomaly detection** compares the median of the last 12 samples of CPU, memory, process count and network rates with the host's own 7-day baseline using a robust z-score (median/MAD). Until `ML_MIN_SAMPLES` samples exist it reports *Learning / insufficient historical data* and predicts nothing. Anomalies are labelled statistical signals, not proof of compromise. The interface (`detect(samples)`) is where an Isolation Forest or One-Class SVM can be swapped in.

---

## 13. AI setup

Without configuration, `POST /hosts/:id/ai/analyze` uses the **deterministic engine**: findings ranked by severity and confidence, recommendations from rule tables, honest uncertainties. The page says "AI unavailable / not configured — showing deterministic recommendations".

To add an LLM explanation layer, set in `server/.env`:

```bash
# Anthropic
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-...
AI_MODEL=<a current Claude model id from https://docs.claude.com>

# Any OpenAI-compatible API, including a local model for air-gapped sites
AI_PROVIDER=openai
AI_BASE_URL=http://127.0.0.1:11434     # e.g. Ollama / vLLM / llama.cpp server
AI_MODEL=llama3.1:8b
AI_API_KEY=                             # optional for local servers
```

Guarantees, enforced in `server/src/services/aiService.js`:

- The model receives only normalized findings (type, category, severity, confidence, title, evidence truncated to 400 chars), scores and anomaly results — never raw logs or file contents.
- The system prompt forbids inventing facts, claiming compromise without evidence and executing anything; it requires read-only verification steps and `REQUIRES ADMIN APPROVAL:` on security-altering remediation.
- Output must be JSON matching a zod schema (`summary`, `riskLevel`, `topPriorities[]`, `observations[]`, `uncertainties[]`); anything else falls back to the deterministic engine.
- Evidence wins: the model cannot downgrade a deterministic CRITICAL.
- The AI never drives actions; the endpoint is rate-limited (6/min) and audited.

---

## 14. API reference

All responses use `{ "success": true, "data": … }` or `{ "success": false, "error": { "code", "message", "details?" } }`. User routes need `Authorization: Bearer <jwt>`; agent routes need `Authorization: Bearer <agentSecret>` + `X-Agent-Id`.

| Method | Path | Who |
|---|---|---|
| POST | `/api/v1/auth/register`, `/auth/login` | public (rate-limited; 5 failures lock an account for 15 min) |
| GET | `/api/v1/auth/me` · POST `/auth/logout` (invalidates all sessions) | user |
| GET | `/api/v1/hosts`, `/hosts/:id`, `/hosts/:id/snapshot` | viewer |
| POST | `/api/v1/hosts/register` | agent with enrollment token |
| DELETE | `/api/v1/hosts/:id` | admin |
| POST | `/api/v1/hosts/:id/metrics` | that host's agent |
| GET | `/api/v1/hosts/:id/metrics?range=15m\|1h\|6h\|24h\|7d` | viewer |
| POST | `/api/v1/hosts/:id/scan` `{type}` | analyst |
| GET | `/api/v1/hosts/:id/scans`, `/hosts/:id/scans/:scanId` | viewer |
| GET | `/api/v1/hosts/:id/findings`, `/hosts/:id/security-score` | viewer |
| GET | `/api/v1/findings?severity=&status=&category=&hostId=&from=&to=&q=&page=&limit=` · `/findings/:id` | viewer |
| PATCH | `/api/v1/findings/:id` `{status}` | admin |
| POST | `/api/v1/hosts/:id/ai/analyze` | analyst |
| GET | `/api/v1/hosts/:id/ai/insights`, `/hosts/:id/ai/anomalies` | viewer |
| GET | `/api/v1/alerts` · PATCH `/alerts/:id/acknowledge` | viewer · analyst |
| POST | `/api/v1/agent/heartbeat`, `/agent/events`, `/agent/scan-results` | agent |
| POST/GET/DELETE | `/api/v1/agent/enrollment-tokens` | admin |
| GET | `/api/v1/dashboard/summary`, `/settings` | viewer |
| GET/POST/PATCH/DELETE | `/api/v1/users`, GET `/audit-logs` | admin |

Socket.IO (auth with the JWT): `metric:update`, `host:snapshot`, `host:online`, `host:offline`, `host:status`, `finding:new`, `security:alert`, `scan:queued`, `scan:started`, `scan:progress`, `scan:completed`.

Agent payloads are versioned (`schemaVersion` 1.0, agent 1.0.0); the API is `/api/v1`.

---

## 15. Testing

```bash
# Agent: 35 tests — OS/BOSS detection, capability registry, collectors, SSH/SUID/permission/auth/C2/
# kernel/CIS parsing, schema rules, crash isolation, NOT_SUPPORTED semantics, bounded outbox
cd agent && python3 -m pytest -q

# Backend: 27 tests — risk/health/ML/AI units and an API flow: registration & roles, login,
# enrollment (single-use token), agent auth, heartbeat, metrics validation, scan queue → dispatch,
# findings dedup + auto-resolve, security score, triage, audit log, alerts, AI fallback, logout
cd server && MONGODB_URI_TEST=mongodb://127.0.0.1:27017/sentinelai_test npm test

# Dashboard: component tests
cd client && npm test
```

API tests are skipped (not failed) with a clear message if MongoDB is unreachable. A local scan needs no server: `python3 main.py --config /nonexistent scan --type FULL --summary`.

---

## 16. BOSS 10 verification checklist

Run on a fresh BOSS 10 machine and tick each item. Commands assume `A` from §8.

```text
[ ] OS detected correctly            $A detect  → "distribution": "BOSS", "isBoss10": true
[ ] BOSS version detected correctly  → "version": "10", codename present
[ ] Kernel detected                  → matches `uname -r`
[ ] CPU detected                     $A scan --type QUICK --summary → cpu PASS/WARN
[ ] RAM detected                     → memory PASS/WARN
[ ] Disk detected                    → disk lists / and other real filesystems
[ ] Network detected                 Host → Network shows interfaces and listening ports
[ ] Processes detected               Host → Processes populated
[ ] Services detected                Host → Services populated (systemd)
[ ] SSH detected                     ssh check PASS/WARN/FAIL, or NOT_SUPPORTED if openssh-server absent
[ ] Package manager detected         capabilities.packageManager = "dpkg"
[ ] Firewall detected                firewall check names nftables/iptables; not "not readable"
[ ] Audit/logging detected           audit_logging shows journald/rsyslog/auditd state and auth events
[ ] SUID scan works                  FULL scan: suid lists files; standard ones not flagged
[ ] Writable-file scan works         `sudo touch /usr/local/bin/t && sudo chmod 777 /usr/local/bin/t` → HIGH finding; remove after
[ ] Temporary executable scan works  `cp /bin/true /tmp/t && chmod +x /tmp/t` → finding; remove after
[ ] Benchmark capability detected    benchmark NOT_SUPPORTED with reason, or a compliance % with oscap + content
[ ] Rootkit capability detected      rootkit verdict + scanner status (installed / requires root / not installed)
[ ] C2 heuristic works               `nc 127.0.0.1 4444` style test from /tmp → Suspicious/High risk (test only on lab hosts)
[ ] Agent starts as service          systemctl status sentinel-agent → active (running)
[ ] Backend connection works         $A ping → heartbeat OK
[ ] Dashboard receives metrics       Overview charts move every 5 s without refresh
[ ] Security scan works              Host → Scans → Start scan → progress → completed
[ ] AI analysis works                Host → AI analysis → Analyse now (deterministic or LLM)
```

What was verified while building this release: the full flow (install.sh in restricted mode → enrollment → heartbeat → metrics → snapshots → scheduled and dashboard-requested scans → findings, alerts, scores → dashboard pages and live updates → uninstall) on an Ubuntu 24.04 container without systemd, with the API running against FerretDB (a MongoDB-wire-compatible server). **It has not yet been run on BOSS 10 or on MongoDB itself** — this checklist is that step.

---

## 17. Production deployment

1. **Database:** MongoDB with authentication enabled, bound to localhost or a private network, backed up.
2. **API:**
   ```bash
   sudo useradd --system --shell /usr/sbin/nologin sentinelai-api
   sudo mkdir -p /opt/sentinelai && sudo cp -r server /opt/sentinelai/
   cd /opt/sentinelai/server && sudo npm ci --omit=dev
   sudo install -m 0640 -o root -g sentinelai-api .env.example /etc/sentinelai/server.env   # then edit: NODE_ENV=production, secrets, CORS_ORIGIN, TRUST_PROXY=true
   sudo cp deploy/sentinelai-server.service /etc/systemd/system/ && sudo systemctl enable --now sentinelai-server
   ```
3. **Dashboard:** `VITE_API_URL=https://sentinel.example.org/api/v1 VITE_SOCKET_URL=https://sentinel.example.org npm run build`, copy `client/dist` to `/var/www/sentinelai`.
4. **TLS proxy:** `deploy/nginx-sentinelai.conf` serves the dashboard and proxies `/api`, `/health` and `/socket.io` (WebSocket upgrade, 16 MB body limit for scan results).
5. **Agents:** install with `https://` URLs. For an internal CA, set `server.ca_bundle` in `agent.yaml`.
6. Set `ALLOW_REGISTRATION=false` once your team has accounts; create others in *Settings → People* or with `npm run create-admin`.

Scaling notes: every record carries `hostId`, queries are indexed and paginated, the API is stateless apart from Socket.IO (add the Socket.IO Redis adapter to run several API instances behind a load balancer), metric ingestion is one insert per sample (≈ 200 inserts/s at 1 000 hosts with a 5 s interval — raise `metrics_interval` or use a MongoDB time-series collection for larger fleets).

---

## 18. Troubleshooting

| Problem | What to do |
|---|---|
| **Agent cannot connect** | `curl -I https://SERVER/health` from the host; check `SENTINEL_SERVER_URL` in `/etc/sentinelai/agent.env`; with a private CA set `server.ca_bundle`; `journalctl -u sentinel-agent -n 50`. Data collected meanwhile waits in the outbox (`outbox` count on the host) and is replayed. |
| **Agent logs "server rejected agent credentials"** | The host was deleted or re-enrolled elsewhere. Create a token and run `sudo rm /var/lib/sentinelai/credentials.json && sudo SENTINEL_AGENT_TOKEN=... ./install.sh`. |
| **Enrollment token invalid** | Tokens are single-use by default and expire (24 h default). Create a new one or raise *Hosts it can enroll*. |
| **MongoDB unavailable** | API exits with `startup failed`. `systemctl status mongod`; check `MONGODB_URI`; `mongosh "$MONGODB_URI" --eval 'db.runCommand({ping:1})'`. |
| **Port already in use** | `sudo ss -ltnp 'sport = :5000'` (or `:5173`); change `PORT` / `vite --port`, and update `VITE_API_URL`/`CORS_ORIGIN`. |
| **Permission denied / "not readable" in a check** | Expected in restricted mode for a few items (e.g. rkhunter). Confirm the unit has its capabilities: `systemctl show sentinel-agent -p AmbientCapabilities`. For full coverage reinstall with `--mode root`. |
| **Command not found** | The check reports `NOT_SUPPORTED` with the missing command — install the package if you want that check (e.g. `apt install iproute2 nftables`). |
| **CIS benchmark unavailable** | `NOT_SUPPORTED: oscap not installed` or `no SCAP datastream found`. Install `libopenscap8` and SCAP content (see §11), or point `benchmark.datastream` at it. |
| **Rootkit scanner unavailable** | Shows "not installed" or "requires root". `apt install rkhunter chkrootkit` and use `--mode root`. Built-in heuristics run regardless. |
| **SSH not installed** | `ssh` check is `NOT_SUPPORTED` — correct when the host has no SSH server. |
| **Firewall tool unavailable** | `NOT_SUPPORTED: no firewall tooling`. Install `nftables` (Debian default) if the host needs a firewall. |
| **BOSS version not detected** | `$A detect`; inspect `/etc/os-release`. Detection looks for "boss" in `ID`, `ID_LIKE`, `NAME`, `PRETTY_NAME` and `VERSION_ID` major = 10. If your image differs, adjust `BOSS_MARKERS` in `agent/bossplatform/os_detection.py`. |
| **systemd unavailable** | Installer prints the manual `main.py run` command; the services check reports `NOT_SUPPORTED`. Run the agent under your init system or a supervisor. |
| **Python unavailable / venv missing** | `sudo apt install python3 python3-venv`; Python ≥ 3.9 required. |
| **Node unavailable** | Install Node.js LTS (≥ 18) from your distribution or nodejs.org; `node -v`. |
| **Dashboard shows "Cannot reach the SentinelAI server"** | Backend down or `VITE_API_URL` wrong (it is baked in at build time — rebuild after changing it). |
| **No live updates** | Check `VITE_SOCKET_URL` and that the proxy forwards `/socket.io/` with the `Upgrade` header. |
| **AI page always deterministic** | `AI_PROVIDER`, `AI_MODEL` and key/base URL must all be set; the server log shows `AI unavailable: …` with the reason. |

---

## 19. Uninstallation

```bash
cd agent
sudo ./uninstall.sh            # stops and removes the service and /opt/sentinelai/agent; keeps config and credentials
sudo ./uninstall.sh --purge    # also removes /etc/sentinelai, /var/lib/sentinelai and the sentinelai user
```

Then remove the host in the dashboard (*Host → Overview → Remove host*, admins only) to delete its metrics, findings, scans and alerts. For the server: `systemctl disable --now sentinelai-server`, remove `/opt/sentinelai/server`, `/etc/sentinelai/server.env` and drop the MongoDB database.

---

## 20. Security model and known limits

- **Secrets:** JWTs signed HS256, passwords bcrypt (cost 12), agent secrets and enrollment tokens stored as SHA-256 only, shown once. Logs on both sides redact token/secret/password/key patterns. Audit metadata drops any key that looks secret.
- **Input:** every write endpoint is validated with zod; query filters are whitelisted; agent-supplied object keys containing `.` or a leading `$` are rewritten before storage; request bodies are capped (200 KB, 16 MB for agent uploads); helmet, CORS allow-list and rate limits are on; production errors never include stack traces.
- **Agent:** fixed argv lists only (no `shell=True`), per-command timeouts, output caps, a global scan timeout, a single scan worker, bounded queues, no filesystem walks of `/proc /sys /dev /run`, no symlink following, file-count and depth limits.
- **Privacy:** no password hashes, private keys, document contents or browser data are collected. `authorized_keys` files are only counted. Auth logs leave the host as counts and top sources only.
- **Limits:** the JWT is kept in `sessionStorage` (cleared when the tab closes; an XSS bug would expose it — the app renders no HTML from data). Vulnerability awareness uses the local APT cache, not a CVE database. The frontend is JavaScript rather than TypeScript. See `docs/ARCHITECTURE.md` for the threat model and which checks need which privileges.
