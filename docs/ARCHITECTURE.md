# SentinelAI — design notes

Answers to the spec's "before writing code" list (§102), kept current with the implementation.

## Repository tree

```text
sentinelai/
├── agent/                         Python agent (runs on BOSS 10)
│   ├── main.py                    CLI: detect | scan | enroll | run | ping
│   ├── config.py  logger.py       YAML + env config; JSON logs with secret redaction
│   ├── capability_detector.py     Context: OS info + capability registry
│   ├── scanner.py  scheduler.py   scan engine; fast/slow job loop + scan worker thread
│   ├── metrics.py  client.py      5-second sample; HTTP client, enrollment, SQLite outbox
│   ├── util.py                    safe subprocess, result envelope, safe filesystem walk
│   ├── bossplatform/              compatibility layer (os, capabilities, packages, services,
│   │                              network, firewall/MAC, benchmark content)
│   ├── collectors/                system cpu memory disk process network services users packages
│   ├── security/                  base + registry + 14 checks
│   ├── models/schemas.py          normalized finding + versioned envelope
│   ├── deploy/                    agent.yaml, sentinel-agent.service
│   ├── install.sh  uninstall.sh
│   └── tests/
├── server/                        Express API
│   └── src/ config/ middleware/ models/ modules/{auth,users,hosts,agents,metrics,security,
│            findings,alerts,ai,dashboard}/ services/ sockets/ utils/ scripts/
├── client/                        React + Vite dashboard
│   └── src/ components/ layouts/ pages/ pages/host/ charts/ hooks/ services/ context/ utils/
├── deploy/                        server systemd unit, nginx TLS proxy
└── docs/
```

## Major modules and dependencies

| Module | Depends on |
|---|---|
| Agent collectors/checks | psutil, stdlib (`subprocess`, `os`, `pwd`, `ipaddress`, `sqlite3`, `xml.etree`), PyYAML, requests |
| API | express, mongoose, jsonwebtoken, bcryptjs, helmet, cors, express-rate-limit, zod, socket.io, dotenv |
| Dashboard | react, react-router-dom, axios, recharts, socket.io-client, @fontsource (self-hosted fonts) |
| Optional host tools | openssh-server, nftables/iptables, auditd, rsyslog, rkhunter, chkrootkit, libopenscap8 + SCAP content, apt |

## Privileges required

| Needs root (or the listed capability) | Why |
|---|---|
| `/etc/shadow` read (CAP_DAC_READ_SEARCH) | empty-password detection |
| `sshd -T` (CAP_DAC_READ_SEARCH) | effective SSH config needs host keys readable |
| other users' `/proc/<pid>/exe`, sockets (CAP_SYS_PTRACE) | process paths, deleted executables, connection owners |
| `nft list ruleset`, `iptables-save` (CAP_NET_ADMIN) | firewall state |
| `auditctl -l` | audit rules |
| rkhunter / chkrootkit | the tools themselves require root (agent `--mode root` only) |
| `oscap xccdf eval` | many rules read root-only files |
| auth logs | `adm` / `systemd-journal` group membership suffices |

Everything else (CPU, memory, disk, network counters, process list, kernel parameters, `/etc/passwd`, SUID walk, world-writable walk, temp executables, packages) runs unprivileged. The default install runs as user `sentinelai` with only those three capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, write access limited to `/var/lib/sentinelai`, `CPUQuota=50%`, `MemoryMax=512M`.

## Checks that depend on optional tools

`ssh` (openssh-server), `services` (systemd), `firewall` (nft/iptables/firewalld/ufw), `audit_logging` rules (auditd), `rootkit` scanners (rkhunter/chkrootkit — heuristics run regardless), `benchmark` (oscap + content), `vulnerabilities` (apt), `packages` (dpkg-query or rpm). Each reports `NOT_SUPPORTED` with a reason when its requirement is missing.

## BOSS 10 assumptions that need runtime verification

1. `/etc/os-release` identifies BOSS via `ID`/`ID_LIKE`/`NAME` containing "boss" and `VERSION_ID` major 10.
2. systemd is PID 1 (detected, not assumed).
3. dpkg/apt are the package tools; merged `/usr` (Debian 12 base) affects `dpkg -S` — handled by path fallback.
4. Default firewall stack (nftables expected on a Debian 12 base) and whether rules exist out of the box.
5. Auth events in journald vs `/var/log/auth.log` (both supported).
6. Availability of SCAP content for BOSS or Debian 12.
7. APT origin naming for security updates (the agent looks for "security" in the origin).
8. The list of commonly-expected SUID binaries (`security/suid.py: KNOWN`) on a BOSS desktop install.

## Security risks in this architecture and mitigations

| Risk | Mitigation |
|---|---|
| Rogue machine submitting data | enrollment tokens (single-use, expiring, hashed, revocable) → per-host secret; agents can only write their own host |
| Stolen agent secret | secret file 0600 in a 0700 dir; rotation by re-enrollment; host deletion revokes |
| Agent as an attack surface | no inbound port; server cannot push commands except "run a predefined scan type"; fixed argv, no shell, timeouts |
| Privilege of the agent | restricted mode with three read-oriented capabilities; root mode opt-in |
| Injection through agent data | zod validation, key sanitization (`.`/`$`), size limits, whitelisted query filters |
| Credential attacks on the dashboard | bcrypt, rate limits, account lockout, JWT revocation on logout/role change |
| Sensitive data leakage | no hashes/keys/file contents collected; LLM sees only normalized findings; secrets redacted in logs and audit |
| LLM hallucination or overreach | deterministic layer is authoritative; JSON schema validation; cannot downgrade CRITICAL; no action capability |
| Alert fatigue / flooding | dedup key + cooldown counter |
| Agent causing load | fast vs slow schedules, single scan worker, walk limits, systemd CPU/memory quotas, idle IO class |
| Plain-HTTP deployments | installer and agent warn when the URL is not HTTPS |

## Implementation phases (as built)

1. Repository: `agent/`, `server/`, `client/`, `docs/`, git.
2. Agent foundation: OS/BOSS detection, capability registry, config, logging, health collectors.
3. Backend: Express, MongoDB models, auth, enrollment, heartbeat, metrics.
4. Dashboard: login, overview, hosts, host system/network views, charts.
5. Security engine: SSH, accounts, SUID, world-writable, temp executables, processes, network, firewall, audit, packages.
6. Benchmark: SCAP discovery + read-only `oscap` evaluation.
7. Rootkit / C2 layered heuristics.
8. Risk engine: normalization, weighted risk, health, alerts.
9. AI: deterministic recommendations, structured LLM prompt, schema validation, fallback; anomaly baseline.
10. Real-time: Socket.IO events.
11. Hardening: RBAC, rate limits, validation, audit trail, least-privilege service.
12. Testing: agent, API and component tests; BOSS 10 checklist in the README.
13. Deployment: installer, uninstaller, systemd units, nginx config.
