"""Audit/logging posture and structured security events (spec §24). Only counts and short samples
leave the host - never raw logs."""
import os
import re
from collections import Counter

from bossplatform import service_manager as sm
from models.schemas import finding
from util import read_text, result, run, status_from_findings

from .base import SecurityCheck

PATTERNS = {
    "ssh_failed_password": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    "ssh_invalid_user": re.compile(r"Invalid user (\S+) from (\S+)"),
    "sudo_auth_failure": re.compile(r"sudo: .*authentication failure|sudo:.*incorrect password", re.I),
    "sudo_command": re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.{0,120})"),
    "su_failure": re.compile(r"su(?:\[\d+\])?: .*(FAILED|authentication failure)", re.I),
}
AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")


def parse_events(lines):
    counts, sources, users, sudo_cmds = Counter(), Counter(), Counter(), []
    for line in lines:
        for kind, rx in PATTERNS.items():
            m = rx.search(line)
            if not m:
                continue
            counts[kind] += 1
            if kind in ("ssh_failed_password", "ssh_invalid_user"):
                users[m.group(1)] += 1
                sources[m.group(2)] += 1
            elif kind == "sudo_command" and len(sudo_cmds) < 20:
                sudo_cmds.append({"user": m.group(1), "command": m.group(2).strip()})
    return {"counts": dict(counts), "topSources": sources.most_common(10), "topUsers": users.most_common(10),
            "recentSudo": sudo_cmds}


def auth_lines(reg, max_lines=20000):
    if reg.has("journalctl"):
        r = run(["journalctl", "--since", "-1h", "--no-pager", "-o", "short", "-n", str(max_lines),
                 "SYSLOG_FACILITY=4", "+", "SYSLOG_FACILITY=10", "+", "_COMM=sshd", "+", "_COMM=sudo"], timeout=20)
        if r and r.stdout.strip() and "No entries" not in r.stdout[:40]:
            return r.stdout.splitlines()[-max_lines:], "journald (last 1h)"
    for p in AUTH_LOGS:
        t = read_text(p, limit=8 * 1024 * 1024)
        if t:
            return t.splitlines()[-max_lines:], p + " (tail)"
    return None, None


class AuditCheck(SecurityCheck):
    name, category = "audit_logging", "logging"

    def run(self, ctx):
        reg, o = ctx.reg, ctx.os_info
        auditd = sm.is_active(reg, o, ["auditd"], ["auditd"])
        journald = sm.is_active(reg, o, ["systemd-journald"], ["systemd-journald"])
        syslog = sm.is_active(reg, o, ["rsyslog", "syslog-ng"], ["rsyslogd", "syslog-ng"])
        rules = None
        if reg.has("auditctl"):
            r = run(["auditctl", "-l"], timeout=10)
            if r:
                rules = 0 if "No rules" in r.stdout else len(r.stdout.splitlines())
        persistent_journal = os.path.isdir("/var/log/journal")
        data = {"auditd": auditd, "auditRules": rules, "journald": journald,
                "journalPersistent": persistent_journal, "syslog": syslog}
        findings = []
        if not auditd:
            findings.append(finding("auditd_inactive", "logging", "LOW", "Linux audit daemon not running",
                                    "auditd is not installed or not active.", {"auditd": auditd},
                                    "Install and enable auditd for forensic visibility of privileged actions.",
                                    "systemctl is-active auditd", confidence=0.85, resource="auditd"))
        elif rules == 0:
            findings.append(finding("audit_no_rules", "logging", "LOW", "auditd has no rules loaded",
                                    "auditd is running but `auditctl -l` lists no rules.", {"rules": 0},
                                    "Load a baseline audit ruleset (identity files, sudoers, privileged commands).",
                                    "auditctl -l", confidence=0.9, resource="audit_rules"))
        if not journald and not syslog:
            findings.append(finding("no_logging", "logging", "MEDIUM", "No system logging daemon detected",
                                    "Neither journald nor rsyslog/syslog-ng is active.", data,
                                    "Enable a logging service.", "systemctl status systemd-journald rsyslog",
                                    confidence=0.7, resource="logging"))
        lines, source = auth_lines(reg)
        if lines is None:
            data["events"] = None
            data["eventsNote"] = "authentication logs not readable (run as root or add agent user to adm group)"
        else:
            ev = parse_events(lines)
            ev["source"] = source
            data["events"] = ev
            fails = ev["counts"].get("ssh_failed_password", 0) + ev["counts"].get("ssh_invalid_user", 0)
            if fails >= 20:
                sev = "HIGH" if fails >= 200 else "MEDIUM"
                findings.append(finding("ssh_bruteforce_activity", "authentication", sev,
                                        f"{fails} failed SSH login attempts",
                                        f"{fails} failed SSH authentications found in {source}.",
                                        {"failures": fails, "topSources": ev["topSources"][:5],
                                         "topUsers": ev["topUsers"][:5]},
                                        "Confirm password auth is needed; consider key-only auth, firewall "
                                        "restrictions or fail2ban.", "journalctl -u ssh --since -1h | grep Failed",
                                        confidence=0.9, resource="ssh_failures",
                                        why="Repeated failures indicate active password guessing."))
            sf = ev["counts"].get("sudo_auth_failure", 0) + ev["counts"].get("su_failure", 0)
            if sf >= 5:
                findings.append(finding("privilege_auth_failures", "authentication", "MEDIUM",
                                        f"{sf} failed sudo/su attempts", "Multiple failed privilege escalations.",
                                        {"count": sf}, "Review who attempted elevation and why.",
                                        "journalctl _COMM=sudo --since -1h", confidence=0.8, resource="sudo_failures"))
        return result(self.name, status_from_findings(findings), data, findings)
