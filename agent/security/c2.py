"""Suspicious outbound connection heuristics (spec §13). Evidence-scored; an external IP alone is
never 'malicious'. 'CONFIRMED_MALICIOUS' requires a match in an operator-supplied IOC list."""
import ipaddress
import os
from collections import Counter

from bossplatform import network_tools as nt
from models.schemas import finding
from util import read_text, result, status_from_findings

from .base import SecurityCheck

IOC_FILE = "/etc/sentinelai/ioc-blocklist.txt"
SHELLS = {"bash", "sh", "dash", "zsh", "nc", "ncat", "netcat", "socat", "perl", "python", "python3", "php", "ruby"}
TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/")
LEVELS = (("HIGH_RISK", 50), ("SUSPICIOUS", 20), ("OBSERVED", 0))


def load_iocs(path=IOC_FILE):
    iocs = set()
    for line in (read_text(path) or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            iocs.add(line)
    return iocs


def ip_class(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    if ip.is_multicast or ip.is_reserved:
        return "special"
    return "public"


def score(conn, repeat, suspicious_ports, iocs):
    """Pure scoring function -> (score, signals, level)."""
    signals = []
    s = 0
    exe = conn.get("exe") or ""
    remote = conn["remoteAddress"]
    if remote in iocs:
        return 100, ["remote address matches operator IOC list"], "CONFIRMED_MALICIOUS"
    if exe.startswith(TEMP):
        s += 40; signals.append(f"process executable in temp dir ({exe})")
    if exe.endswith(" (deleted)"):
        s += 30; signals.append("process executable deleted from disk")
    if conn["remotePort"] in suspicious_ports:
        s += 25; signals.append(f"remote port {conn['remotePort']} commonly used by backdoors/C2")
    if (conn.get("process") or "") in SHELLS:
        s += 25; signals.append(f"interpreter/shell '{conn['process']}' holds a network connection")
    if conn.get("pid") is None:
        s += 5; signals.append("owning process not visible to agent")
    if repeat >= 10:
        s += 10; signals.append(f"{repeat} concurrent connections from same process to same destination")
    if ip_class(remote) == "public" and conn["remotePort"] not in (80, 443, 53, 123, 22, 853, 993, 995, 587, 465):
        s += 5; signals.append("public destination on an uncommon port")
    level = next(name for name, t in LEVELS if s >= t)
    return s, signals, level


class C2Check(SecurityCheck):
    name, category = "c2_heuristics", "network"

    def run(self, ctx):
        conns, err = nt.connections()
        iocs = load_iocs()
        sus_ports = set(ctx.cfg["network"]["suspicious_ports"])
        ext = [c for c in conns if c["state"] == "ESTABLISHED" and c["remoteAddress"]
               and ip_class(c["remoteAddress"]) in ("public", "private")]
        repeats = Counter((c["pid"], c["remoteAddress"]) for c in ext)
        scored, findings = [], []
        for c in ext:
            s, signals, level = score(c, repeats[(c["pid"], c["remoteAddress"])], sus_ports, iocs)
            item = {**c, "score": s, "level": level, "signals": signals, "ipClass": ip_class(c["remoteAddress"])}
            scored.append(item)
            if level == "OBSERVED":
                continue
            sev = {"SUSPICIOUS": "MEDIUM", "HIGH_RISK": "HIGH", "CONFIRMED_MALICIOUS": "CRITICAL"}[level]
            findings.append(finding("suspicious_connection", "network", sev,
                                    f"{level.replace('_', ' ').title()} connection: {c['process'] or 'unknown'} -> "
                                    f"{c['remoteAddress']}:{c['remotePort']}",
                                    "Connection scored on: " + "; ".join(signals) + ".", item,
                                    "Identify the process owner and purpose; check the destination against threat "
                                    "intelligence before taking action. Do not kill processes blindly.",
                                    f"ss -tnp dst {c['remoteAddress']}; ls -l /proc/{c['pid']}/exe" if c["pid"]
                                    else f"ss -tnp dst {c['remoteAddress']}",
                                    confidence=min(0.95, 0.3 + s / 150), requires_approval=True,
                                    resource=f"conn:{c['process']}:{c['remoteAddress']}:{c['remotePort']}"))
        # Exposure: listeners on all interfaces outside the expected list.
        expected = set(ctx.cfg["network"]["expected_listen_ports"])
        exposed = [c for c in nt.listening(conns)
                   if nt.is_wildcard(c["localAddress"]) and c["localPort"] not in expected]
        seen = set()
        for c in exposed:
            key = (c["proto"][:3], c["localPort"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding("exposed_service", "network", "LOW",
                                    f"Service listening on all interfaces: {c['proto'][:3]}/{c['localPort']}",
                                    f"{c['process'] or 'unknown process'} accepts connections on every interface. "
                                    "Review whether this exposure is intentional.",
                                    {k: c[k] for k in ("proto", "localAddress", "localPort", "process", "pid", "user")},
                                    "Bind to localhost or restrict with firewall rules if remote access is not needed.",
                                    f"ss -tulpn | grep ':{c['localPort']} '", confidence=0.9,
                                    resource=f"listen:{c['proto'][:3]}:{c['localPort']}"))
        levels = Counter(i["level"] for i in scored)
        data = {"connections": sorted(scored, key=lambda x: -x["score"])[:200], "levels": dict(levels),
                "iocListLoaded": bool(iocs), "iocCount": len(iocs), "exposedListeners": len(seen),
                "threatIntel": "operator IOC file" if iocs else "none configured"}
        return result(self.name, status_from_findings(findings), data, findings, [err] if err else [])
