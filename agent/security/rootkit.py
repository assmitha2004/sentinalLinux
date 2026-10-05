"""Layered rootkit indicator check (spec §20). Never concludes 'clean' - only 'no strong indicators'.
A: installed scanners, B: process anomalies, C: filesystem anomalies, D: kernel modules."""
import os
import re

import psutil

from models.schemas import finding
from util import read_text, result, run, status_from_findings

from .base import SecurityCheck

# Known file artefacts from public rootkit families (subset of the paths rkhunter/chkrootkit check).
KNOWN_ARTEFACTS = ("/dev/.udev/rules.d/root.rules", "/usr/lib/libsh", "/lib/libsh.so", "/usr/bin/xchk",
                   "/dev/.lib", "/usr/lib/.libssl", "/etc/ld.so.hash", "/lib/udev/libudev-ar.so")
SUSPECT_MODULE = re.compile(r"(diamorphine|reptile|suterusu|adore|knark|rootkit|hide_?pid)", re.I)


def hidden_pids():
    """PIDs visible in /proc that psutil's listing doesn't return, and vice versa. Can be noisy for
    short-lived processes, so we re-check before reporting."""
    def proc_pids():
        return {int(d) for d in os.listdir("/proc") if d.isdigit()}
    a = proc_pids()
    b = set(psutil.pids())
    suspect = a ^ b
    if not suspect:
        return []
    a2, b2 = proc_pids(), set(psutil.pids())
    return sorted(p for p in suspect if (p in a2) != (p in b2))


def ld_preload():
    t = read_text("/etc/ld.so.preload")
    return [l.strip() for l in (t or "").splitlines() if l.strip() and not l.startswith("#")]


def run_scanner(reg, name):
    if name == "rkhunter":
        r = run(["rkhunter", "--check", "--sk", "--nocolors", "--rwo", "--no-mail-on-warning"], timeout=600,
                ok_codes=(0, 1))
    else:
        r = run(["chkrootkit", "-q"], timeout=600, ok_codes=(0, 1))
    if r.code is None:
        return {"tool": name, "ran": False, "reason": r.reason}
    lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    warnings = [l for l in lines if "warning" in l.lower() or "infected" in l.lower()]
    return {"tool": name, "ran": True, "exitCode": r.code, "warnings": warnings[:50]}


class RootkitCheck(SecurityCheck):
    name, category, slow = "rootkit", "rootkit", True

    def run(self, ctx):
        reg, findings, errors = ctx.reg, [], []
        scanners = []
        for tool in ("rkhunter", "chkrootkit"):
            if reg.has(tool):
                if ctx.is_root:
                    scanners.append(run_scanner(reg, tool))
                else:
                    scanners.append({"tool": tool, "ran": False, "reason": "requires root"})
            else:
                scanners.append({"tool": tool, "ran": False, "reason": "not installed"})
        for s in scanners:
            for w in s.get("warnings", [])[:10]:
                findings.append(finding(f"{s['tool']}_warning", "rootkit", "MEDIUM",
                                        f"{s['tool']} warning", w, {"tool": s["tool"], "line": w},
                                        f"Review the {s['tool']} log; many warnings are false positives after "
                                        "package updates.", f"{s['tool']} --check (as root)", confidence=0.5,
                                        resource=f"{s['tool']}:{w[:60]}"))
        hp = hidden_pids()
        if hp:
            findings.append(finding("hidden_process", "rootkit", "HIGH", "Process listing inconsistency",
                                    "PIDs present in /proc differ from the process table on repeated reads.",
                                    {"pids": hp[:20]}, "Investigate with an independent tool (e.g. unhide).",
                                    "ls /proc | grep -E '^[0-9]+$' | sort -n", confidence=0.4,
                                    resource="hidden_pids"))
        pre = ld_preload()
        if pre:
            findings.append(finding("ld_preload", "rootkit", "HIGH", "/etc/ld.so.preload is in use",
                                    "Libraries are force-loaded into every process.", {"entries": pre},
                                    "Verify each library belongs to legitimate software; userland rootkits use this.",
                                    "cat /etc/ld.so.preload", confidence=0.6, resource="ld.so.preload",
                                    requires_approval=True))
        artefacts = [p for p in KNOWN_ARTEFACTS if os.path.exists(p)]
        if artefacts:
            findings.append(finding("rootkit_artefact", "rootkit", "CRITICAL", "Known rootkit file artefact present",
                                    "Files matching known rootkit artefact paths exist.", {"paths": artefacts},
                                    "Isolate the host and perform offline forensic analysis.",
                                    "ls -la " + " ".join(artefacts), confidence=0.8, resource="artefacts",
                                    requires_approval=True))
        mods = [l.split()[0] for l in (read_text("/proc/modules") or "").splitlines() if l]
        bad_mods = [m for m in mods if SUSPECT_MODULE.search(m)]
        if bad_mods:
            findings.append(finding("suspicious_module", "rootkit", "CRITICAL", "Kernel module with rootkit name",
                                    "Loaded module names match known LKM rootkits.", {"modules": bad_mods},
                                    "Isolate the host; do not trust its own tools.", "lsmod", confidence=0.85,
                                    resource="modules", requires_approval=True))
        tainted = (read_text("/proc/sys/kernel/tainted") or "0").strip()
        signals = len(findings)
        strong = [f for f in findings if f["confidence"] >= 0.7 and f["severity"] in ("HIGH", "CRITICAL")]
        verdict = ("Strong rootkit indicators detected - investigate" if strong else
                   "Weak indicators only - review" if findings else "No strong rootkit indicators detected")
        data = {"verdict": verdict, "scanners": scanners, "hiddenPids": hp, "ldPreload": pre,
                "loadedModules": len(mods), "kernelTainted": tainted, "signals": signals}
        return result(self.name, status_from_findings(findings), data, findings, errors)
