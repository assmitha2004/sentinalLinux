"""Vulnerability awareness (spec §26). Offline: pending upgrades from the *local* package cache and
reboot-required state. No exploit logic. Optional CVE enrichment is a server-side future hook."""
import os

from bossplatform.capabilities import package_manager_name
from models.schemas import finding
from util import read_text, result, run, status_from_findings

from .base import SecurityCheck


def upgradable_dpkg():
    # `apt list --upgradable` reads the local cache only; it never contacts mirrors.
    r = run(["apt", "list", "--upgradable"], timeout=60)
    if not r:
        return None, r.reason
    out = []
    for line in r.stdout.splitlines():
        if "/" not in line or "upgradable from" not in line:
            continue
        name, rest = line.split("/", 1)
        parts = rest.split()
        origin = parts[0] if parts else ""
        new = parts[1] if len(parts) > 1 else ""
        cur = line.rsplit("upgradable from:", 1)[1].strip(" ]")
        out.append({"package": name, "installedVersion": cur, "candidateVersion": new, "origin": origin,
                    "security": "security" in origin.lower()})
    return out, None


class VulnerabilityCheck(SecurityCheck):
    name, category = "vulnerabilities", "vulnerability"

    def is_supported(self, ctx):
        if package_manager_name(ctx.reg) == "dpkg" and ctx.reg.has("apt"):
            return True, None
        return False, "pending-update analysis currently supports apt/dpkg only"

    def run(self, ctx):
        ups, err = upgradable_dpkg()
        findings = []
        if ups is None:
            return result(self.name, "ERROR", errors=[err])
        sec = [u for u in ups if u["security"]]
        for u in sec[:100]:
            findings.append(finding("security_update_pending", "vulnerability", "MEDIUM",
                                    f"Security update pending: {u['package']}",
                                    f"{u['package']} {u['installedVersion']} has a newer version "
                                    f"{u['candidateVersion']} from {u['origin']}.",
                                    {**u, "knownIssue": "see vendor security advisory for this version",
                                     "source": "local apt cache"},
                                    "Apply updates through your normal change process (apt upgrade).",
                                    f"apt list --upgradable 2>/dev/null | grep ^{u['package']}/",
                                    confidence=0.8, resource=f"pkg:{u['package']}"))
        if len(ups) - len(sec) >= 20:
            findings.append(finding("updates_pending", "vulnerability", "LOW", f"{len(ups)} package updates pending",
                                    "Many packages are behind the versions in the local package cache.",
                                    {"count": len(ups)}, "Plan a maintenance window to apply updates.",
                                    "apt list --upgradable", confidence=0.8, resource="updates"))
        reboot = os.path.exists("/var/run/reboot-required") or os.path.exists("/run/reboot-required")
        if reboot:
            pk = (read_text("/var/run/reboot-required.pkgs") or "").split()
            findings.append(finding("reboot_required", "vulnerability", "LOW", "Reboot required",
                                    "Updated components (possibly the kernel) are not active until reboot.",
                                    {"packages": pk[:20]}, "Schedule a reboot.", "cat /var/run/reboot-required.pkgs",
                                    confidence=0.95, resource="reboot"))
        data = {"kernel": ctx.os_info["kernel"], "upgradable": ups[:500], "upgradableCount": len(ups),
                "securityCount": len(sec), "rebootRequired": reboot,
                "note": "Based on the local package cache; run 'apt update' to refresh it. CVE database "
                        "enrichment is not enabled."}
        return result(self.name, status_from_findings(findings), data, findings)
