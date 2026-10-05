"""Mandatory access control (AppArmor/SELinux) status."""
from bossplatform import security_tools as st
from models.schemas import finding
from util import result, status_from_findings

from .base import SecurityCheck


class MACCheck(SecurityCheck):
    name, category = "mac", "kernel"

    def run(self, ctx):
        s = st.mac_status(ctx.reg)
        findings = []
        aa_on = bool(s["apparmor"] and s["apparmor"].get("enabled"))
        se_on = bool(s["selinux"] and s["selinux"].get("enforcing"))
        if not aa_on and not se_on:
            findings.append(finding("mac_disabled", "kernel", "LOW", "No mandatory access control active",
                                    "Neither AppArmor nor SELinux is enabled/enforcing.", s,
                                    "Enable AppArmor (default on Debian-based systems) for service confinement.",
                                    "cat /sys/module/apparmor/parameters/enabled", confidence=0.8, resource="mac"))
        return result(self.name, status_from_findings(findings), s, findings)
