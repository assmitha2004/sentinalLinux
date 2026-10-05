"""Firewall detection (spec §23). Detects nftables / iptables / firewalld / ufw - never modifies."""
from bossplatform import security_tools as st
from models.schemas import finding
from util import result, status_from_findings

from .base import SecurityCheck


class FirewallCheck(SecurityCheck):
    name, category = "firewall", "firewall"
    requirements = ("nft or iptables or firewall-cmd",)

    def is_supported(self, ctx):
        if ctx.reg.any("nft", "iptables", "iptables-save", "firewall-cmd", "ufw"):
            return True, None
        return False, "no firewall tooling (nft/iptables/firewalld/ufw) installed"

    def run(self, ctx):
        techs = st.firewall_status(ctx.reg)
        readable = [t for t in techs if t.get("readable")]
        active = [t for t in readable if t.get("enabled")]
        data = {"technologies": techs, "active": [t["technology"] for t in active]}
        findings = []
        if not readable:
            data["state"] = "UNKNOWN"
            return result(self.name, "WARN", data,
                          errors=["firewall rules not readable (agent needs root / CAP_NET_ADMIN)"])
        if not active:
            data["state"] = "DISABLED"
            findings.append(finding("firewall_inactive", "firewall", "MEDIUM", "No active host firewall rules",
                                    "Firewall tooling is installed but no filtering rules or restrictive default "
                                    "policies were found.", {"technologies": techs},
                                    "Define an nftables ruleset allowing only required inbound services, "
                                    "test it from a second session, then enable it persistently.",
                                    "nft list ruleset", confidence=0.8, resource="firewall",
                                    requires_approval=True,
                                    why="Without a host firewall every listening service is reachable from the network."))
        else:
            data["state"] = "ACTIVE"
        return result(self.name, status_from_findings(findings), data, findings)
