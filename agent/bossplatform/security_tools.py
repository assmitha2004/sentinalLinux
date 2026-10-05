"""Firewall / MAC / audit tooling detection (spec §23, §24). Detection first, never modification."""
import os

from util import run


def firewall_status(reg):
    """Inspect every firewall technology present. Returns list of dicts; empty list = none found."""
    out = []
    if reg.has("nft"):
        r = run(["nft", "list", "ruleset"], timeout=10)
        if r:
            lines = r.stdout.splitlines()
            rules = [l for l in lines if l.strip() and not l.strip().startswith(("table", "chain", "type", "}", "#"))
                     and "policy" not in l]
            policies = sorted({l.split("policy", 1)[1].strip(" ;") for l in lines if "policy" in l})
            out.append({"technology": "nftables", "readable": True, "rules": len(rules),
                        "tables": sum(1 for l in lines if l.startswith("table")),
                        "defaultPolicies": policies, "enabled": len(rules) > 0 or "drop" in policies})
        else:
            out.append({"technology": "nftables", "readable": False, "reason": r.reason})
    if reg.has("iptables-save") or reg.has("iptables"):
        r = run(["iptables-save"], timeout=10) if reg.has("iptables-save") else run(["iptables", "-S"], timeout=10)
        if r:
            lines = r.stdout.splitlines()
            rules = [l for l in lines if l.startswith("-A")]
            policies = [l for l in lines if l.startswith(":") or l.startswith("-P")]
            drop_policy = any("DROP" in p or "REJECT" in p for p in policies)
            out.append({"technology": "iptables", "readable": True, "rules": len(rules),
                        "defaultPolicies": policies[:10], "enabled": len(rules) > 0 or drop_policy})
        else:
            out.append({"technology": "iptables", "readable": False, "reason": r.reason})
    if reg.has("firewall-cmd"):
        r = run(["firewall-cmd", "--state"], timeout=10, ok_codes=(0, 252))
        out.append({"technology": "firewalld", "readable": bool(r), "enabled": r.stdout.strip() == "running"})
    if reg.has("ufw"):
        r = run(["ufw", "status"], timeout=10)
        out.append({"technology": "ufw", "readable": bool(r), "enabled": bool(r) and "Status: active" in r.stdout})
    return out


def mac_status(reg):
    """Mandatory access control: AppArmor / SELinux."""
    st = {"apparmor": None, "selinux": None}
    if os.path.isdir("/sys/kernel/security/apparmor"):
        enabled = (open_safe("/sys/module/apparmor/parameters/enabled") or "").strip() == "Y"
        st["apparmor"] = {"enabled": enabled}
        if reg.has("aa-status"):
            r = run(["aa-status", "--json"], timeout=10)
            if r:
                st["apparmor"]["details"] = "available"
    if os.path.isdir("/sys/fs/selinux"):
        mode = (open_safe("/sys/fs/selinux/enforce") or "").strip()
        st["selinux"] = {"enforcing": mode == "1"}
    return st


def open_safe(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return None
