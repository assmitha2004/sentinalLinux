"""Kernel hardening parameters (spec §22) read straight from /proc/sys - no sysctl binary needed."""
from models.schemas import finding
from util import read_text, result, status_from_findings

from .base import SecurityCheck

# param: (expected, severity, why)
EXPECTED = {
    "kernel.randomize_va_space": ("2", "MEDIUM", "ASLR makes memory-corruption exploits much harder."),
    "kernel.kptr_restrict": ("1+", "LOW", "Hides kernel pointers that aid exploit development."),
    "kernel.dmesg_restrict": ("1", "LOW", "Prevents unprivileged users reading kernel logs."),
    "fs.protected_symlinks": ("1", "MEDIUM", "Blocks symlink attacks in sticky directories like /tmp."),
    "fs.protected_hardlinks": ("1", "MEDIUM", "Blocks hardlink-based privilege escalation."),
    "fs.suid_dumpable": ("0", "LOW", "Prevents SUID programs dumping memory (may leak secrets)."),
    "net.ipv4.tcp_syncookies": ("1", "LOW", "Mitigates SYN-flood denial of service."),
    "net.ipv4.conf.all.accept_redirects": ("0", "LOW", "ICMP redirects can be used to reroute traffic."),
    "net.ipv4.conf.all.send_redirects": ("0", "LOW", "Hosts that are not routers should not send redirects."),
    "net.ipv4.conf.all.accept_source_route": ("0", "LOW", "Source routing allows spoofed traffic paths."),
    "net.ipv4.conf.all.rp_filter": ("1+", "LOW", "Reverse-path filtering drops spoofed packets."),
    "net.ipv4.ip_forward": ("0", "INFO", "Forwarding is only needed on routers/container hosts."),
}


def read_param(name):
    v = read_text("/proc/sys/" + name.replace(".", "/"))
    return v.strip() if v is not None else None


def compliant(value, expected):
    if expected.endswith("+"):
        return value.isdigit() and int(value) >= int(expected[:-1])
    return value == expected


class KernelParamsCheck(SecurityCheck):
    name, category = "kernel_params", "kernel"

    def run(self, ctx):
        params, findings = [], []
        for name, (exp, sev, why) in EXPECTED.items():
            val = read_param(name)
            ok = None if val is None else compliant(val, exp)
            params.append({"name": name, "value": val, "expected": exp, "compliant": ok})
            if ok is False:
                findings.append(finding("kernel_param", "kernel", sev, f"Kernel parameter {name} = {val}",
                                        f"{name} is {val}; recommended {exp.rstrip('+')}{' or higher' if exp.endswith('+') else ''}.",
                                        {"param": name, "value": val, "expected": exp},
                                        f"Set '{name} = {exp.rstrip('+')}' in /etc/sysctl.d/99-sentinel.conf and "
                                        "apply with 'sysctl --system' after review.",
                                        f"sysctl {name}", confidence=0.95, resource=name, why=why,
                                        requires_approval=True))
        mods = read_text("/proc/modules") or ""
        return result(self.name, status_from_findings(findings),
                      {"params": params, "loadedModules": len(mods.splitlines())}, findings)
