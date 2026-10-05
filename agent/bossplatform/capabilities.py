"""Command capability registry (spec §84). Built once at startup; every collector consults it
before invoking a command, so a missing tool degrades to NOT_SUPPORTED instead of crashing."""
import os

from util import have

COMMANDS = (
    # core / network
    "ip", "ss", "netstat", "systemctl", "journalctl", "sudo", "find", "stat", "sha256sum",
    "lsmod", "modinfo", "sysctl", "getent", "chage", "last", "who",
    # package managers
    "dpkg", "dpkg-query", "apt", "apt-get", "rpm", "dnf", "yum",
    # security
    "sshd", "auditctl", "ausearch", "aa-status", "getenforce", "sestatus",
    "rkhunter", "chkrootkit", "oscap", "lynis", "debsums",
    # firewall
    "nft", "iptables", "iptables-save", "ip6tables", "firewall-cmd", "ufw",
    # logging
    "rsyslogd", "syslog-ng",
)

# Directories where SCAP benchmark content is commonly installed. We only *look* here;
# absence simply means NOT_SUPPORTED.
SCAP_CONTENT_DIRS = ("/usr/share/xml/scap", "/usr/share/scap-security-guide", "/usr/share/openscap",
                     "/opt/scap", "/etc/sentinelai/scap")


class CapabilityRegistry:
    def __init__(self, commands=COMMANDS):
        self.commands = {c: have(c) for c in commands}

    def has(self, cmd):
        if cmd not in self.commands:
            self.commands[cmd] = have(cmd)
        return self.commands[cmd]

    def any(self, *cmds):
        return next((c for c in cmds if self.has(c)), None)

    def summary(self, os_info):
        c = self.commands
        return {
            "systemd": os_info.get("initSystem") == "systemd" and c.get("systemctl", False),
            "ss": c["ss"], "ip": c["ip"], "netstat": c["netstat"],
            "journalctl": c["journalctl"],
            "auditd": c["auditctl"] or os.path.exists("/sbin/auditd") or os.path.exists("/usr/sbin/auditd"),
            "selinux": os.path.isdir("/sys/fs/selinux"),
            "apparmor": os.path.isdir("/sys/kernel/security/apparmor"),
            "openscap": c["oscap"],
            "scapContent": any(os.path.isdir(d) for d in SCAP_CONTENT_DIRS),
            "rkhunter": c["rkhunter"], "chkrootkit": c["chkrootkit"],
            "nftables": c["nft"], "iptables": c["iptables"], "firewalld": c["firewall-cmd"],
            "sshd": c["sshd"],
            "packageManager": package_manager_name(self),
            "isRoot": os.geteuid() == 0,
        }

    def to_dict(self, os_info):
        return {"commands": dict(self.commands), "summary": self.summary(os_info)}


def package_manager_name(reg):
    if reg.has("dpkg-query"):
        return "dpkg"
    if reg.has("rpm"):
        return "rpm"
    return None
