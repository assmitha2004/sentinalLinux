"""SSH server posture (spec §14). Read-only: `sshd -T` when permitted, else parse config files."""
import glob
import os
import pwd

from bossplatform import network_tools as nt
from bossplatform import service_manager as sm
from models.schemas import finding
from util import read_text, result, run, status_from_findings

from .base import SecurityCheck

CONFIG = "/etc/ssh/sshd_config"


def parse_config(text, include_dir="/etc/ssh/sshd_config.d"):
    """First value wins (sshd semantics). Include files are read in sorted order where they appear.
    Match blocks are ignored (we report global settings only)."""
    opts = {}

    def feed(t, depth=0):
        in_match = False
        for raw in (t or "").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":
                in_match = True
                continue
            if in_match:
                continue
            if key == "include" and depth < 3:
                pattern = val if val.startswith("/") else os.path.join("/etc/ssh", val)
                for f in sorted(glob.glob(pattern)):
                    feed(read_text(f), depth + 1)
                continue
            opts.setdefault(key, val.lower())

    feed(text)
    return opts


def effective_config(reg):
    """Returns (options, source)."""
    if reg.has("sshd"):
        r = run(["sshd", "-T"], timeout=10)
        if r and r.stdout:
            opts = {}
            for line in r.stdout.splitlines():
                k, _, v = line.partition(" ")
                opts.setdefault(k.lower(), v.strip().lower())
            return opts, "sshd -T"
    text = read_text(CONFIG)
    if text is None:
        return None, None
    return parse_config(text), CONFIG


def evaluate(opts, source, exposed):
    """Pure function: config options -> findings. Defaults follow upstream OpenSSH."""
    f = []
    v = lambda k, d: opts.get(k, d)  # noqa: E731
    ver = f"sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|permitemptypasswords'"
    root = v("permitrootlogin", "prohibit-password")
    pw = v("passwordauthentication", "yes")
    exposure = "SSH is listening on all interfaces" if exposed else "SSH is listening"
    if root == "yes":
        f.append(finding("ssh_root_login", "ssh", "HIGH" if pw == "yes" else "MEDIUM",
                         "SSH permits direct root login",
                         f"PermitRootLogin is '{root}'. {exposure}.",
                         {"PermitRootLogin": root, "source": source, "exposedAllInterfaces": exposed},
                         "Create/verify a non-root admin account with sudo, then set 'PermitRootLogin no' "
                         "(or 'prohibit-password'). Validate with 'sshd -t' before restarting ssh.",
                         ver, confidence=0.95, resource="sshd:permitrootlogin", requires_approval=True,
                         why="Root is the most-targeted account in brute-force attacks; direct root login "
                             "also removes per-user accountability."))
    if pw == "yes":
        f.append(finding("ssh_password_authentication", "ssh", "MEDIUM" if exposed else "LOW",
                         "SSH allows password authentication",
                         f"PasswordAuthentication is enabled. {exposure}.",
                         {"PasswordAuthentication": pw, "source": source},
                         "Review whether password authentication is required. Prefer key-based authentication "
                         "where operationally appropriate, then set 'PasswordAuthentication no'.",
                         ver, confidence=0.9, resource="sshd:passwordauthentication", requires_approval=True,
                         why="Password-based SSH increases brute-force and credential-stuffing exposure."))
    if v("permitemptypasswords", "no") == "yes":
        f.append(finding("ssh_empty_passwords", "ssh", "CRITICAL", "SSH permits empty passwords",
                         "PermitEmptyPasswords is 'yes'.", {"PermitEmptyPasswords": "yes", "source": source},
                         "Set 'PermitEmptyPasswords no' immediately.", ver, confidence=0.95,
                         resource="sshd:permitemptypasswords", requires_approval=True,
                         why="Any account without a password becomes remotely accessible."))
    try:
        tries = int(v("maxauthtries", "6"))
    except ValueError:
        tries = 6
    if tries > 6:
        f.append(finding("ssh_max_auth_tries", "ssh", "LOW", "SSH MaxAuthTries is high",
                         f"MaxAuthTries={tries} allows many guesses per connection.", {"MaxAuthTries": tries},
                         "Consider MaxAuthTries 4.", "sshd -T | grep maxauthtries", confidence=0.9,
                         resource="sshd:maxauthtries"))
    if v("x11forwarding", "no") == "yes":
        f.append(finding("ssh_x11_forwarding", "ssh", "LOW", "SSH X11 forwarding enabled",
                         "X11Forwarding is 'yes'.", {"X11Forwarding": "yes"},
                         "Disable X11Forwarding unless users need remote GUI apps.",
                         "sshd -T | grep x11forwarding", confidence=0.9, resource="sshd:x11forwarding"))
    return f


def authorized_keys_summary():
    """Counts only - key material is never read beyond counting non-comment lines."""
    out = []
    for u in pwd.getpwall():
        p = os.path.join(u.pw_dir, ".ssh", "authorized_keys")
        try:
            with open(p) as fh:
                n = sum(1 for l in fh if l.strip() and not l.startswith("#"))
            out.append({"user": u.pw_name, "keys": n})
        except OSError:
            continue
    return out


class SSHCheck(SecurityCheck):
    name, category = "ssh", "ssh"
    requirements = ("openssh-server",)

    def is_supported(self, ctx):
        if ctx.reg.has("sshd") or os.path.exists(CONFIG):
            return True, None
        return False, "OpenSSH server not installed"

    def run(self, ctx):
        conns, _ = nt.connections()
        listen = [c for c in nt.listening(conns)
                  if c["proto"].startswith("tcp") and (c["process"] == "sshd" or c["localPort"] == 22)]
        running = sm.is_active(ctx.reg, ctx.os_info, ["ssh", "sshd"], ["sshd"])
        exposed = any(nt.is_wildcard(c["localAddress"]) for c in listen)
        opts, source = effective_config(ctx.reg)
        data = {"installed": True, "running": running,
                "listening": [{"address": c["localAddress"], "port": c["localPort"]} for c in listen],
                "exposedAllInterfaces": exposed, "configSource": source, "authorizedKeys": authorized_keys_summary()}
        if opts is None:
            return result(self.name, "WARN", data, errors=["sshd configuration not readable (run agent as root)"])
        keys = ("permitrootlogin", "passwordauthentication", "permitemptypasswords", "pubkeyauthentication",
                "maxauthtries", "x11forwarding", "port", "listenaddress")
        data["config"] = {k: opts.get(k) for k in keys}
        findings = evaluate(opts, source, exposed) if (running or listen) else []
        if not (running or listen):
            data["note"] = "sshd installed but not running; configuration not scored"
        if exposed:
            findings.append(finding("ssh_exposed", "network", "INFO", "SSH is reachable on all interfaces",
                                    "sshd listens on a wildcard address. Review whether this exposure is intentional.",
                                    {"listening": data["listening"]},
                                    "Restrict with ListenAddress or firewall rules if remote access is not needed.",
                                    "ss -tlnp | grep ssh", confidence=0.95, resource="sshd:exposed"))
        return result(self.name, status_from_findings(findings), data, findings)
