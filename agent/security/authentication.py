"""Account & authentication posture (spec §15, §22). Shadow is read only to test for an EMPTY
password field; hashes are never stored, logged, or uploaded."""
import os
import stat

from collectors.users import list_users
from models.schemas import finding
from util import read_text, result, status_from_findings

from .base import SecurityCheck

SERVICE_UID_MAX = 999


def empty_password_accounts(shadow_text):
    out = []
    for line in (shadow_text or "").splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1] == "":
            out.append(parts[0])
    return out


def login_defs(text):
    vals = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                vals[parts[0]] = parts[1]
    return vals


def analyze(users, shadow_text, defs):
    f = []
    for u in users:
        if u["uid"] == 0 and u["name"] != "root":
            f.append(finding("uid0_account", "users", "CRITICAL", f"Account '{u['name']}' has UID 0",
                             "A non-root account with UID 0 has full root privileges.",
                             {"user": u["name"], "uid": 0, "shell": u["shell"]},
                             "Verify whether this account is legitimate; if not, investigate as possible compromise.",
                             "awk -F: '$3==0' /etc/passwd", confidence=0.9, resource=f"user:{u['name']}",
                             requires_approval=True,
                             why="Hidden UID-0 accounts are a classic persistence technique."))
        if 0 < u["uid"] <= SERVICE_UID_MAX and u["canLogin"] and u["name"] not in ("sync",):
            f.append(finding("service_account_shell", "users", "LOW",
                             f"System account '{u['name']}' has an interactive shell",
                             f"UID {u['uid']} uses {u['shell']}.",
                             {"user": u["name"], "uid": u["uid"], "shell": u["shell"]},
                             "If no one logs in as this account, set its shell to /usr/sbin/nologin.",
                             f"getent passwd {u['name']}", confidence=0.6, resource=f"shell:{u['name']}",
                             requires_approval=True))
        if u["canLogin"] and u["homeExists"] and u["uid"] >= 1000:
            try:
                mode = os.stat(u["home"]).st_mode
                if mode & stat.S_IWOTH:
                    f.append(finding("home_world_writable", "permissions", "MEDIUM",
                                     f"Home directory of '{u['name']}' is world-writable",
                                     f"{u['home']} mode {oct(mode & 0o777)}.",
                                     {"path": u["home"], "mode": oct(mode & 0o777)},
                                     "Restrict permissions (e.g. chmod 750).", f"stat -c '%a %U' {u['home']}",
                                     confidence=0.95, resource=u["home"], requires_approval=True))
            except OSError:
                pass
    for name in empty_password_accounts(shadow_text):
        f.append(finding("empty_password", "users", "HIGH", f"Account '{name}' has an empty password",
                         "The password field in /etc/shadow is empty.", {"user": name},
                         "Lock the account (passwd -l) or set a password.",
                         f"passwd -S {name}", confidence=0.95, resource=f"emptypw:{name}", requires_approval=True,
                         why="Accounts without passwords may be logged into without credentials."))
    maxd = defs.get("PASS_MAX_DAYS")
    if maxd and maxd.isdigit() and int(maxd) > 365:
        f.append(finding("password_max_days", "auth", "LOW", "No effective password expiry",
                         f"PASS_MAX_DAYS is {maxd} in /etc/login.defs.", {"PASS_MAX_DAYS": maxd},
                         "Align PASS_MAX_DAYS with your organisation's password policy.",
                         "grep ^PASS_ /etc/login.defs", confidence=0.9, resource="login.defs:PASS_MAX_DAYS"))
    return f


class AuthenticationCheck(SecurityCheck):
    name, category = "authentication", "users"

    def run(self, ctx):
        users = list_users()
        shadow = read_text("/etc/shadow")
        defs = login_defs(read_text("/etc/login.defs"))
        pam = read_text("/etc/pam.d/common-password") or read_text("/etc/pam.d/system-auth") or ""
        findings = analyze(users, shadow, defs)
        quality = "pam_pwquality" in pam or "pam_cracklib" in pam
        if pam and not quality:
            findings.append(finding("password_quality", "auth", "LOW", "No password complexity module configured",
                                    "Neither pam_pwquality nor pam_cracklib is referenced in the PAM password stack.",
                                    {"pamFileRead": True}, "Consider installing and configuring libpam-pwquality.",
                                    "grep -E 'pwquality|cracklib' /etc/pam.d/common-password",
                                    confidence=0.7, resource="pam:pwquality"))
        data = {"users": users, "loginCapable": [u["name"] for u in users if u["canLogin"]],
                "shadowReadable": shadow is not None,
                "passwordPolicy": {k: defs.get(k) for k in ("PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE",
                                                            "ENCRYPT_METHOD", "UMASK")},
                "pamPasswordQuality": quality}
        errors = [] if shadow is not None else ["/etc/shadow not readable; empty-password check skipped (needs root)"]
        return result(self.name, status_from_findings(findings), data, findings, errors)
