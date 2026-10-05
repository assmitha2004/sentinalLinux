"""SUID/SGID inventory (spec §16). A standard, package-owned SUID binary is inventoried, not flagged."""
import grp
import hashlib
import os
import pwd
import stat

from bossplatform import package_manager as pm
from models.schemas import finding
from util import result, safe_walk, status_from_findings

from .base import SecurityCheck

# Well-known SUID/SGID programs on Debian-family systems. Used only to lower suspicion.
KNOWN = {"su", "sudo", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "mount", "umount", "ping", "ping6",
         "pkexec", "fusermount", "fusermount3", "ntfs-3g", "crontab", "ssh-agent", "ssh-keysign", "expiry",
         "chage", "wall", "write", "dotlockfile", "unix_chkpwd", "pam_extrausers_chkpwd", "polkit-agent-helper-1",
         "dbus-daemon-launch-helper", "Xorg.wrap", "at", "bsd-write", "mlocate", "plocate", "staprun",
         "lxc-user-nic", "chrome-sandbox", "VBoxHeadless", "snap-confine", "traceroute6.iputils", "mount.nfs",
         "mount.cifs", "pppd", "exim4", "sg", "vmware-user-suid-wrapper", "Xorg", "utempter", "ssh-keysign"}
SUSPICIOUS_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")


def sha256(path, limit=64 * 1024 * 1024):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            read = 0
            while chunk := fh.read(1 << 20):
                h.update(chunk)
                read += len(chunk)
                if read > limit:
                    return None
        return h.hexdigest()
    except OSError:
        return None


def _name(fn, ident):
    try:
        return fn(ident)[0]
    except KeyError:
        return str(ident)


def classify(path, owner_pkg):
    """Return (risk, reasons)."""
    reasons = []
    base = os.path.basename(path)
    if path.startswith(SUSPICIOUS_DIRS):
        reasons.append("located in a user-writable or temporary location")
    if owner_pkg is None:
        reasons.append("not owned by any installed package")
    if base not in KNOWN:
        reasons.append("not a commonly expected SUID/SGID program")
    if path.startswith(SUSPICIOUS_DIRS):
        return "HIGH", reasons
    if owner_pkg is None and base not in KNOWN:
        return "MEDIUM", reasons
    if owner_pkg is None or base not in KNOWN:
        return "LOW", reasons
    return "INFO", reasons


class SUIDCheck(SecurityCheck):
    name, category, slow = "suid", "permissions", True

    def run(self, ctx):
        roots = ctx.cfg["paths"]["suid_roots"]
        items, findings = [], []
        for path, st in safe_walk(roots):
            if not stat.S_ISREG(st.st_mode) or not st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                continue
            owner_pkg = pm.owner_of(ctx.reg, path)
            risk, reasons = classify(path, owner_pkg)
            item = {"path": path, "owner": _name(pwd.getpwuid, st.st_uid), "group": _name(grp.getgrgid, st.st_gid),
                    "permissions": stat.filemode(st.st_mode), "suid": bool(st.st_mode & stat.S_ISUID),
                    "sgid": bool(st.st_mode & stat.S_ISGID), "package": owner_pkg, "risk": risk,
                    "hash": sha256(path) if risk != "INFO" else None}
            items.append(item)
            if risk != "INFO":
                findings.append(finding("unexpected_suid", "permissions", risk,
                                        f"Unexpected SUID/SGID executable: {path}",
                                        "Unexpected SUID executable detected: " + "; ".join(reasons) + ".",
                                        item, "Verify package ownership and whether this permission is required. "
                                        "If not required, remove the bit with chmod u-s,g-s after review.",
                                        f"stat {path}; dpkg -S {path}", confidence=0.6 if risk == "LOW" else 0.75,
                                        resource=path, requires_approval=True,
                                        why="SUID programs run with the owner's privileges; an unexpected one is a "
                                            "common privilege-escalation backdoor."))
        return result(self.name, status_from_findings(findings),
                      {"scannedRoots": roots, "count": len(items), "files": items}, findings)
