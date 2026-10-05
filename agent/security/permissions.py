"""World-writable files and sensitive-file permissions (spec §17, §22)."""
import os
import stat

from models.schemas import finding
from util import result, safe_walk, status_from_findings

from .base import SecurityCheck

SENSITIVE = {  # path: (max mode, expected owner uid)
    "/etc/passwd": (0o644, 0), "/etc/group": (0o644, 0), "/etc/shadow": (0o640, 0), "/etc/gshadow": (0o640, 0),
    "/etc/sudoers": (0o440, 0), "/etc/ssh/sshd_config": (0o644, 0), "/etc/crontab": (0o644, 0),
}
UNIT_DIRS = ("/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/")


def kind_of(path, st):
    if stat.S_ISDIR(st.st_mode):
        return "directory"
    if path.startswith(UNIT_DIRS) and path.endswith((".service", ".timer", ".socket")):
        return "service"
    if st.st_mode & 0o111:
        return "executable"
    if path.startswith("/etc/"):
        return "config"
    return "file"


SEVERITY = {"service": "HIGH", "executable": "HIGH", "config": "HIGH", "directory": "MEDIUM", "file": "LOW"}


def world_writable(roots, excludes, limit=500):
    hits = []
    for path, st in safe_walk(roots, excludes):
        if stat.S_ISLNK(st.st_mode) or not st.st_mode & stat.S_IWOTH:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
            continue  # sticky dirs like /var/tmp are intentionally world-writable
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            continue
        hits.append({"path": path, "kind": kind_of(path, st), "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid})
        if len(hits) >= limit:
            break
    return hits


def sensitive_files():
    out = []
    for path, (maxmode, uid) in SENSITIVE.items():
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = st.st_mode & 0o777
        if mode & ~maxmode or st.st_uid != uid:
            out.append({"path": path, "mode": oct(mode), "expectedMax": oct(maxmode), "uid": st.st_uid})
    return out


class PermissionsCheck(SecurityCheck):
    name, category, slow = "permissions", "permissions", True

    def run(self, ctx):
        p = ctx.cfg["paths"]
        hits = world_writable(p["writable_roots"], p["writable_excludes"])
        findings = []
        for h in hits:
            findings.append(finding(f"world_writable_{h['kind']}", "permissions", SEVERITY[h["kind"]],
                                    f"World-writable {h['kind']}: {h['path']}",
                                    f"{h['path']} has mode {h['mode']}; any local user can modify it.", h,
                                    "Remove world-write permission (chmod o-w) after confirming nothing depends on it.",
                                    f"stat -c '%A %U:%G %n' {h['path']}", confidence=0.95, resource=h["path"],
                                    requires_approval=True,
                                    why="Any local user or compromised service could alter this "
                                        f"{h['kind']} to execute code or change system behaviour."))
        for s in sensitive_files():
            findings.append(finding("sensitive_file_permissions", "permissions", "HIGH",
                                    f"Weak permissions on {s['path']}",
                                    f"{s['path']} has mode {s['mode']} (expected at most {s['expectedMax']}, owner root).",
                                    s, f"Restore permissions: chmod {s['expectedMax'][2:]} {s['path']}; chown root {s['path']}",
                                    f"stat -c '%a %U' {s['path']}", confidence=0.95, resource=s["path"],
                                    requires_approval=True))
        return result(self.name, status_from_findings(findings),
                      {"worldWritable": hits, "count": len(hits), "roots": p["writable_roots"],
                       "excludes": p["writable_excludes"]}, findings)
