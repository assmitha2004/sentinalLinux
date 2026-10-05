"""Executables in temporary directories (spec §18). Nothing is ever deleted."""
import os
import stat
import time

import psutil

from models.schemas import finding
from util import result, safe_walk, status_from_findings

from .base import SecurityCheck

ELF_MAGIC = b"\x7fELF"


def file_kind(path):
    """'elf', 'script' (shebang) or None. Files with +x but neither header cannot be executed directly."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    if head == ELF_MAGIC:
        return "elf"
    if head[:2] == b"#!":
        return "script"
    return None


def running_exes():
    exes = {}
    for p in psutil.process_iter(["pid", "exe"]):
        if p.info["exe"]:
            exes.setdefault(p.info["exe"], []).append(p.info["pid"])
    return exes


class TempExecCheck(SecurityCheck):
    name, category = "temp_executables", "filesystem"

    def run(self, ctx):
        dirs = [d for d in ctx.cfg["paths"]["temp_dirs"] if os.path.isdir(d)]
        running = running_exes()
        now = time.time()
        items, findings = [], []
        for path, st in safe_walk(dirs, max_files=50000, max_depth=6):
            if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
                continue
            kind = file_kind(path)
            if kind is None and not st.st_mode & 0o6000:
                continue  # +x on a data file (e.g. copied node_modules) is not executable
            elf = kind == "elf"
            recent = now - st.st_mtime < 86400
            pids = running.get(path, [])
            item = {"path": path, "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid, "size": st.st_size,
                    "kind": kind, "modifiedHoursAgo": round((now - st.st_mtime) / 3600, 1), "runningPids": pids}
            items.append(item)
            sev = "HIGH" if pids else "MEDIUM" if elf else "LOW"
            reasons = [r for r, c in (("currently executing", pids), ("is an ELF binary", elf),
                                      ("modified in the last 24h", recent),
                                      ("SUID/SGID set", st.st_mode & 0o6000)) if c]
            findings.append(finding("temp_executable", "filesystem", "CRITICAL" if st.st_mode & 0o6000 else sev,
                                    f"Executable file in temporary directory: {path}",
                                    "Executable in temp location" + (": " + ", ".join(reasons) if reasons else "") + ".",
                                    item, "Determine who created it and why. Preserve a copy for analysis before any "
                                    "removal; do not delete blindly.", f"ls -la {path}; file {path}; sha256sum {path}",
                                    confidence=0.7 if pids or elf else 0.4, resource=path, requires_approval=True,
                                    why="Temporary directories are world-writable and a common malware staging area."))
        deleted = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                link = os.readlink(f"/proc/{p.info['pid']}/exe")
            except OSError:
                continue
            if link.endswith(" (deleted)") and link.startswith(tuple(d + "/" for d in dirs)):
                deleted.append({"pid": p.info["pid"], "name": p.info["name"], "exe": link})
        for d in deleted:
            findings.append(finding("temp_deleted_exe_running", "filesystem", "HIGH",
                                    f"Process running a deleted temp executable (PID {d['pid']})",
                                    "A process is executing a binary from a temp dir that has since been deleted.", d,
                                    "Investigate the process; the binary can be recovered from /proc/<pid>/exe.",
                                    f"ls -l /proc/{d['pid']}/exe", confidence=0.8, resource=f"deltemp:{d['pid']}",
                                    requires_approval=True))
        return result(self.name, status_from_findings(findings),
                      {"directories": dirs, "executables": items, "deletedRunning": deleted}, findings)
