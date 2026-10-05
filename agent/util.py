"""Shared helpers: safe subprocess execution and the standard check-result envelope."""
import os
import shutil
import subprocess
from datetime import datetime, timezone

MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # cap any single command's captured output

STATUSES = ("PASS", "WARN", "FAIL", "ERROR", "NOT_SUPPORTED", "NOT_APPLICABLE")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Directories that must never be walked by filesystem checks.
VIRTUAL_FS = ("/proc", "/sys", "/dev", "/run")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def have(cmd):
    """True if an executable is on PATH (or in sbin dirs, which non-root PATHs often omit)."""
    if shutil.which(cmd):
        return True
    return any(os.access(os.path.join(d, cmd), os.X_OK) for d in ("/usr/sbin", "/sbin"))


def which(cmd):
    found = shutil.which(cmd)
    if found:
        return found
    for d in ("/usr/sbin", "/sbin"):
        p = os.path.join(d, cmd)
        if os.access(p, os.X_OK):
            return p
    return None


class CommandResult:
    def __init__(self, ok, stdout="", stderr="", code=None, reason=None):
        self.ok, self.stdout, self.stderr, self.code, self.reason = ok, stdout, stderr, code, reason

    def __bool__(self):
        return self.ok


def run(argv, timeout=15, ok_codes=(0,)):
    """Run a fixed argv list (never a shell string). Missing command / timeout / permission
    errors are returned as a failed CommandResult instead of raising."""
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    exe = which(argv[0])
    if not exe:
        return CommandResult(False, reason=f"command not found: {argv[0]}")
    try:
        p = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=timeout,
                           check=False, errors="replace", env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return CommandResult(False, reason=f"timeout after {timeout}s: {argv[0]}")
    except PermissionError:
        return CommandResult(False, reason=f"permission denied: {argv[0]}")
    except OSError as e:
        return CommandResult(False, reason=f"{argv[0]}: {e}")
    out = p.stdout[:MAX_OUTPUT_BYTES]
    return CommandResult(p.returncode in ok_codes, out, p.stderr[:4096], p.returncode,
                         None if p.returncode in ok_codes else f"exit {p.returncode}: {p.stderr.strip()[:200]}")


def result(check, status="PASS", data=None, findings=None, errors=None, requirements=None, available=True,
           reason=None):
    """Standard envelope every collector/check returns."""
    findings = findings or []
    sev = "INFO"
    for f in findings:
        if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[sev]:
            sev = f["severity"]
    out = {
        "check": check,
        "status": status,
        "severity": sev,
        "timestamp": now_iso(),
        "data": data or {},
        "findings": findings,
        "errors": errors or [],
        "capability": {"available": available, "requirements": requirements or []},
    }
    if reason:
        out["reason"] = reason
    return out


def not_supported(check, reason, requirements=None):
    return result(check, "NOT_SUPPORTED", available=False, requirements=requirements, reason=reason)


def status_from_findings(findings):
    if not findings:
        return "PASS"
    worst = max(SEVERITY_RANK[f["severity"]] for f in findings)
    return "FAIL" if worst >= SEVERITY_RANK["HIGH"] else "WARN" if worst >= SEVERITY_RANK["LOW"] else "PASS"


def read_text(path, limit=1024 * 1024):
    """Read a small text file; returns None on permission/missing errors."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


def safe_walk(roots, excludes=(), max_files=200000, max_depth=12):
    """Yield (path, lstat) for regular files and dirs under roots without following symlinks,
    never entering virtual filesystems or excluded prefixes, and stopping at max_files."""
    seen = 0
    for root in roots:
        if not os.path.isdir(root) or os.path.islink(root):
            continue
        # An explicitly requested root (e.g. /dev/shm) is allowed even if it sits under a virtual fs.
        blocked = tuple(b for b in (*VIRTUAL_FS, *excludes) if not root.startswith(b.rstrip("/") + "/")
                        and root != b)
        root_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda e: None):
            if dirpath.count("/") - root_depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames
                           if not os.path.join(dirpath, d).startswith(blocked)
                           and not os.path.ismount(os.path.join(dirpath, d))]
            for name in filenames + dirnames:
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                seen += 1
                if seen > max_files:
                    return
                yield p, st
