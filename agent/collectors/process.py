"""Process collector (spec §11). Flags suspicious processes with evidence; never kills anything."""
import os

import psutil

from models.schemas import finding
from util import result, status_from_findings

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
NORMAL_EXE_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "/snap/", "/nix/")
SUSPICIOUS_CMD = ("bash -i", "/dev/tcp/", "nc -e", "ncat -e", "socat exec", "base64 -d|", "curl|sh", "wget -qO-|sh",
                  "python -c 'import socket", "mkfifo /tmp/")
FIELDS = ["pid", "ppid", "name", "exe", "cmdline", "username", "cpu_percent", "memory_percent", "create_time",
          "status"]


def snapshot(top=60):
    """Return (all_procs_minimal, top_procs_detailed)."""
    procs = []
    for p in psutil.process_iter(FIELDS):
        i = p.info
        procs.append({
            "pid": i["pid"], "ppid": i["ppid"], "name": i["name"], "exe": i["exe"],
            "cmdline": " ".join(i["cmdline"] or [])[:512], "user": i["username"],
            "cpu": round(i["cpu_percent"] or 0, 1), "mem": round(i["memory_percent"] or 0, 2),
            "startTime": int(i["create_time"] or 0), "status": i["status"],
        })
    procs.sort(key=lambda x: (x["cpu"], x["mem"]), reverse=True)
    return procs, procs[:top]


def _deleted_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe").endswith(" (deleted)")
    except OSError:
        return False


def analyze(procs, th):
    findings = []
    self_pid = os.getpid()
    for p in procs:
        if p["pid"] == self_pid:
            continue
        exe, cmd = p["exe"] or "", (p["cmdline"] or "").replace("  ", " ")
        ev = {"pid": p["pid"], "name": p["name"], "user": p["user"], "exe": exe, "cmdline": cmd[:300]}
        if exe.startswith(TEMP_PREFIXES):
            findings.append(finding("process_from_temp", "process", "HIGH",
                                    f"Process '{p['name']}' runs from a temporary directory",
                                    f"PID {p['pid']} executes {exe}.", ev,
                                    "Inspect the binary (owner, hash, origin) before deciding whether to stop it. "
                                    "Do not kill blindly; collect evidence first.",
                                    f"ls -l {exe}; cat /proc/{p['pid']}/cmdline | tr '\\0' ' '",
                                    confidence=0.75, resource=f"pid:{p['pid']}:{exe}",
                                    why="Malware commonly drops payloads in world-writable temp directories.",
                                    requires_approval=True))
        if _deleted_exe(p["pid"]):
            findings.append(finding("process_deleted_exe", "process", "HIGH" if p["user"] == "root" else "MEDIUM",
                                    f"Process '{p['name']}' is running a deleted executable",
                                    f"The executable of PID {p['pid']} was removed from disk after start.", ev,
                                    "This is often benign after a package upgrade (restart the service). "
                                    "If no upgrade happened, investigate as possible tampering.",
                                    f"ls -l /proc/{p['pid']}/exe", confidence=0.5,
                                    resource=f"pid:{p['pid']}:deleted",
                                    why="Attackers delete their binaries to hide; upgrades cause the same signal."))
        if exe and p["user"] == "root" and not exe.startswith(NORMAL_EXE_PREFIXES) \
                and not exe.startswith(TEMP_PREFIXES):
            findings.append(finding("root_process_unusual_path", "process", "MEDIUM",
                                    f"Root process '{p['name']}' runs from an unusual path",
                                    f"{exe} is outside standard system binary directories.", ev,
                                    "Verify the binary's origin and package ownership.",
                                    f"dpkg -S {exe} || ls -l {exe}", confidence=0.5, resource=f"rootexe:{exe}"))
        low = cmd.lower()
        hit = next((s for s in SUSPICIOUS_CMD if s in low), None)
        if hit:
            findings.append(finding("suspicious_cmdline", "process", "HIGH",
                                    f"Suspicious command line in '{p['name']}'",
                                    f"Command line contains the pattern '{hit}', associated with reverse shells "
                                    "or download-and-execute.", {**ev, "pattern": hit},
                                    "Confirm who started this process and why.",
                                    f"ps -o pid,ppid,user,lstart,cmd -p {p['pid']}", confidence=0.6,
                                    resource=f"cmd:{p['pid']}:{hit}", requires_approval=True))
        if p["cpu"] >= th["process_cpu_high"]:
            findings.append(finding("process_high_cpu", "health", "LOW", f"'{p['name']}' uses {p['cpu']}% of a CPU core",
                                    "Single process with high CPU usage.", ev,
                                    "Confirm this workload is expected.", f"top -p {p['pid']}",
                                    confidence=0.9, resource=f"cpu:{p['name']}"))
        if p["mem"] >= th["process_mem_high"]:
            findings.append(finding("process_high_mem", "health", "LOW", f"'{p['name']}' uses {p['mem']}% memory",
                                    "Single process with high memory usage.", ev,
                                    "Confirm this workload is expected.", f"ps -o pid,rss,cmd -p {p['pid']}",
                                    confidence=0.9, resource=f"mem:{p['name']}"))
    return findings


def collect(ctx):
    procs, top = snapshot()
    findings = analyze(procs, ctx.cfg["thresholds"])
    root_count = sum(1 for p in procs if p["user"] == "root")
    return result("processes", status_from_findings(findings),
                  {"count": len(procs), "rootCount": root_count, "top": top}, findings)
