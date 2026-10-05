"""Disk collector (spec §10 Disk) with configurable WARN/HIGH/CRITICAL thresholds."""
import psutil

from models.schemas import finding
from util import result, status_from_findings

PSEUDO_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "devpts",
             "mqueue", "hugetlbfs", "debugfs", "tracefs", "securityfs", "pstore", "bpf", "configfs",
             "fusectl", "autofs", "efivarfs", "ramfs", "nsfs"}


def classify(percent, th):
    if percent >= th["critical"]:
        return "CRITICAL"
    if percent >= th["high"]:
        return "HIGH"
    if percent >= th["warn"]:
        return "MEDIUM"
    return None


def collect(ctx):
    th = ctx.cfg["thresholds"]["disk"]
    fs, findings, errors, seen = [], [], [], set()
    for part in psutil.disk_partitions(all=False):
        if part.fstype in PSEUDO_FS or part.device in seen:
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
        except OSError as e:
            errors.append(f"{part.mountpoint}: {e}")
            continue
        seen.add(part.device)
        fs.append({"mount": part.mountpoint, "device": part.device, "fstype": part.fstype,
                   "total": u.total, "used": u.used, "free": u.free, "percent": u.percent})
        sev = classify(u.percent, th)
        if sev:
            findings.append(finding("disk_usage", "health", sev, f"Filesystem {part.mountpoint} is {u.percent}% full",
                                    f"{part.mountpoint} ({part.device}) has {u.free // (1024**2)} MiB free.",
                                    {"mount": part.mountpoint, "percent": u.percent, "freeBytes": u.free},
                                    "Remove or archive unneeded data, rotate logs, or extend the filesystem.",
                                    f"df -h {part.mountpoint}", confidence=0.95, resource=part.mountpoint,
                                    why="A full filesystem can stop logging, break updates and crash services."))
    try:
        io = psutil.disk_io_counters()
        io = {"readBytes": io.read_bytes, "writeBytes": io.write_bytes} if io else None
    except OSError:
        io = None
    return result("disk", status_from_findings(findings), {"filesystems": fs, "io": io}, findings, errors)
