"""Memory collector (spec §10 Memory)."""
import psutil

from models.schemas import finding
from util import result, status_from_findings


def collect(ctx):
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    data = {"total": vm.total, "used": vm.used, "available": vm.available, "free": vm.free,
            "cached": getattr(vm, "cached", 0), "buffers": getattr(vm, "buffers", 0), "percent": vm.percent,
            "swapTotal": sw.total, "swapUsed": sw.used, "swapPercent": sw.percent}
    th = ctx.cfg["thresholds"]
    findings = []
    if vm.percent >= th["memory_high"]:
        findings.append(finding("memory_pressure", "health", "MEDIUM", "High memory usage",
                                f"Memory usage is {vm.percent}% (threshold {th['memory_high']}%).",
                                {"percent": vm.percent, "availableBytes": vm.available},
                                "Identify the largest memory consumers.", "ps -eo pid,comm,%mem --sort=-%mem | head",
                                confidence=0.9, resource="memory"))
    if sw.total and sw.percent >= th["swap_high"]:
        findings.append(finding("swap_pressure", "health", "LOW", "High swap usage",
                                f"Swap usage is {sw.percent}%.", {"swapPercent": sw.percent},
                                "Sustained swapping degrades performance; review memory sizing.", "free -h; vmstat 1 5",
                                confidence=0.85, resource="swap"))
    return result("memory", status_from_findings(findings), data, findings)
