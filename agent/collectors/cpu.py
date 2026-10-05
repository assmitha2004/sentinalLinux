"""CPU collector (spec §10 CPU). Model/temperature are best-effort; absence is not an error."""
import os

import psutil

from models.schemas import finding
from util import read_text, result, status_from_findings


def _model():
    for line in (read_text("/proc/cpuinfo") or "").splitlines():
        if line.lower().startswith(("model name", "hardware", "cpu model")):
            return line.split(":", 1)[1].strip()
    return None


def _temperature():
    try:
        temps = psutil.sensors_temperatures()
    except (AttributeError, OSError):
        return None
    vals = [t.current for entries in temps.values() for t in entries if t.current]
    return max(vals) if vals else None


def collect(ctx, interval=0.5):
    per_core = psutil.cpu_percent(interval=interval, percpu=True)
    usage = round(sum(per_core) / len(per_core), 1) if per_core else 0.0
    load = os.getloadavg()
    freq = None
    try:
        f = psutil.cpu_freq()
        freq = round(f.current, 0) if f else None
    except (OSError, NotImplementedError):
        pass
    logical = psutil.cpu_count() or 1
    data = {"model": _model(), "physicalCores": psutil.cpu_count(logical=False), "logicalCpus": logical,
            "usagePercent": usage, "perCore": per_core, "load1": load[0], "load5": load[1], "load15": load[2],
            "frequencyMhz": freq, "temperatureC": _temperature()}
    findings = []
    hi = ctx.cfg["thresholds"]["cpu_high"]
    if usage >= hi:
        findings.append(finding("cpu_pressure", "health", "MEDIUM", "Sustained high CPU usage",
                                f"CPU usage is {usage}% (threshold {hi}%).", {"usagePercent": usage},
                                "Identify the top CPU consumers and confirm they are expected.",
                                "ps -eo pid,user,comm,%cpu --sort=-%cpu | head", confidence=0.9, resource="cpu"))
    if load[1] > logical * 2:
        findings.append(finding("load_pressure", "health", "MEDIUM", "System load well above CPU count",
                                f"5-minute load {load[1]:.2f} exceeds 2x the {logical} logical CPUs.",
                                {"load5": load[1], "logicalCpus": logical},
                                "Check for runaway processes or I/O wait.", "uptime; vmstat 1 5",
                                confidence=0.85, resource="load"))
    return result("cpu", status_from_findings(findings), data, findings)
