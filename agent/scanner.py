"""Scan engine (spec §56-57): runs a scan type's checks sequentially with progress callbacks and a
global timeout, isolating failures per check."""
import time
import uuid

from collectors import cpu, disk, memory, network, packages, process, services, system
from security.registry import CHECKS, SCAN_TYPES
from util import now_iso, result

COLLECTORS = {"system": system.collect, "cpu": cpu.collect, "memory": memory.collect, "disk": disk.collect,
              "network": network.collect, "processes": process.collect, "services": services.collect,
              "packages": packages.collect}


def _run_collector(name, ctx):
    t0 = time.monotonic()
    try:
        out = COLLECTORS[name](ctx)
    except Exception as e:  # noqa: BLE001 - one collector must never crash a scan
        out = result(name, "ERROR", errors=[f"{type(e).__name__}: {e}"])
    out["category"] = "health" if name not in ("network", "processes", "packages") else name
    out["durationMs"] = int((time.monotonic() - t0) * 1000)
    return out


def run_scan(ctx, scan_type="QUICK", scan_id=None, progress=None, skip_slow=False):
    if scan_type not in SCAN_TYPES:
        raise ValueError(f"unknown scan type {scan_type}")
    items = SCAN_TYPES[scan_type]
    if skip_slow:
        items = [i for i in items if i.startswith("collector:") or not CHECKS[i].slow]
    scan = {"scanId": scan_id or str(uuid.uuid4()), "type": scan_type, "status": "RUNNING",
            "startedAt": now_iso(), "checksTotal": len(items), "checksCompleted": 0, "checks": []}
    deadline = time.monotonic() + ctx.cfg["agent"]["scan_timeout"]
    for i, item in enumerate(items):
        if time.monotonic() > deadline:
            scan["checks"].append(result(item, "ERROR", errors=["scan timeout reached; check skipped"]))
            continue
        if item.startswith("collector:"):
            out = _run_collector(item.split(":", 1)[1], ctx)
        else:
            out = CHECKS[item].execute(ctx)
        scan["checks"].append(out)
        scan["checksCompleted"] = i + 1
        if progress:
            progress(scan, out)
    scan["findings"] = [f for c in scan["checks"] for f in c["findings"]]
    scan["completedAt"] = now_iso()
    scan["status"] = "COMPLETED" if not any(c["status"] == "ERROR" for c in scan["checks"]) else "COMPLETED_WITH_ERRORS"
    scan["summary"] = summarize(scan)
    return scan


def summarize(scan):
    sev = {}
    for f in scan["findings"]:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    st = {}
    for c in scan["checks"]:
        st[c["status"]] = st.get(c["status"], 0) + 1
    return {"findingsBySeverity": sev, "checksByStatus": st, "findings": len(scan["findings"])}
