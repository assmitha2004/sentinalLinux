"""Fast, cheap metric sample for the 5-second loop (spec §68: no expensive work here)."""
import os
import time

import psutil

from collectors.disk import PSEUDO_FS

_last_net = {"t": None, "rx": 0, "tx": 0}


def sample():
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    net = psutil.net_io_counters()
    now = time.time()
    rx_rate = tx_rate = None
    if _last_net["t"]:
        dt = max(now - _last_net["t"], 1e-3)
        rx_rate = max(0, (net.bytes_recv - _last_net["rx"]) / dt)
        tx_rate = max(0, (net.bytes_sent - _last_net["tx"]) / dt)
    _last_net.update(t=now, rx=net.bytes_recv, tx=net.bytes_sent)
    disks = []
    for p in psutil.disk_partitions(all=False):
        if p.fstype in PSEUDO_FS:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except OSError:
            continue
        disks.append({"mount": p.mountpoint, "total": u.total, "used": u.used, "percent": u.percent})
    load = os.getloadavg()
    return {
        "cpu": {"usage": psutil.cpu_percent(interval=None), "logical": psutil.cpu_count() or 1},
        "memory": {"total": vm.total, "used": vm.total - vm.available, "percent": vm.percent,
                   "swapPercent": sw.percent},
        "disk": disks,
        "load": {"load1": load[0], "load5": load[1], "load15": load[2]},
        "network": {"rxBytes": net.bytes_recv, "txBytes": net.bytes_sent,
                    "rxRate": rx_rate, "txRate": tx_rate},
        "processCount": len(psutil.pids()),
        "uptimeSeconds": int(now - psutil.boot_time()),
    }
