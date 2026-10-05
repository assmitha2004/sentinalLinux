"""OS + uptime collector (spec §10 OS/Uptime)."""
import time

import psutil

from util import result


def collect(ctx):
    boot = psutil.boot_time()
    o = ctx.os_info
    return result("system", data={
        "hostname": o["hostname"], "distribution": o["distribution"], "version": o["version"],
        "codename": o["codename"], "prettyName": o["prettyName"], "kernel": o["kernel"],
        "architecture": o["architecture"], "initSystem": o["initSystem"], "isBoss10": o["isBoss10"],
        "bootTime": int(boot), "uptimeSeconds": int(time.time() - boot),
    })
