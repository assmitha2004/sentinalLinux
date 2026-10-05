"""Startup discovery (spec §4): OS + capability registry bundled into a context object."""
import os

from bossplatform.capabilities import CapabilityRegistry
from bossplatform.os_detection import detect_os
from util import read_text


class Context:
    def __init__(self, cfg):
        self.cfg = cfg
        self.os_info = detect_os()
        self.reg = CapabilityRegistry()
        self.is_root = os.geteuid() == 0

    def capabilities(self):
        return self.reg.to_dict(self.os_info)

    def host_info(self):
        o = self.os_info
        mid = (read_text("/etc/machine-id") or read_text("/var/lib/dbus/machine-id") or "").strip()[:64] or None
        return {"hostname": o["hostname"], "machineId": mid, "os": {k: o[k] for k in ("distribution", "id", "version", "codename",
                                                                      "prettyName", "debianVersion", "isBoss",
                                                                      "isBoss10", "initSystem")},
                "kernel": o["kernel"], "architecture": o["architecture"]}

    def report(self):
        caps = self.capabilities()
        return {"os": {k: self.os_info[k] for k in ("distribution", "version", "codename", "kernel", "architecture",
                                                     "initSystem", "isBoss10")},
                "capabilities": caps["summary"], "commands": caps["commands"]}
