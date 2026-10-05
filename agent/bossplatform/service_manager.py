"""Service state abstraction. systemd if present; otherwise falls back to process-name matching."""
import psutil

from util import run


def list_services(reg, os_info):
    if os_info.get("initSystem") == "systemd" and reg.has("systemctl"):
        r = run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"],
                timeout=20)
        if not r:
            return "systemd", None, r.reason
        services = []
        for line in r.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                services.append({"name": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3],
                                 "description": parts[4] if len(parts) > 4 else ""})
        return "systemd", services, None
    return os_info.get("initSystem", "unknown"), None, "service enumeration requires systemd"


def failed_services(services):
    return [s for s in services or [] if s["active"] == "failed"]


def is_active(reg, os_info, unit_names, process_names=()):
    """True/False if determinable, None if unknown. Tries systemd units, then process names."""
    if os_info.get("initSystem") == "systemd" and reg.has("systemctl"):
        for u in unit_names:
            r = run(["systemctl", "is-active", u], timeout=5, ok_codes=(0, 3, 4))
            if r and r.stdout.strip() == "active":
                return True
        if not process_names:
            return False
    if process_names:
        names = set(process_names)
        try:
            return any(p.info["name"] in names for p in psutil.process_iter(["name"]))
        except psutil.Error:
            return None
    return None
