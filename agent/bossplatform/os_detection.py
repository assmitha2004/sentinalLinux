"""OS / distribution detection. Reads /etc/os-release (and fallbacks) at runtime; nothing about
BOSS 10 is hard-coded beyond the strings used to *recognise* it."""
import os
import platform
import socket

OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
BOSS_MARKERS = ("boss",)  # matched case-insensitively against ID / ID_LIKE / NAME


def parse_os_release(text):
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _read_first(paths):
    for p in paths:
        try:
            with open(p) as fh:
                return fh.read()
        except OSError:
            continue
    return ""


def detect_init_system():
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    try:
        with open("/proc/1/comm") as fh:
            comm = fh.read().strip()
        return comm or "unknown"
    except OSError:
        return "unknown"


def is_boss(info):
    hay = " ".join(info.get(k, "") for k in ("ID", "ID_LIKE", "NAME", "PRETTY_NAME")).lower()
    return any(m in hay for m in BOSS_MARKERS)


def detect_os(os_release_text=None):
    info = parse_os_release(os_release_text if os_release_text is not None else _read_first(OS_RELEASE_FILES))
    debian_version = (_read_first(("/etc/debian_version",)) or "").strip() or None
    boss = is_boss(info)
    version = info.get("VERSION_ID") or (info.get("VERSION", "").split(" ")[0] or None)
    uname = platform.uname()
    return {
        "distribution": "BOSS" if boss else (info.get("NAME") or "unknown"),
        "id": info.get("ID", "unknown"),
        "idLike": info.get("ID_LIKE", ""),
        "prettyName": info.get("PRETTY_NAME", ""),
        "version": version,
        "codename": info.get("VERSION_CODENAME") or None,
        "debianVersion": debian_version,
        "isBoss": boss,
        "isBoss10": bool(boss and version and str(version).split(".")[0] == "10"),
        "kernel": uname.release,
        "architecture": uname.machine,
        "hostname": socket.gethostname(),
        "initSystem": detect_init_system(),
    }
