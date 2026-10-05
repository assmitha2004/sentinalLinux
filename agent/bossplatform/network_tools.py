"""Network inspection. psutil is the primary source (works without ss/ip); `ss` is used only to
attach process names when psutil can't see them without root."""
import socket

import psutil

KIND = {(socket.AF_INET, socket.SOCK_STREAM): "tcp", (socket.AF_INET6, socket.SOCK_STREAM): "tcp6",
        (socket.AF_INET, socket.SOCK_DGRAM): "udp", (socket.AF_INET6, socket.SOCK_DGRAM): "udp6"}


def interfaces():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io = psutil.net_io_counters(pernic=True)
    out = []
    for name, alist in addrs.items():
        st = stats.get(name)
        c = io.get(name)
        out.append({
            "name": name,
            "up": bool(st and st.isup),
            "speedMbps": st.speed if st else None,
            "mtu": st.mtu if st else None,
            "ipv4": [a.address for a in alist if a.family == socket.AF_INET],
            "ipv6": [a.address.split("%")[0] for a in alist if a.family == socket.AF_INET6],
            "mac": next((a.address for a in alist if a.family == psutil.AF_LINK), None),
            "rxBytes": c.bytes_recv if c else 0, "txBytes": c.bytes_sent if c else 0,
            "rxErrors": c.errin if c else 0, "txErrors": c.errout if c else 0,
        })
    return out


def connections():
    """Returns (list, error). Without root, other users' sockets may lack pid."""
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as e:
        return [], f"permission denied listing sockets: {e}"
    names = {}
    out = []
    for c in conns:
        pname = None
        if c.pid:
            if c.pid not in names:
                try:
                    p = psutil.Process(c.pid)
                    names[c.pid] = (p.name(), _safe(p.exe), _safe(p.username))
                except psutil.Error:
                    names[c.pid] = (None, None, None)
            pname = names[c.pid]
        out.append({
            "proto": KIND.get((c.family, c.type), "other"),
            "localAddress": c.laddr.ip if c.laddr else None, "localPort": c.laddr.port if c.laddr else None,
            "remoteAddress": c.raddr.ip if c.raddr else None, "remotePort": c.raddr.port if c.raddr else None,
            "state": c.status, "pid": c.pid,
            "process": pname[0] if pname else None, "exe": pname[1] if pname else None,
            "user": pname[2] if pname else None,
        })
    return out, None


def _safe(fn):
    try:
        return fn()
    except psutil.Error:
        return None


def listening(conns):
    return [c for c in conns if c["state"] == "LISTEN" or (c["proto"].startswith("udp") and not c["remoteAddress"])]


def is_loopback(addr):
    return bool(addr) and (addr.startswith("127.") or addr == "::1")


def is_wildcard(addr):
    return addr in ("0.0.0.0", "::", "*")
