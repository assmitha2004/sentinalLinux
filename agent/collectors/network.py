"""Network collector (spec §12): interfaces, counters, connections, listening ports."""
from bossplatform import network_tools as nt
from util import result


def collect(ctx):
    conns, err = nt.connections()
    listen = nt.listening(conns)
    established = [c for c in conns if c["state"] == "ESTABLISHED"]
    external = [c for c in established if c["remoteAddress"] and not nt.is_loopback(c["remoteAddress"])]
    data = {
        "interfaces": nt.interfaces(),
        "listening": listen[:300],
        "established": established[:300],
        "counts": {"listening": len(listen), "established": len(established), "external": len(external),
                   "total": len(conns)},
        "pidVisibility": "full" if ctx.reg.summary(ctx.os_info)["isRoot"] else "partial (agent not root)",
    }
    return result("network", "PASS", data, errors=[err] if err else [])
