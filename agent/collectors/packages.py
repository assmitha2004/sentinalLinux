"""Package inventory (spec §25) via the platform layer."""
from bossplatform import package_manager as pm
from util import not_supported, result


def collect(ctx):
    manager, pkgs, err = pm.list_packages(ctx.reg)
    if pkgs is None:
        return not_supported("packages", err or "package manager unavailable", ["dpkg-query or rpm"])
    broken = [p for p in pkgs if p.get("status") and not p["status"].startswith("ii")]
    return result("packages", "PASS", {"manager": manager, "count": len(pkgs), "packages": pkgs,
                                       "notFullyInstalled": broken[:100]})
