"""Service collector. Failed services become LOW health findings."""
from bossplatform import service_manager as sm
from models.schemas import finding
from util import not_supported, result, status_from_findings


def collect(ctx):
    init, services, err = sm.list_services(ctx.reg, ctx.os_info)
    if services is None:
        return not_supported("services", err, ["systemd"])
    failed = sm.failed_services(services)
    findings = [finding("service_failed", "health", "LOW", f"Service {s['name']} has failed",
                        f"systemd reports {s['name']} in failed state.", s,
                        "Inspect the unit logs and either fix or disable the unit.",
                        f"systemctl status {s['name']}; journalctl -u {s['name']} -n 50",
                        confidence=0.95, resource=s["name"]) for s in failed]
    running = [s for s in services if s["sub"] == "running"]
    return result("services", status_from_findings(findings),
                  {"init": init, "total": len(services), "running": len(running), "failed": len(failed),
                   "services": services[:400]}, findings)
