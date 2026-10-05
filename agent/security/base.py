"""Common interface for security checks (spec §86). A check that raises is converted to ERROR so
one broken check never takes down the agent (spec §44)."""
import time
import traceback

import logger
from util import not_supported, result

log = logger.get("checks")


class SecurityCheck:
    name = "base"
    category = "security"
    requirements = ()  # human-readable list of what the check needs
    slow = False

    def is_supported(self, ctx):
        """Return (True, None) or (False, reason)."""
        return True, None

    def run(self, ctx):
        raise NotImplementedError

    def execute(self, ctx):
        t0 = time.monotonic()
        try:
            ok, reason = self.is_supported(ctx)
            out = self.run(ctx) if ok else not_supported(self.name, reason, list(self.requirements))
        except Exception as e:  # noqa: BLE001 - isolation boundary by design
            log.error(f"check {self.name} crashed: {e}", extra={"check": self.name})
            out = result(self.name, "ERROR", errors=[f"{type(e).__name__}: {e}",
                                                     traceback.format_exc().splitlines()[-2][:200]])
        out["category"] = self.category
        out["durationMs"] = int((time.monotonic() - t0) * 1000)
        log.info(f"check {self.name} -> {out['status']}",
                 extra={"check": self.name, "status": out["status"], "durationMs": out["durationMs"]})
        return out
