"""Structured JSON logging (spec §67) with a redaction filter so secrets never reach logs."""
import json
import logging
import re
import sys
from datetime import datetime, timezone

SECRET_RE = re.compile(r"(?i)(token|secret|password|api[_-]?key|authorization|bearer)([\"'=:\s]+)([^\s\"',}]+)")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        msg = SECRET_RE.sub(r"\1\2[REDACTED]", record.getMessage())
        out = {"timestamp": datetime.now(timezone.utc).isoformat(), "level": record.levelname,
               "component": getattr(record, "component", record.name), "message": msg}
        for k in ("durationMs", "check", "status"):
            if hasattr(record, k):
                out[k] = getattr(record, k)
        if record.exc_info:
            out["error"] = self.formatException(record.exc_info).splitlines()[-1]
        return json.dumps(out)


def setup(level="INFO", file=None):
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.FileHandler(file) if file else logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(level.upper())
    logging.getLogger("urllib3").setLevel(logging.WARNING)


class _Adapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):  # merge per-call extra (merge_extra= only exists on py3.13+)
        kwargs["extra"] = {**self.extra, **kwargs.get("extra", {})}
        return msg, kwargs


def get(component):
    return _Adapter(logging.getLogger("sentinel"), {"component": component})
