"""Normalized finding (spec §87) and versioned payload envelope (spec §81)."""
import hashlib

from util import SEVERITIES, now_iso

SCHEMA_VERSION = "1.0"
AGENT_VERSION = "1.0.0"


def finding(type, category, severity, title, description, evidence, recommendation, verification,
            confidence=0.7, why=None, resource=None, requires_approval=False, verification_mode="READ-ONLY"):
    if severity not in SEVERITIES:
        raise ValueError(f"bad severity {severity}")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be 0..1")
    if not evidence:
        raise ValueError("every finding needs evidence")  # spec §54 evidence-first
    resource = resource or ""
    return {
        # Stable id: same issue on same resource -> same id, so the server can dedupe across scans.
        "id": hashlib.sha1(f"{type}|{resource}".encode()).hexdigest()[:16],
        "type": type, "category": category, "severity": severity, "title": title,
        "description": description, "whyItMatters": why or description,
        "evidence": evidence, "resource": resource, "confidence": round(confidence, 2),
        "recommendation": recommendation,
        "verification": {"mode": verification_mode, "command": verification},
        "requiresAdminApproval": requires_approval,
        "source": "sentinel-agent", "timestamp": now_iso(),
    }


def envelope(kind, host, body):
    return {"schemaVersion": SCHEMA_VERSION, "agentVersion": AGENT_VERSION, "kind": kind,
            "host": host, "timestamp": now_iso(), **body}
