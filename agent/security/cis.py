"""SCAP / CIS benchmark (spec §21). Runs `oscap xccdf eval` read-only (no --remediate) when tooling
AND content exist. Otherwise NOT_SUPPORTED - compliance is never fabricated."""
import os
import tempfile
import xml.etree.ElementTree as ET

from bossplatform import benchmark_tools as bt
from models.schemas import finding
from util import result, run

from .base import SecurityCheck

SEV = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "unknown": "LOW", "info": "INFO"}


def list_profiles(ds):
    r = run(["oscap", "info", "--profiles", ds], timeout=60)
    if not r:
        return []
    return [l.split(":", 1)[0].strip() for l in r.stdout.splitlines() if ":" in l]


def choose_profile(profiles, preferred=None):
    if preferred and preferred in profiles:
        return preferred
    for pat in ("cis_level1_server", "cis_level1", "cis", "standard", "anssi_np_nt28_minimal"):
        for p in profiles:
            if pat in p.lower():
                return p
    return profiles[0] if profiles else None


def parse_results(xml_path):
    tree = ET.parse(xml_path)  # namespace-agnostic: match on tag suffix
    titles = {}
    for rule in tree.iter():
        if rule.tag.endswith("}Rule") or rule.tag == "Rule":
            t = next((c.text for c in rule if c.tag.endswith("title")), None)
            titles[rule.get("id")] = t
    results = []
    for rr in tree.iter():
        if not (rr.tag.endswith("}rule-result") or rr.tag == "rule-result"):
            continue
        res = next((c.text for c in rr if c.tag.endswith("result")), None)
        results.append({"id": rr.get("idref"), "title": titles.get(rr.get("idref")), "result": res,
                        "severity": rr.get("severity", "unknown")})
    return results


class CISCheck(SecurityCheck):
    name, category, slow = "benchmark", "benchmark", True
    requirements = ("oscap (OpenSCAP)", "SCAP datastream content for this OS")

    def is_supported(self, ctx):
        if not ctx.reg.has("oscap"):
            return False, "Required benchmark tooling not available (oscap not installed)"
        if not bt.find_datastreams(ctx.cfg.get("benchmark", {}).get("content_dirs", [])):
            return False, "Required benchmark content not available (no SCAP datastream found)"
        return True, None

    def run(self, ctx):
        bcfg = ctx.cfg.get("benchmark", {})
        streams = bt.find_datastreams(bcfg.get("content_dirs", []))
        ds = bcfg.get("datastream") or bt.pick_datastream(streams, ctx.os_info)
        if not ds:
            return result(self.name, "NOT_SUPPORTED", {"available": streams[:20]}, available=False,
                          reason="No SCAP content matching this OS (BOSS/Debian) was found")
        profile = choose_profile(list_profiles(ds), bcfg.get("profile"))
        if not profile:
            return result(self.name, "ERROR", {"datastream": ds}, errors=["no profiles in datastream"])
        with tempfile.TemporaryDirectory(prefix="sentinel-oscap-") as td:
            out = os.path.join(td, "results.xml")
            r = run(["oscap", "xccdf", "eval", "--profile", profile, "--results", out, ds],
                    timeout=ctx.cfg["agent"]["scan_timeout"], ok_codes=(0, 2))  # 2 = some rules failed
            if r.code not in (0, 2) or not os.path.exists(out):
                return result(self.name, "ERROR", {"datastream": ds, "profile": profile},
                              errors=[r.reason or "oscap produced no results"])
            rules = parse_results(out)
        passed = [x for x in rules if x["result"] == "pass"]
        failed = [x for x in rules if x["result"] in ("fail", "error")]
        scored = len(passed) + len(failed)
        pct = round(100 * len(passed) / scored, 1) if scored else None
        findings = [finding("benchmark_rule_failed", "benchmark", SEV.get(f["severity"], "LOW"),
                            f"Benchmark rule failed: {f['title'] or f['id']}",
                            f"OpenSCAP rule {f['id']} returned '{f['result']}' under profile {profile}.", f,
                            "Review the rule's rationale in the SCAP content and remediate manually after testing.",
                            f"oscap xccdf eval --profile {profile} --rule {f['id']} {ds}", confidence=0.9,
                            resource=f["id"], requires_approval=True) for f in failed[:300]]
        data = {"datastream": ds, "profile": profile, "compliancePercent": pct, "passed": len(passed),
                "failed": len(failed), "notApplicable": sum(1 for x in rules if x["result"] == "notapplicable"),
                "total": len(rules), "failedRules": failed[:300]}
        status = "PASS" if pct is not None and pct >= 90 else "WARN" if pct is not None and pct >= 70 else "FAIL"
        return result(self.name, status, data, findings)
