import os
import stat

from models.schemas import envelope, finding
from scanner import run_scan
from security.authentication import analyze as auth_analyze
from security.authentication import empty_password_accounts
from security.base import SecurityCheck
from security.c2 import ip_class, score
from security.cis import parse_results
from security.kernel import compliant
from security.permissions import world_writable
from security.ssh import evaluate, parse_config
from security.suid import classify

import pytest


# ---- SSH ----
def test_ssh_parse_first_value_wins_and_ignores_match():
    o = parse_config("PermitRootLogin no\nPermitRootLogin yes\nMatch User bob\n  PasswordAuthentication yes\n",
                     include_dir="/nonexistent")
    assert o["permitrootlogin"] == "no"
    assert "passwordauthentication" not in o


def test_ssh_spec_example_root_and_password_is_high():
    f = evaluate({"permitrootlogin": "yes", "passwordauthentication": "yes"}, "test", exposed=True)
    by = {x["type"]: x for x in f}
    assert by["ssh_root_login"]["severity"] == "HIGH"
    assert by["ssh_password_authentication"]["severity"] == "MEDIUM"
    assert all(x["requiresAdminApproval"] for x in f)
    assert by["ssh_root_login"]["verification"]["mode"] == "READ-ONLY"


def test_ssh_hardened_has_no_findings():
    f = evaluate({"permitrootlogin": "no", "passwordauthentication": "no", "permitemptypasswords": "no",
                  "maxauthtries": "4", "x11forwarding": "no"}, "test", exposed=True)
    assert f == []


# ---- SUID ----
def test_suid_standard_package_binary_is_not_flagged():
    assert classify("/usr/bin/passwd", "passwd")[0] == "INFO"


def test_suid_in_tmp_is_high_and_unknown_is_medium():
    assert classify("/tmp/x", None)[0] == "HIGH"
    assert classify("/usr/local/bin/weird", None)[0] == "MEDIUM"


# ---- permissions ----
def test_world_writable_detects_file_but_not_sticky_dir(tmp_path):
    f = tmp_path / "evil.sh"
    f.write_text("#!/bin/sh\n")
    os.chmod(f, 0o777)
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    hits = world_writable([str(tmp_path)], ())
    paths = {h["path"]: h for h in hits}
    assert str(f) in paths and paths[str(f)]["kind"] == "executable"
    assert str(sticky) not in paths


# ---- auth ----
def test_uid0_and_empty_password():
    users = [{"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "canLogin": True,
              "homeExists": False},
             {"name": "toor", "uid": 0, "gid": 0, "home": "/x", "shell": "/bin/sh", "canLogin": True,
              "homeExists": False}]
    f = auth_analyze(users, "root:$6$abc:1::::::\nguest::1::::::\n", {})
    types = [x["type"] for x in f]
    assert "uid0_account" in types and "empty_password" in types
    assert all("$6$" not in str(x) for x in f)  # hash never leaks into a finding
    assert empty_password_accounts("a:!:1\nb::1\n") == ["b"]


# ---- C2 ----
def test_external_ip_alone_is_only_observed():
    c = {"remoteAddress": "8.8.8.8", "remotePort": 443, "exe": "/usr/bin/curl", "process": "curl", "pid": 10}
    s, sig, level = score(c, 1, {4444}, set())
    assert level == "OBSERVED"


def test_temp_shell_to_backdoor_port_is_high_risk():
    c = {"remoteAddress": "203.0.113.5", "remotePort": 4444, "exe": "/tmp/x", "process": "bash", "pid": 10}
    assert score(c, 1, {4444}, set())[2] == "HIGH_RISK"


def test_confirmed_only_with_ioc():
    c = {"remoteAddress": "203.0.113.5", "remotePort": 443, "exe": "/usr/bin/x", "process": "x", "pid": 1}
    assert score(c, 1, set(), {"203.0.113.5"})[2] == "CONFIRMED_MALICIOUS"
    assert ip_class("10.0.0.1") == "private" and ip_class("1.1.1.1") == "public"


# ---- kernel ----
def test_kernel_compliance():
    assert compliant("2", "2") and not compliant("1", "2") and compliant("2", "1+") and not compliant("0", "1+")


# ---- CIS parse ----
def test_cis_parse(tmp_path):
    x = tmp_path / "r.xml"
    x.write_text('''<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
      <Rule id="r1"><title>Rule one</title></Rule><Rule id="r2"><title>Rule two</title></Rule>
      <TestResult><rule-result idref="r1" severity="high"><result>fail</result></rule-result>
      <rule-result idref="r2" severity="low"><result>pass</result></rule-result></TestResult></Benchmark>''')
    r = parse_results(str(x))
    assert {"id": "r1", "title": "Rule one", "result": "fail", "severity": "high"} in r
    assert len(r) == 2


def test_cis_not_supported_without_oscap(ctx):
    from security.registry import CHECKS
    if ctx.reg.has("oscap"):
        pytest.skip("oscap installed")
    r = CHECKS["benchmark"].execute(ctx)
    assert r["status"] == "NOT_SUPPORTED" and "compliancePercent" not in r["data"]


# ---- schema / engine ----
def test_finding_requires_evidence_and_valid_ranges():
    with pytest.raises(ValueError):
        finding("t", "c", "HIGH", "x", "d", {}, "r", "v")
    with pytest.raises(ValueError):
        finding("t", "c", "BAD", "x", "d", {"a": 1}, "r", "v")
    f = finding("t", "c", "HIGH", "x", "d", {"a": 1}, "r", "v", resource="p")
    assert f["id"] == finding("t", "c", "LOW", "y", "d", {"b": 2}, "r", "v", resource="p")["id"]
    env = envelope("scan", {"hostname": "h"}, {"x": 1})
    assert env["schemaVersion"] == "1.0" and env["agentVersion"]


def test_crashing_check_is_isolated(ctx):
    class Boom(SecurityCheck):
        name = "boom"

        def run(self, ctx):
            raise RuntimeError("kaboom")
    r = Boom().execute(ctx)
    assert r["status"] == "ERROR" and "kaboom" in r["errors"][0]


def test_unsupported_check_is_not_fail(ctx):
    class Nope(SecurityCheck):
        name = "nope"

        def is_supported(self, ctx):
            return False, "tool missing"
    r = Nope().execute(ctx)
    assert r["status"] == "NOT_SUPPORTED" and r["reason"] == "tool missing"


def test_quick_scan_end_to_end(ctx):
    seen = []
    scan = run_scan(ctx, "QUICK", progress=lambda s, c: seen.append(c["check"]))
    assert scan["checksCompleted"] == scan["checksTotal"] == len(seen)
    assert scan["status"].startswith("COMPLETED")
    for f in scan["findings"]:
        assert f["evidence"] and f["recommendation"] and f["verification"]["command"]
