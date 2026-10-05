"""Agent configuration: defaults <- YAML file <- environment variables (spec §47, §65)."""
import copy
import os

import yaml

DEFAULT_PATH = os.environ.get("SENTINEL_CONFIG", "/etc/sentinelai/agent.yaml")

DEFAULTS = {
    "server": {"url": "", "verify_tls": True, "ca_bundle": None, "timeout": 15},
    "agent": {
        "id": "",
        "state_dir": "/var/lib/sentinelai",
        "heartbeat_interval": 30,
        "metrics_interval": 5,
        "network_interval": 10,
        "process_interval": 10,
        "security_scan_interval": 300,
        "full_scan_interval": 86400,
        "benchmark_interval": 0,          # 0 = only on demand
        "command_poll_interval": 15,
        "queue_max_items": 5000,
        "scan_timeout": 900,
    },
    "logging": {"level": "INFO", "file": None},
    "thresholds": {
        "disk": {"warn": 80, "high": 90, "critical": 95},
        "cpu_high": 90, "memory_high": 90, "swap_high": 80,
        "process_cpu_high": 80, "process_mem_high": 30,
    },
    "paths": {
        "binaries": ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"],
        "suid_roots": ["/usr", "/bin", "/sbin", "/opt", "/home", "/var", "/etc", "/tmp", "/srv", "/root"],
        "writable_roots": ["/etc", "/usr", "/bin", "/sbin", "/lib", "/opt", "/var/lib", "/srv"],
        "writable_excludes": ["/var/lib/docker", "/var/lib/containers"],
        "temp_dirs": ["/tmp", "/var/tmp", "/dev/shm"],
        "hash_binaries": False,
    },
    "network": {
        "expected_listen_ports": [22, 53, 631],
        "suspicious_ports": [1337, 4444, 5555, 6666, 6667, 31337, 12345, 9001, 1080],
    },
}


def _merge(base, over):
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def _bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def load(path=DEFAULT_PATH):
    cfg = copy.deepcopy(DEFAULTS)
    if path and os.path.exists(path):
        with open(path) as fh:
            _merge(cfg, yaml.safe_load(fh) or {})
    env = os.environ
    if env.get("SENTINEL_SERVER_URL"):
        cfg["server"]["url"] = env["SENTINEL_SERVER_URL"]
    if "SENTINEL_VERIFY_TLS" in env:
        cfg["server"]["verify_tls"] = _bool(env["SENTINEL_VERIFY_TLS"])
    if env.get("SENTINEL_CA_BUNDLE"):
        cfg["server"]["ca_bundle"] = env["SENTINEL_CA_BUNDLE"]
    if env.get("SENTINEL_STATE_DIR"):
        cfg["agent"]["state_dir"] = env["SENTINEL_STATE_DIR"]
    if env.get("SENTINEL_LOG_LEVEL"):
        cfg["logging"]["level"] = env["SENTINEL_LOG_LEVEL"]
    # Secrets come only from the environment (EnvironmentFile in the systemd unit), never the YAML.
    cfg["enrollment_token"] = env.get("SENTINEL_AGENT_TOKEN", "")
    return cfg
