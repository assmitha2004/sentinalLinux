#!/usr/bin/env python3
"""SentinelAI agent CLI.

  main.py detect                 print OS + capability discovery (no server needed)
  main.py scan --type QUICK      run a scan locally and print JSON (no server needed)
  main.py enroll --token TOKEN   enroll with the backend (one time)
  main.py run                    run the agent loop (systemd ExecStart)
  main.py ping                   send one heartbeat to verify connectivity
"""
import argparse
import json
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
import logger  # noqa: E402
from capability_detector import Context  # noqa: E402

log = logger.get("main")


def cmd_detect(ctx, args):
    print(json.dumps(ctx.report(), indent=2))


def cmd_scan(ctx, args):
    from scanner import run_scan
    scan = run_scan(ctx, args.type, skip_slow=args.skip_slow)
    if args.summary:
        out = {"type": scan["type"], "status": scan["status"], "summary": scan["summary"],
               "checks": [{"check": c["check"], "status": c["status"], "findings": len(c["findings"]),
                           "reason": c.get("reason"), "errors": c["errors"], "ms": c.get("durationMs")}
                          for c in scan["checks"]],
               "findings": [{"severity": f["severity"], "title": f["title"]} for f in scan["findings"]]}
        print(json.dumps(out, indent=2))
    else:
        print(json.dumps(scan, indent=2, default=str))


def cmd_enroll(ctx, args):
    from client import Client
    token = args.token or ctx.cfg["enrollment_token"]
    if not token:
        sys.exit("No enrollment token: pass --token or set SENTINEL_AGENT_TOKEN")
    if not ctx.cfg["server"]["url"]:
        sys.exit("No server URL: set server.url in the config or SENTINEL_SERVER_URL")
    c = Client(ctx.cfg)
    creds = c.enroll(token, ctx.host_info(), ctx.capabilities()["summary"])
    print(f"Enrolled. agentId={creds['agentId']} hostId={creds['hostId']} "
          f"(credentials stored in {c.cred_path}, mode 0600)")


def cmd_ping(ctx, args):
    """Send one heartbeat; used by install.sh to verify connectivity and credentials."""
    from client import AuthError, Client
    c = Client(ctx.cfg)
    if not c.enrolled():
        sys.exit("not enrolled")
    try:
        data = c.post("/agent/heartbeat", {"agentVersion": "1.0.0", "host": ctx.host_info(),
                                           "capabilities": ctx.capabilities()["summary"]}, queue=False)
    except AuthError as e:
        sys.exit(f"heartbeat rejected: {e}")
    if data is None:
        sys.exit(f"heartbeat failed: cannot reach {ctx.cfg['server']['url']}")
    print(f"heartbeat OK (server time {data['serverTime']})")


def cmd_run(ctx, args):
    from client import Client
    from scheduler import Agent
    if not ctx.cfg["server"]["url"]:
        sys.exit("No server URL configured")
    c = Client(ctx.cfg)
    if not c.enrolled():
        token = ctx.cfg["enrollment_token"]
        if not token:
            sys.exit("Agent not enrolled and SENTINEL_AGENT_TOKEN not set")
        c.enroll(token, ctx.host_info(), ctx.capabilities()["summary"])
        log.info("enrolled using SENTINEL_AGENT_TOKEN")
    rep = ctx.report()
    log.info(f"starting on {rep['os']['distribution']} {rep['os']['version']} kernel {rep['os']['kernel']} "
             f"root={ctx.is_root}")
    if not ctx.os_info["isBoss10"]:
        log.warning("host is not BOSS 10; running in compatibility mode - results may differ")
    agent = Agent(ctx, c)
    signal.signal(signal.SIGTERM, lambda *_: agent.stop.set())
    signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
    agent.run()


def main(argv=None):
    p = argparse.ArgumentParser(prog="sentinel-agent")
    p.add_argument("--config", default=config.DEFAULT_PATH)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("detect")
    s = sub.add_parser("scan")
    s.add_argument("--type", default="QUICK", choices=["QUICK", "STANDARD", "FULL", "BENCHMARK", "NETWORK",
                                                       "PROCESS", "FILESYSTEM"])
    s.add_argument("--summary", action="store_true", help="print a compact summary instead of full JSON")
    s.add_argument("--skip-slow", action="store_true")
    e = sub.add_parser("enroll")
    e.add_argument("--token")
    e.add_argument("--server")
    sub.add_parser("run")
    sub.add_parser("ping")
    args = p.parse_args(argv)
    cfg = config.load(args.config)
    if getattr(args, "server", None):
        cfg["server"]["url"] = args.server
    logger.setup(cfg["logging"]["level"] if args.cmd == "run" else "WARNING", cfg["logging"]["file"])
    ctx = Context(cfg)
    {"detect": cmd_detect, "scan": cmd_scan, "enroll": cmd_enroll, "run": cmd_run, "ping": cmd_ping}[args.cmd](ctx, args)


if __name__ == "__main__":
    main()
