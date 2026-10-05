"""Independent schedules for metrics / snapshots / heartbeat / scans (spec §42). Scans run on one
worker thread so a long scan never blocks the metrics loop; only one scan runs at a time."""
import queue
import threading
import time

import logger
import metrics
from client import AuthError
from collectors import network, process, services, system
from scanner import run_scan

log = logger.get("scheduler")


class Agent:
    def __init__(self, ctx, client):
        self.ctx, self.client = ctx, client
        self.cfg = ctx.cfg["agent"]
        self.stop = threading.Event()
        self.scans = queue.Queue(maxsize=10)
        self.current_scan = None

    # ---- jobs ----
    def job_metrics(self):
        self.client.post(f"/hosts/{self.client.host_id}/metrics", metrics.sample())

    def job_snapshot(self):
        body = {"type": "snapshot", "data": {
            "system": system.collect(self.ctx)["data"],
            "network": network.collect(self.ctx)["data"],
            "processes": process.collect(self.ctx)["data"],
            "services": services.collect(self.ctx).get("data")}}
        self.client.post("/agent/events", body, queue=False)  # snapshots are disposable; don't queue

    def job_heartbeat(self):
        data = self.client.post("/agent/heartbeat", {
            "agentVersion": "1.0.0", "host": self.ctx.host_info(),
            "capabilities": self.ctx.capabilities()["summary"], "outbox": self.client.outbox.size(),
            "currentScan": self.current_scan}, queue=False)
        if data is None:
            return
        self.client.flush()
        for cmd in data.get("commands", []):
            if cmd.get("type") == "scan":
                self.enqueue_scan(cmd.get("scanType", "QUICK"), cmd.get("scanId"))

    def job_security(self):
        self.enqueue_scan("STANDARD", None, skip_slow=True)

    def job_full(self):
        self.enqueue_scan("FULL", None)

    def job_benchmark(self):
        self.enqueue_scan("BENCHMARK", None)

    def enqueue_scan(self, scan_type, scan_id, skip_slow=False):
        try:
            self.scans.put_nowait((scan_type, scan_id, skip_slow))
        except queue.Full:
            log.warning("scan queue full; dropping request")

    def scan_worker(self):
        while not self.stop.is_set():
            try:
                scan_type, scan_id, skip_slow = self.scans.get(timeout=1)
            except queue.Empty:
                continue
            self.current_scan = scan_type
            t0 = time.monotonic()

            def progress(scan, check):
                self.client.post("/agent/events", {"type": "scan_progress", "data": {
                    "scanId": scan["scanId"], "type": scan["type"], "check": check["check"],
                    "checksCompleted": scan["checksCompleted"], "checksTotal": scan["checksTotal"]}}, queue=False)

            try:
                scan = run_scan(self.ctx, scan_type, scan_id, progress, skip_slow=skip_slow)
                scan["capabilities"] = self.ctx.capabilities()["summary"]
                self.client.post("/agent/scan-results", scan)
                log.info(f"{scan_type} scan done: {scan['summary']['findings']} findings",
                         extra={"durationMs": int((time.monotonic() - t0) * 1000)})
            except AuthError:
                raise
            except Exception as e:  # noqa: BLE001
                log.error(f"scan {scan_type} failed: {e}")
                if scan_id:
                    self.client.post("/agent/events", {"type": "scan_failed",
                                                       "data": {"scanId": scan_id, "error": str(e)[:300]}})
            finally:
                self.current_scan = None

    # ---- loop ----
    def run(self):
        jobs = [(self.job_heartbeat, self.cfg["heartbeat_interval"]),
                (self.job_metrics, self.cfg["metrics_interval"]),
                (self.job_snapshot, self.cfg["process_interval"]),
                (self.job_security, self.cfg["security_scan_interval"]),
                (self.job_full, self.cfg["full_scan_interval"]),
                (self.job_benchmark, self.cfg["benchmark_interval"])]
        jobs = [(fn, iv) for fn, iv in jobs if iv and iv > 0]
        next_run = {fn: time.monotonic() for fn, _ in jobs}
        # Don't fire the expensive daily FULL scan immediately on every restart.
        if self.job_full in next_run:
            next_run[self.job_full] += 600
        if self.job_benchmark in next_run:
            next_run[self.job_benchmark] += 900
        worker = threading.Thread(target=self.scan_worker, name="scan-worker", daemon=True)
        worker.start()
        log.info("agent loop started")
        while not self.stop.is_set():
            now = time.monotonic()
            for fn, iv in jobs:
                if now >= next_run[fn]:
                    next_run[fn] = now + iv
                    try:
                        fn()
                    except AuthError as e:
                        log.error(f"{e}; re-enroll the agent (main.py enroll). Stopping.")
                        self.stop.set()
                    except Exception as e:  # noqa: BLE001 - keep the loop alive
                        log.error(f"job {fn.__name__} failed: {e}")
            self.stop.wait(max(0.2, min(next_run.values()) - time.monotonic()))
