"""Backend client with enrollment, credential storage and a bounded SQLite outbox (spec §34, §43)."""
import json
import os
import os
import sqlite3
import threading

import requests

import logger

log = logger.get("client")


class AuthError(Exception):
    pass


class Outbox:
    """Bounded persistent queue. When full, the oldest rows are dropped so disk usage stays capped."""

    def __init__(self, path, max_items=5000):
        self.max_items = max_items
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        os.chmod(path, 0o600)
        self.db.execute("CREATE TABLE IF NOT EXISTS q (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, body TEXT)")
        self.db.commit()

    def put(self, path, body):
        with self.lock:
            self.db.execute("INSERT INTO q (path, body) VALUES (?, ?)", (path, json.dumps(body)))
            n = self.db.execute("SELECT COUNT(*) FROM q").fetchone()[0]
            if n > self.max_items:
                self.db.execute("DELETE FROM q WHERE id IN (SELECT id FROM q ORDER BY id LIMIT ?)",
                                (n - self.max_items,))
            self.db.commit()

    def peek(self, n=50):
        with self.lock:
            return self.db.execute("SELECT id, path, body FROM q ORDER BY id LIMIT ?", (n,)).fetchall()

    def delete(self, row_id):
        with self.lock:
            self.db.execute("DELETE FROM q WHERE id = ?", (row_id,))
            self.db.commit()

    def size(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM q").fetchone()[0]


class Client:
    def __init__(self, cfg):
        s = cfg["server"]
        self.base = s["url"].rstrip("/") + "/api/v1"
        self.verify = s.get("ca_bundle") or s["verify_tls"]
        self.timeout = s["timeout"]
        self.state_dir = cfg["agent"]["state_dir"]
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        self.cred_path = os.path.join(self.state_dir, "credentials.json")
        self.outbox = Outbox(os.path.join(self.state_dir, "outbox.db"), cfg["agent"]["queue_max_items"])
        self.session = requests.Session()
        self.creds = self._load_creds()
        if s["url"].startswith("http://") and not s["url"].startswith(("http://localhost", "http://127.")):
            log.warning("server URL is plain HTTP; use HTTPS in production")

    # ---- credentials ----
    def _load_creds(self):
        try:
            with open(self.cred_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def enrolled(self):
        return bool(self.creds and self.creds.get("agentSecret"))

    def enroll(self, token, host_info, capabilities):
        r = self.session.post(f"{self.base}/hosts/register", json={"enrollmentToken": token, **host_info,
                                                                   "capabilities": capabilities},
                              timeout=self.timeout, verify=self.verify)
        if r.status_code != 201:
            raise AuthError(f"enrollment failed ({r.status_code}): {_err(r)}")
        data = r.json()["data"]
        creds = {"agentId": data["agentId"], "hostId": data["hostId"], "agentSecret": data["agentSecret"]}
        fd = os.open(self.cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(creds, fh)
        self.creds = creds
        return creds

    def _headers(self):
        if not self.enrolled():
            raise AuthError("agent not enrolled")
        return {"Authorization": f"Bearer {self.creds['agentSecret']}", "X-Agent-Id": self.creds["agentId"]}

    @property
    def host_id(self):
        return self.creds["hostId"]

    # ---- transport ----
    def _send(self, path, body):
        """Raises requests.ConnectionError on network/5xx so callers can queue. 4xx -> logged, returns None."""
        try:
            r = self.session.post(self.base + path, json=body, headers=self._headers(), timeout=self.timeout,
                                  verify=self.verify)
        except requests.Timeout as e:
            raise requests.ConnectionError(str(e)) from e
        if r.status_code in (401, 403):
            raise AuthError(f"server rejected agent credentials ({r.status_code})")
        if r.status_code >= 500 or r.status_code == 429:
            raise requests.ConnectionError(f"server error {r.status_code}")
        if r.status_code >= 400:
            log.error(f"POST {path} rejected {r.status_code}: {_err(r)}")
            return None
        return r.json().get("data")

    def post(self, path, body, queue=True):
        """POST; on network/5xx failure queue for retry (bounded). Returns response data or None."""
        try:
            return self._send(path, body)
        except requests.ConnectionError as e:
            if queue:
                self.outbox.put(path, body)
                log.warning(f"POST {path} failed ({str(e)[:80]}); queued (outbox={self.outbox.size()})")
            return None

    def flush(self, max_batch=50):
        """Replay queued items oldest-first; stop at the first network failure."""
        sent = 0
        for row_id, path, body in self.outbox.peek(max_batch):
            try:
                self._send(path, json.loads(body))
            except requests.ConnectionError:
                break
            self.outbox.delete(row_id)  # delivered, or permanently rejected (4xx) - either way done
            sent += 1
        return sent


def _err(r):
    try:
        return r.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        return r.text[:200]
