"""Wires every component together. One Core per running app (tests make their own)."""
import os
import secrets
import time
from pathlib import Path

from . import paths
from .alerts import AlertManager
from .auth import AuthService
from .capture import CaptureManager
from .config import Settings
from .db import Database
from .detection import DetectionEngine
from .scanner import ScanManager
from .simulator import Simulator


class Core:
    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir) if data_dir else paths.data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        logs = self.data_dir / "logs"
        logs.mkdir(exist_ok=True)
        self.started = time.time()
        self.settings = Settings(self.data_dir / "settings.json")
        self.db = Database(self.data_dir / "netsentinel.db")
        self.auth = AuthService(self.db)
        self.secret = self._load_secret()
        self.alerts = AlertManager(self.db, self.settings, logs)
        self.engine = DetectionEngine(self.settings, self.alerts)
        self.capture = CaptureManager(self.settings, self.engine, logs)
        self.sim = Simulator(self.capture, self.engine)
        self.scans = ScanManager(self.db, self.settings, self.engine)

    def _load_secret(self):
        env = os.environ.get("NETSENTINEL_SECRET")
        if env:
            return env
        path = self.data_dir / "secret.key"
        if not path.exists():
            path.write_text(secrets.token_hex(32))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return path.read_text().strip()

    def health(self):
        c = self.alerts.counts()
        high, med, low, live = c["open_high"], c["open_medium"], c["open_low"], c.get("live_open", 0)
        if live and high:
            return {"level": "alert", "headline": "Needs attention", "detail": f"{high} high-severity alert(s) haven't been reviewed."}
        if live and med:
            return {"level": "warn", "headline": "Worth a look", "detail": f"{med} medium-severity alert(s) are waiting for review."}
        if live:
            return {"level": "ok", "headline": "Mostly quiet", "detail": f"{low} low-severity notice(s) to glance at."}
        if c.get("simulation_open", 0):
            return {"level": "demo", "headline": "Demo data on screen", "detail": "These alerts come from the simulator, not your network."}
        return {"level": "ok", "headline": "All quiet", "detail": "No open alerts."}

    def shutdown(self):
        try:
            self.sim.stop()
            self.capture.stop()
        finally:
            self.db.close()
