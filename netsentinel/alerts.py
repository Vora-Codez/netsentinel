"""Alert creation, de-duplication, storage and the SIEM-friendly JSONL feed."""
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import knowledge

MAX_ALERT_ROWS = 5000
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 3


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _legacy_rule_id(rule_name):
    for rid, info in knowledge.RULES.items():
        if info["name"] == rule_name:
            return rid
    return ""


class AlertManager:
    def __init__(self, db, settings, log_dir):
        self.db, self.settings = db, settings
        self.log_path = Path(log_dir) / "alerts.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._recent = {}
        self._lock = threading.Lock()
        self._inserts = 0

    def raise_alert(self, rule_id, src, dst, description, *, severity=None, now=None,
                    source="live", cooldown=None):
        """Create an alert, or bump the counter on an identical recent one.
        Returns the alert dict if a NEW row was created, else None."""
        info = knowledge.rule_info(rule_id)
        severity = severity or info["severity"]
        now = now if now is not None else time.time()
        key = (rule_id, src, dst, source)
        if cooldown is None:
            cooldown = self.settings.get("alert_cooldown")
        ts = utcnow()
        with self._lock:
            prev = self._recent.get(key)
            if prev and 0 <= now - prev[1] < cooldown:
                self.db.execute("UPDATE alerts SET count = count + 1, last_seen = ? WHERE id = ?", (ts, prev[0]))
                return None
            cur = self.db.execute(
                """INSERT INTO alerts (rule_id, rule_name, severity, mitre_id, src_ip, dst_ip,
                   description, timestamp, last_seen, count, source) VALUES (?,?,?,?,?,?,?,?,?,1,?)""",
                (rule_id, info["name"], severity, info["mitre"], src, dst, description, ts, ts, source))
            alert_id = cur.lastrowid
            self._recent[key] = (alert_id, now)
            self._inserts += 1
            if len(self._recent) > 5000:
                self._recent = dict(list(self._recent.items())[-2500:])
            if self._inserts % 100 == 0:
                self.db.execute("DELETE FROM alerts WHERE id <= (SELECT MAX(id) FROM alerts) - ?", (MAX_ALERT_ROWS,))
        record = {"id": alert_id, "rule_id": rule_id, "rule_name": info["name"], "severity": severity,
                  "mitre_id": info["mitre"], "src_ip": src, "dst_ip": dst, "description": description,
                  "timestamp": ts, "source": source}
        if source == "live":                       # never pollute the SIEM feed with demo data
            self._append_jsonl(record)
        return record

    def _append_jsonl(self, record):
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > LOG_MAX_BYTES:
                for i in range(LOG_BACKUPS, 0, -1):
                    src = self.log_path.with_suffix(f".jsonl.{i - 1}" if i > 1 else ".jsonl")
                    dst = self.log_path.with_suffix(f".jsonl.{i}")
                    if src.exists():
                        os.replace(src, dst)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass

    def list(self, *, since_id=0, limit=200, severity="all", source="all", status="all"):
        where, params = ["id > ?"], [int(since_id)]
        if severity in ("high", "medium", "low"):
            where.append("severity = ?"); params.append(severity)
        if source in ("live", "simulation"):
            where.append("COALESCE(source,'live') = ?"); params.append(source)
        if status == "open":
            where.append("reviewed = 0")
        elif status == "reviewed":
            where.append("reviewed = 1")
        params.append(max(1, min(int(limit), 1000)))
        rows = self.db.query(f"SELECT * FROM alerts WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?", params)
        return [self._enrich(r) for r in rows]

    @staticmethod
    def _enrich(row):
        rid = row.get("rule_id") or _legacy_rule_id(row.get("rule_name", ""))
        info = knowledge.rule_info(rid)
        row.update(rule_id=rid, title=info["title"], meaning=info["meaning"], action=info["action"],
                   count=row.get("count") or 1, source=row.get("source") or "live")
        row["last_seen"] = row.get("last_seen") or row["timestamp"]
        return row

    def counts(self):
        rows = self.db.query("""SELECT severity, COALESCE(source,'live') AS source, reviewed, COUNT(*) AS n
                                FROM alerts GROUP BY severity, COALESCE(source,'live'), reviewed""")
        out = {"total": 0, "open": 0, "open_high": 0, "open_medium": 0, "open_low": 0,
               "live_open": 0, "simulation_open": 0}
        for r in rows:
            out["total"] += r["n"]
            if not r["reviewed"]:
                out["open"] += r["n"]
                out[f"open_{r['severity']}"] = out.get(f"open_{r['severity']}", 0) + r["n"]
                out[f"{r['source']}_open"] = out.get(f"{r['source']}_open", 0) + r["n"]
        return out

    def set_reviewed(self, alert_id, reviewed=True):
        return self.db.execute("UPDATE alerts SET reviewed = ? WHERE id = ?",
                               (1 if reviewed else 0, alert_id)).rowcount > 0

    def review_all(self):
        return self.db.execute("UPDATE alerts SET reviewed = 1 WHERE reviewed = 0").rowcount

    def clear(self, source="all"):
        with self._lock:
            if source in ("live", "simulation"):
                n = self.db.execute("DELETE FROM alerts WHERE COALESCE(source,'live') = ?", (source,)).rowcount
            else:
                n = self.db.execute("DELETE FROM alerts").rowcount
            self._recent.clear()
        return n
