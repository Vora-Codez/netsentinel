"""SQLite storage (one shared, lock-guarded connection). Packets/flows stay in memory."""
import sqlite3
import threading
from pathlib import Path

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, rule_name TEXT NOT NULL,
        severity TEXT NOT NULL, mitre_id TEXT, src_ip TEXT, dst_ip TEXT, description TEXT NOT NULL,
        timestamp TEXT NOT NULL, last_seen TEXT, count INTEGER DEFAULT 1,
        reviewed INTEGER DEFAULT 0, source TEXT DEFAULT 'live')""",
    """CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target TEXT NOT NULL, port INTEGER NOT NULL,
        state TEXT NOT NULL, service TEXT, risk TEXT, banner TEXT, timestamp TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS scan_runs (
        id TEXT PRIMARY KEY, targets TEXT, ports TEXT, started TEXT, finished TEXT, status TEXT,
        hosts_scanned INTEGER DEFAULT 0, hosts_up INTEGER DEFAULT 0, open_count INTEGER DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pw_hash TEXT NOT NULL, role TEXT NOT NULL, disabled INTEGER DEFAULT 0, created TEXT NOT NULL,
        last_login TEXT, session_epoch INTEGER DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT,
        action TEXT NOT NULL, detail TEXT, ip TEXT)""",
]
# columns added after v2 -> upgrade old databases in place
MIGRATIONS = {
    "alerts": {"rule_id": "TEXT", "last_seen": "TEXT", "count": "INTEGER DEFAULT 1",
               "source": "TEXT DEFAULT 'live'"},
    "scans": {"run_id": "TEXT", "service": "TEXT", "risk": "TEXT"},
}


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        self.conn.execute("PRAGMA synchronous=NORMAL")
        with self.lock:
            for ddl in SCHEMA:
                self.conn.execute(ddl)
            for table, cols in MIGRATIONS.items():
                have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
                for col, ddl in cols.items():
                    if col not in have:
                        self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
            self.conn.commit()

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def executemany(self, sql, rows):
        with self.lock:
            self.conn.executemany(sql, rows)
            self.conn.commit()

    def query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
