"""User-editable detection/scanner settings, persisted as JSON and validated on every write."""
import ipaddress
import json
import threading
from pathlib import Path

DEFAULTS = {
    "port_scan_threshold": 15, "port_scan_window": 10,
    "sweep_threshold": 20, "sweep_threshold_web": 100, "sweep_window": 10,
    "beacon_min_hits": 5, "beacon_jitter_pct": 25,
    "exfil_mb": 50, "exfil_window": 60,
    "syn_flood_threshold": 200, "alert_cooldown": 60,
    "cleartext_alerts": True, "new_device_alerts": True,
    "malicious_ports": {"4444": "Metasploit default handler", "31337": "Back Orifice / classic backdoor",
                        "6666": "Common IRC botnet C2", "12345": "NetBus backdoor",
                        "1337": "Common 'leet' backdoor port"},
    "blacklist": {},
    "beacon_ignore_ports": [53, 123, 5353],
    "scan_timeout": 0.8, "scan_workers": 150,
    "capture_iface": "", "log_packets_jsonl": False,
    "session_idle_minutes": 30,
}
LIMITS = {
    "port_scan_threshold": (3, 1000), "port_scan_window": (1, 600),
    "sweep_threshold": (3, 5000), "sweep_threshold_web": (3, 20000), "sweep_window": (1, 600),
    "beacon_min_hits": (3, 50), "beacon_jitter_pct": (1, 90), "exfil_mb": (1, 100000),
    "exfil_window": (5, 3600), "syn_flood_threshold": (20, 100000), "alert_cooldown": (0, 86400),
    "scan_timeout": (0.1, 10), "scan_workers": (1, 500),
    "session_idle_minutes": (5, 1440),
}


def _valid_ip(s):
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _ports(vals):
    out = []
    for p in vals:
        try:
            pn = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= pn <= 65535:
            out.append(pn)
    return out


def clean(raw: dict) -> dict:
    """Only valid, in-range settings from `raw` (silently drops junk)."""
    out = {}
    for key, default in DEFAULTS.items():
        if key not in raw:
            continue
        val = raw[key]
        if key in LIMITS:
            lo, hi = LIMITS[key]
            try:
                num = float(val)
            except (TypeError, ValueError):
                continue
            num = min(max(num, lo), hi)
            out[key] = num if isinstance(default, float) else int(num)
        elif isinstance(default, bool):
            out[key] = bool(val)
        elif key == "malicious_ports" and isinstance(val, dict):
            out[key] = {str(p): str(w)[:120] for p, w in
                        ((q, w) for q, w in val.items() if _ports([q])) }
        elif key == "blacklist" and isinstance(val, dict):
            out[key] = {str(ip).strip(): str(w)[:120] for ip, w in val.items() if _valid_ip(str(ip))}
        elif key == "beacon_ignore_ports" and isinstance(val, list):
            out[key] = sorted(set(_ports(val)))
        elif key == "capture_iface" and isinstance(val, str):
            out[key] = val[:200]
    return out


class Settings:
    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.RLock()
        self._data = json.loads(json.dumps(DEFAULTS))
        if self._path.exists():
            try:
                self._data.update(clean(json.loads(self._path.read_text("utf-8"))))
            except (OSError, ValueError):
                pass

    def get(self, key):
        with self._lock:
            return self._data[key]

    def all(self):
        with self._lock:
            return json.loads(json.dumps(self._data))

    def update(self, partial):
        with self._lock:
            self._data.update(clean(partial))
            self._save()
            return self.all()

    def reset(self):
        with self._lock:
            self._data = json.loads(json.dumps(DEFAULTS))
            self._save()
            return self.all()

    def _save(self):
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), "utf-8")
        tmp.replace(self._path)
